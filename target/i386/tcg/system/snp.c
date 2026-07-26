/*
 * Emulated AMD SEV-SNP guest environment for TCG.
 *
 * Implements #VC reflection and the SNP guest instructions.  See snp.h for the
 * security caveats: this provides no confidentiality and no attestation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/log.h"
#include "qemu/thread.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "migration/vmstate.h"
#include "svm.h"
#include "tcg/helper-tcg.h"
#include "snp.h"

#ifdef TARGET_X86_64

/*
 * VM-scoped state.  Only the arming flag for now; the RMP-lite page-state map
 * will live here too.
 */
typedef struct SnpTcgState {
    QemuMutex lock;
    /*
     * #VC reflection is armed by the guest's first PVALIDATE.  That is the
     * true analogue of the TDX "first TDCALL" rule and better motivated:
     * PVALIDATE is an SNP-only instruction, #UD everywhere else, needs no GHCB
     * or handler to execute, and is what a real SNP guest does first anyway.
     * A -kernel boot runs SNP-unaware firmware as a loader shim, which would
     * otherwise take #VC on its own port I/O long before the payload runs.
     */
    bool vc_armed;
} SnpTcgState;

static SnpTcgState *snp_state;

static const VMStateDescription vmstate_snp_tcg = {
    .name = "sev-snp-tcg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(vc_armed, SnpTcgState),
        VMSTATE_END_OF_LIST()
    }
};

static SnpTcgState *snp_get_state(void)
{
    if (!snp_state) {
        snp_state = g_new0(SnpTcgState, 1);
        qemu_mutex_init(&snp_state->lock);
        vmstate_register(NULL, 0, &vmstate_snp_tcg, snp_state);
    }
    return snp_state;
}

/* Is this #VC class enabled, and has the SNP-aware payload taken over yet? */
static bool snp_vc_enabled(CPUX86State *env, uint32_t class)
{
    return (env_archcpu(env)->sev_snp_vc_mask & class) &&
           snp_get_state()->vc_armed;
}

/*
 * Raise #VC with the GHCB SW_EXITCODE as the error code.  Unlike TDX's #VE
 * there is no information latch: #VC delivers everything it has in the pushed
 * error code, and the guest derives the rest by decoding the faulting
 * instruction.
 */
static G_NORETURN void snp_raise_vc(CPUX86State *env, uint64_t exit_code,
                                    uintptr_t ra)
{
    /*
     * A #VC taken while the GHCB MSR still holds an unconsumed request would
     * clobber it, and the outer handler would read garbage.  Real hardware
     * does not escalate this -- Linux uses an IST stack and a per-CPU GHCB
     * backup -- but silently corrupting the request is the worst possible
     * outcome for a development tool, so make it loud instead.
     */
    if (env->snp_ghcb_msr & SNP_GHCB_MSR_INFO_MASK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: #VC (exit code 0x%" PRIx64 ") while the GHCB "
                      "MSR holds an in-flight request; injecting #DF\n",
                      exit_code);
        raise_exception_err_ra(env, EXCP08_DBLE, 0, ra);
    }

    assert(exit_code <= INT32_MAX);
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-snp: injecting #VC (exit code 0x%" PRIx64 ") at RIP 0x"
                  TARGET_FMT_lx "\n", exit_code, env->eip);
    raise_exception_err_ra(env, EXCP1D_VC, (int)exit_code, ra);
}

/*
 * Port I/O.  The GHCB's SW_EXITINFO1 for SVM_EXIT_IOIO is the SVM IOIO
 * intercept encoding, which the translator already assembles for the nested-SVM
 * path -- so it is passed through unchanged rather than rebuilt.
 */
void helper_snp_vc_io(CPUX86State *env, uint32_t port, uint32_t svm_flags)
{
    if (!snp_vc_enabled(env, SNP_VC_IO)) {
        return;
    }
    snp_raise_vc(env, SVM_EXIT_IOIO, GETPC());
}

/*
 * MSRs used for ordinary long-mode and TLS setup are handled natively by a real
 * SNP guest's hypervisor; reflecting them would break a guest before it could
 * install a handler.  The two SEV MSRs must never reflect, or the GHCB MSR
 * protocol would recurse forever.
 */
static bool snp_msr_is_native(uint32_t idx)
{
    switch (idx) {
    case MSR_EFER:
    case MSR_FSBASE:
    case MSR_GSBASE:
    case MSR_KERNELGSBASE:
    case MSR_TSC_AUX:
    case MSR_STAR:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_FMASK:
    case MSR_IA32_SYSENTER_CS:
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
    case MSR_AMD64_SEV:
    case MSR_AMD64_SEV_ES_GHCB:
        return true;
    default:
        return false;
    }
}

void helper_snp_vc_msr(CPUX86State *env, uint32_t is_write)
{
    uint32_t idx = (uint32_t)env->regs[R_ECX];

    if (!snp_vc_enabled(env, SNP_VC_MSR) || snp_msr_is_native(idx)) {
        return;
    }
    snp_raise_vc(env, SVM_EXIT_MSR, GETPC());
}

/*
 * CPUID leaf 0 and the SEV feature leaf always answer natively: a guest that
 * could not execute them would have no way to discover it is an SNP guest, nor
 * to find the C-bit it needs before it can map a GHCB.  Leaf 0x80000000 is
 * included because a guest must read the maximum extended leaf before it can
 * ask for 0x8000001F.
 */
void helper_snp_vc_cpuid(CPUX86State *env)
{
    uint32_t leaf = (uint32_t)env->regs[R_EAX];

    if (!snp_vc_enabled(env, SNP_VC_CPUID) ||
        leaf == 0 || leaf == 0x80000000 || leaf == 0x8000001F) {
        return;
    }
    snp_raise_vc(env, SVM_EXIT_CPUID, GETPC());
}

void helper_snp_vc_hlt(CPUX86State *env)
{
    if (!snp_vc_enabled(env, SNP_VC_HLT)) {
        return;
    }
    snp_raise_vc(env, SVM_EXIT_HLT, GETPC());
}

/*
 * PVALIDATE (F2 0F 01 FF): RAX linear address, ECX page size, EDX validate
 * flag.  EAX returns a status and CF is set when the RMP entry was already in
 * the requested state.
 *
 * With no RMP-lite page-state map yet this validates its operands and reports
 * success, but it does arm #VC reflection -- which is the point of landing it
 * this early, since without it nothing could ever be reflected.
 */
void helper_pvalidate(CPUX86State *env)
{
    SnpTcgState *st = snp_get_state();
    uint64_t gva = env->regs[R_EAX];
    uint32_t page_size = (uint32_t)env->regs[R_ECX];
    uint64_t align;

    if (!st->vc_armed) {
        qemu_mutex_lock(&st->lock);
        st->vc_armed = true;
        qemu_mutex_unlock(&st->lock);
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: first PVALIDATE; #VC reflection is now live\n");
    }

    if (page_size > 1) {
        env->regs[R_EAX] = PVALIDATE_FAIL_INPUT;
        env->eflags &= ~CC_C;
        return;
    }

    align = page_size ? (2 * MiB) : (4 * KiB);
    if (gva & (align - 1)) {
        env->regs[R_EAX] = PVALIDATE_FAIL_INPUT;
        env->eflags &= ~CC_C;
        return;
    }

    /*
     * No page-state tracking yet, so nothing can already be in the requested
     * state: report a successful change with CF clear.
     */
    env->regs[R_EAX] = PVALIDATE_SUCCESS;
    env->eflags &= ~CC_C;
}

#endif /* TARGET_X86_64 */
