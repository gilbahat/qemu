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
#include "qemu/error-report.h"
#include "system/runstate.h"
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
 * Only a *request* counts as in flight.  After VMGEXIT services one the
 * register holds a response, which is nonzero in its info field but is the
 * guest's to read at leisure.
 */
static bool snp_msr_is_request(uint64_t val)
{
    switch (SNP_GHCB_MSR_INFO(val)) {
    case GHCB_MSR_SEV_INFO_REQ:
    case GHCB_MSR_CPUID_REQ:
    case GHCB_MSR_PREF_GPA_REQ:
    case GHCB_MSR_REG_GPA_REQ:
    case GHCB_MSR_PSC_REQ:
    case GHCB_MSR_HV_FT_REQ:
    case GHCB_MSR_TERM_REQ:
        return true;
    default:
        return false;
    }
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
    if (snp_msr_is_request(env->snp_ghcb_msr)) {
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

/*
 * The GHCB MSR protocol.  This is the only channel a guest has before it owns
 * a GHCB page: it writes a request into MSR_AMD64_SEV_ES_GHCB, executes
 * VMGEXIT, and reads the response back out of the same register.
 */
static void snp_ghcb_msr_protocol(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    uint64_t val = env->snp_ghcb_msr;
    uint64_t data = SNP_GHCB_MSR_DATA(val);

    switch (SNP_GHCB_MSR_INFO(val)) {
    case GHCB_MSR_SEV_INFO_REQ:
        /*
         * Carries the C-bit position in bits [31:24], which is how a guest
         * learns it before it can run CPUID -- a second, independent consumer
         * of x-sev-snp-cbitpos.
         */
        env->snp_ghcb_msr = GHCB_MSR_SEV_INFO_RESP
                          | ((uint64_t)GHCB_PROTOCOL_MAX << 48)
                          | ((uint64_t)GHCB_PROTOCOL_MIN << 32)
                          | ((uint64_t)cpu->sev_snp_cbitpos << 24);
        break;

    case GHCB_MSR_CPUID_REQ: {
        uint32_t fn = val >> 32;
        uint32_t reg = (val >> 30) & 3;
        uint32_t regs[4];

        cpu_x86_cpuid(env, fn, 0, &regs[0], &regs[1], &regs[2], &regs[3]);
        env->snp_ghcb_msr = GHCB_MSR_CPUID_RESP
                          | ((uint64_t)regs[reg] << 32)
                          | ((uint64_t)reg << 30);
        break;
    }

    case GHCB_MSR_PREF_GPA_REQ:
        /* No preference: the guest may register whatever page it likes. */
        env->snp_ghcb_msr = GHCB_MSR_PREF_GPA_RESP |
                            (GHCB_MSR_PREF_GPA_NONE << 12);
        break;

    case GHCB_MSR_REG_GPA_REQ: {
        uint64_t gpa = data;

        /*
         * A real hypervisor cannot read a private GHCB, so registering one is
         * refused.  Page-state tracking does not exist yet, so for now only
         * the address itself is checked; the shared-state check joins this
         * when the RMP-lite map lands.
         */
        if (gpa == 0 || (gpa & ~SNP_GHCB_MSR_INFO_MASK) != gpa) {
            env->snp_ghcb_msr = GHCB_MSR_REG_GPA_RESP |
                                (GHCB_MSR_PREF_GPA_NONE << 12);
            break;
        }
        env->snp_ghcb_gpa = gpa;
        env->snp_ghcb_msr = GHCB_MSR_REG_GPA_RESP | gpa;
        break;
    }

    case GHCB_MSR_PSC_REQ: {
        uint64_t op = val >> 56;

        /*
         * No page-state map yet, so every transition succeeds.  Reject an
         * operation the architecture does not define, though -- a guest that
         * sends one has a bug worth surfacing.
         */
        if (op < GHCB_MSR_PSC_OP_PRIVATE || op > GHCB_MSR_PSC_OP_UNSMASH) {
            env->snp_ghcb_msr = GHCB_MSR_PSC_RESP | (1ULL << 32);
            break;
        }
        env->snp_ghcb_msr = GHCB_MSR_PSC_RESP;
        break;
    }

    case GHCB_MSR_HV_FT_REQ:
        env->snp_ghcb_msr = GHCB_MSR_HV_FT_RESP | (GHCB_HV_FT_SNP << 12);
        break;

    case GHCB_MSR_TERM_REQ: {
        unsigned reason_set = (val >> 12) & 0xf;
        unsigned reason_code = (val >> 16) & 0xff;

        /*
         * The guest has given up.  Stopping with the reason reported is far
         * more useful during bring-up than letting it reset into a loop.
         */
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: guest requested termination, reason set %u "
                      "code %u\n", reason_set, reason_code);
        warn_report("sev-snp: guest requested termination (reason set %u, "
                    "code %u)", reason_set, reason_code);
        qemu_system_guest_panicked(NULL);
        break;
    }

    default:
        qemu_log_mask(LOG_UNIMP,
                      "sev-snp: unimplemented GHCB MSR info code 0x%03x\n",
                      (unsigned)SNP_GHCB_MSR_INFO(val));
        /* Terminate is the only defined way to say "I cannot do that". */
        env->snp_ghcb_msr = GHCB_MSR_TERM_REQ;
        break;
    }
}

/*
 * VMGEXIT (F3 0F 01 D9).  With a request in the GHCB MSR this runs the MSR
 * protocol; otherwise it would dispatch an NAE event through the registered
 * GHCB page, which is not modelled yet.
 */
void helper_vmgexit(CPUX86State *env)
{
    if (snp_msr_is_request(env->snp_ghcb_msr)) {
        snp_ghcb_msr_protocol(env);
        return;
    }

    if (!env->snp_ghcb_gpa) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: VMGEXIT with neither a GHCB MSR request nor a "
                      "registered GHCB page\n");
        return;
    }

    qemu_log_mask(LOG_UNIMP,
                  "sev-snp: GHCB page protocol is not implemented; VMGEXIT "
                  "against the registered GHCB at 0x%" PRIx64 " ignored\n",
                  env->snp_ghcb_gpa);
}

#endif /* TARGET_X86_64 */
