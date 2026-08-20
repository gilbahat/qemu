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
#include "qemu/lockable.h"
#include "qemu/thread.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "migration/vmstate.h"
#include "qemu/error-report.h"
#include "system/runstate.h"
#include "system/memory.h"
#include "hw/core/loader.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "svm.h"
#include "tcg/helper-tcg.h"
#include "crypto/hash.h"
#include "hw/core/boards.h"
#include "system/system.h"
#include "system/reset.h"
#include "snp.h"
#include "snp-gcm.h"
#include "hw/i386/snp-dma.h"
#include "hw/i386/x86-launch-image.h"

#ifdef TARGET_X86_64

/* VM-scoped state: the arming flag and the RMP-lite page-state map. */
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

    /*
     * RMP-lite.  Only pages whose state differs from the mode default are
     * stored, so there is nothing to size against RAM, nothing to grow on
     * hotplug, and the launch image can be identified lazily.  Keys are page
     * frame numbers.
     */
    GHashTable *rmp;

    /*
     * The launch measurement -- the SNP analogue of MRTD, and what an
     * ATTESTATION_REPORT's MEASUREMENT field carries.  Computed once,
     * before the guest runs.
     */
    uint8_t measurement[SNP_MEASUREMENT_LEN];
    bool measurement_valid;

    /* Flattened form of rmp, live only across a migration. */
    uint32_t rmp_count;
    uint64_t *rmp_pfn;
    uint8_t *rmp_st;
} SnpTcgState;

static SnpTcgState *snp_state;

/*
 * Page state has to migrate.  A guest that has validated its memory and is then
 * migrated would, without this, find every page back at the mode default: under
 * strict that is unvalidated, so it would take a #VC on its own next
 * instruction.  The map is flattened into parallel arrays because a GHashTable
 * has no VMSTATE representation.
 */
static int snp_pre_save(void *opaque)
{
    SnpTcgState *s = opaque;
    GHashTableIter it;
    gpointer k, v;
    uint32_t i = 0;

    s->rmp_count = s->rmp ? g_hash_table_size(s->rmp) : 0;
    g_free(s->rmp_pfn);
    g_free(s->rmp_st);
    s->rmp_pfn = g_new0(uint64_t, s->rmp_count);
    s->rmp_st = g_new0(uint8_t, s->rmp_count);

    if (s->rmp) {
        g_hash_table_iter_init(&it, s->rmp);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            s->rmp_pfn[i] = GPOINTER_TO_SIZE(k);
            s->rmp_st[i] = GPOINTER_TO_SIZE(v);
            i++;
        }
    }
    return 0;
}

static int snp_post_load(void *opaque, int version_id)
{
    SnpTcgState *s = opaque;
    uint32_t i;

    if (!s->rmp) {
        s->rmp = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_remove_all(s->rmp);
    for (i = 0; i < s->rmp_count; i++) {
        g_hash_table_insert(s->rmp, GSIZE_TO_POINTER(s->rmp_pfn[i]),
                            GSIZE_TO_POINTER(s->rmp_st[i]));
    }
    return 0;
}

static const VMStateDescription vmstate_snp_tcg = {
    .name = "sev-snp-tcg",
    .version_id = 2,
    .minimum_version_id = 2,
    .pre_save = snp_pre_save,
    .post_load = snp_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(vc_armed, SnpTcgState),
        VMSTATE_UINT8_ARRAY(measurement, SnpTcgState, SNP_MEASUREMENT_LEN),
        VMSTATE_BOOL(measurement_valid, SnpTcgState),
        VMSTATE_UINT32(rmp_count, SnpTcgState),
        VMSTATE_VARRAY_UINT32_ALLOC(rmp_pfn, SnpTcgState, rmp_count, 0,
                                    vmstate_info_uint64, uint64_t),
        VMSTATE_VARRAY_UINT32_ALLOC(rmp_st, SnpTcgState, rmp_count, 0,
                                    vmstate_info_uint8, uint8_t),
        VMSTATE_END_OF_LIST()
    }
};

static SnpTcgState *snp_get_state(void);
static void snp_write_secrets_page(void *opaque);

/*
 * The launch measurement.
 *
 * On hardware the AMD-SP computes this over the SNP_LAUNCH_UPDATE sequence and
 * seals it at SNP_LAUNCH_FINISH.  There is no such sequence here -- a -kernel
 * boot places the payload with the ordinary loader -- so this hashes the launch
 * image as loaded: for every page belonging to a loaded image, the GPA followed
 * by the page contents, in address order.  The GPA makes it position-sensitive,
 * which is the property the hardware sequence has.
 *
 * It is therefore **not** the measurement a real SNP guest would report for the
 * same payload and must not be compared against one.  What it gives a guest
 * is a root measurement stable across boots that changes when the payload
 * changes -- the part of an attestation flow that can actually be tested.
 *
 * Deliberately the same construction as the emulated TDX MRTD, so the two are
 * comparable to anyone reading both.
 *
 * Measured at the transition to running, not at machine-init-done: ROMs are
 * copied into guest memory by the initial reset, which happens *after* every
 * machine-init-done notifier, so at that point the image is not in memory yet.
 * A plain reset handler is no good either -- rom_reset() is registered after
 * those notifiers, so it would run second.  By the time the VM starts running
 * the image is in place and no vCPU has executed, which is launch time.
 *
 * Membership is asked of rom_ptr(), but the bytes are read from guest memory.
 * rom_ptr() bounds its answer by romsize while the buffer behind it is only
 * datasize long -- a segment with a .bss tail has romsize > datasize -- so
 * reading a whole page through it walks off the end of the allocation.
 */
static void snp_measure_launch_image(void *opaque, bool running, RunState state)
{
    SnpTcgState *s = opaque;
    ram_addr_t ram_size = current_machine->ram_size;
    g_autoptr(GByteArray) buf = g_byte_array_new();
    g_autofree uint8_t *page = g_malloc0(TARGET_PAGE_SIZE);
    hwaddr gpa;
    unsigned pages = 0;

    if (!running || s->measurement_valid) {
        return;
    }

    for (gpa = 0; gpa < ram_size; gpa += TARGET_PAGE_SIZE) {
        uint64_t le_gpa;

        const void *src;
        size_t valid;

        if (x86_launch_image_page(gpa, &src, &valid)) {
            memset(page, 0, TARGET_PAGE_SIZE);
            if (src && valid) {
                memcpy(page, src, valid);
            }
        } else if (rom_ptr(gpa, 1)) {
            if (address_space_read(&address_space_memory, gpa,
                                   MEMTXATTRS_UNSPECIFIED, page,
                                   TARGET_PAGE_SIZE) != MEMTX_OK) {
                continue;
            }
        } else {
            continue;
        }
        le_gpa = cpu_to_le64(gpa);
        g_byte_array_append(buf, (const uint8_t *)&le_gpa, sizeof(le_gpa));
        g_byte_array_append(buf, page, TARGET_PAGE_SIZE);
        pages++;
    }

    QEMU_LOCK_GUARD(&s->lock);
    if (!pages) {
        warn_report("sev-snp: no launch image found to measure; the launch "
                    "measurement stays zero");
        return;
    }
    {
        struct iovec iov = { .iov_base = buf->data, .iov_len = buf->len };
        uint8_t *out = s->measurement;
        size_t outlen = sizeof(s->measurement);

        if (qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA384, &iov, 1, &out,
                                &outlen, NULL) < 0) {
            warn_report("sev-snp: failed to compute the launch measurement");
            return;
        }
    }
    s->measurement_valid = true;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-snp: launch measurement computed over %u pages\n",
                  pages);
}

static SnpTcgState *snp_get_state(void)
{
    if (!snp_state) {
        snp_state = g_new0(SnpTcgState, 1);
        qemu_mutex_init(&snp_state->lock);
        vmstate_register(NULL, 0, &vmstate_snp_tcg, snp_state);
        qemu_add_vm_change_state_handler(snp_measure_launch_image,
                                        snp_state);
        /*
         * The secrets page is placed from a reset handler rather than at
         * machine-init-done: a guest expects it present at every boot, and a
         * reset must put it back, which is what firmware does on hardware.
         */
        qemu_register_reset(snp_write_secrets_page, snp_state);
    }
    return snp_state;
}

void snp_tcg_init(void)
{
    snp_get_state();
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
 * Every CPUID is intercepted, with no exemptions.
 *
 * Leaf 0, leaf 0x80000000 and the SEV feature leaf 0x8000001F used to answer
 * natively, on the reasoning that a guest which could not execute them would
 * have no way to discover it is an SNP guest nor to find the C-bit it needs
 * before it can map a GHCB.  That reasoning is sound and the conclusion was
 * still wrong: hardware grants no such exemption, and the GHCB MSR protocol
 * already answers both questions -- SEV Information carries the C-bit position
 * and MSR CPUID answers a leaf -- from the guest's first instruction, needing
 * neither a handler nor a GHCB page.  The exemption did not make early
 * discovery possible; it made a guest that never learned to do it look like it
 * worked.
 */
void helper_snp_vc_cpuid(CPUX86State *env)
{
    if (!snp_vc_enabled(env, SNP_VC_CPUID)) {
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

static bool snp_gpa_is_ram(CPUX86State *env, hwaddr gpa)
{
    CPUState *cs = env_cpu(env);
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    hwaddr xlat, len = 1;
    MemoryRegion *mr;

    mr = address_space_translate(cpu_addressspace(cs, attrs), gpa, &xlat, &len,
                                 false, attrs);
    return memory_region_is_ram(mr) || memory_region_is_romd(mr);
}

/*
 * The state a page has before the guest touches it.
 *
 * Under LAZY everything is shared, so a guest that has not adopted the C-bit
 * runs unchanged and only the pages it explicitly claims are enforced.  Under
 * STRICT guest RAM is private as it is on hardware, and only the launch-
 * measured image is validated -- which is what SNP_LAUNCH_UPDATE produces.
 * rom_ptr() is the oracle for that: every blob the x86 boot path places in
 * guest RAM is registered there, and notably a -kernel ELF's .bss is not, so
 * it starts unvalidated exactly as it would on hardware.
 */
static SnpPageState snp_rmp_default(CPUX86State *env, hwaddr gpa)
{
    X86CPU *cpu = env_archcpu(env);

    if (!snp_gpa_is_ram(env, gpa)) {
        return SNP_PAGE_SHARED;      /* MMIO is never guest-private */
    }
    if (cpu->sev_snp_rmp == SNP_RMP_LAZY) {
        return SNP_PAGE_SHARED;
    }
    /*
     * Two oracles, as on the TDX side: rom_ptr() for images the loader placed
     * as ROMs, and the launch-image registry for the -kernel paths that publish
     * through fw_cfg and let a DMA option ROM copy them in.
     */
    if (rom_ptr(gpa & TARGET_PAGE_MASK, 1) ||
        x86_launch_image_contains(gpa & TARGET_PAGE_MASK)) {
        return SNP_PAGE_PRIVATE_VALIDATED;
    }
    return SNP_PAGE_PRIVATE_UNVALIDATED;
}

/*
 * Keys are GSIZE, not GUINT: with phys_bits at cbitpos + 1 a page frame number
 * needs up to 40 bits, and GUINT_TO_POINTER would truncate it -- aliasing two
 * distant pages onto one entry.
 */
static gpointer snp_rmp_key(hwaddr gpa)
{
    return GSIZE_TO_POINTER(gpa >> TARGET_PAGE_BITS);
}

static SnpPageState snp_rmp_get(CPUX86State *env, hwaddr gpa)
{
    SnpTcgState *s = snp_get_state();
    gpointer v;
    bool found;

    QEMU_LOCK_GUARD(&s->lock);
    found = s->rmp &&
            g_hash_table_lookup_extended(s->rmp, snp_rmp_key(gpa), NULL, &v);
    return found ? GPOINTER_TO_SIZE(v) : snp_rmp_default(env, gpa);
}

static void snp_rmp_set(CPUX86State *env, hwaddr gpa, SnpPageState st)
{
    SnpTcgState *s = snp_get_state();

    QEMU_LOCK_GUARD(&s->lock);
    if (!s->rmp) {
        s->rmp = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_insert(s->rmp, snp_rmp_key(gpa), GSIZE_TO_POINTER(st));
}

bool snp_rmp_enabled(CPUX86State *env)
{
    return env_archcpu(env)->sev_snp_guest &&
           env_archcpu(env)->sev_snp_rmp != SNP_RMP_OFF;
}

bool snp_rmp_gpa_is_shared(CPUX86State *env, hwaddr gpa)
{
    return snp_rmp_get(env, gpa) == SNP_PAGE_SHARED;
}

SnpRmpResult snp_rmp_check(CPUX86State *env, hwaddr gpa, bool priv)
{
    SnpPageState st = snp_rmp_get(env, gpa);

    if (priv) {
        if (st == SNP_PAGE_PRIVATE_VALIDATED) {
            return SNP_RMP_OK;
        }
        /* Assigned but unvalidated is the guest's to fix, with PVALIDATE. */
        return st == SNP_PAGE_PRIVATE_UNVALIDATED ? SNP_RMP_NOT_VALIDATED
                                                  : SNP_RMP_MISMATCH;
    }
    return st == SNP_PAGE_SHARED ? SNP_RMP_OK : SNP_RMP_MISMATCH;
}

void snp_rmp_fault(CPUX86State *env, SnpRmpResult res, hwaddr gpa, bool priv,
                   uintptr_t ra)
{
    if (res == SNP_RMP_NOT_VALIDATED) {
        snp_raise_vc(env, SNP_EXIT_PAGE_NOT_VALIDATED, ra);
    }

    /*
     * A C-bit that disagrees with the page's state is not visible to the guest
     * on hardware: the RMP check fails during the nested walk and the
     * hypervisor sees an unresolvable fault.  Say so precisely and stop, rather
     * than inventing a #PF that would send someone hunting for a page-table bug
     * when the bug is in their page *state*.
     */
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-snp: RMP violation: %s access to GPA 0x%" HWADDR_PRIx
                  " whose state is %s\n",
                  priv ? "private (C=1)" : "shared (C=0)", gpa,
                  snp_rmp_get(env, gpa) == SNP_PAGE_SHARED ? "shared"
                      : "guest-private");
    warn_report("sev-snp: RMP violation at GPA 0x%" HWADDR_PRIx
                ": %s access to %s memory. A real hypervisor would terminate "
                "the guest here.", gpa, priv ? "private (C=1)" : "shared (C=0)",
                snp_rmp_get(env, gpa) == SNP_PAGE_SHARED ? "shared"
                    : "guest-private");
    qemu_system_guest_panicked(NULL);
}

/*
 * Page-state change, from the GHCB MSR protocol.  Moving a page to private
 * clears its validated bit: the guest must PVALIDATE it before use, which is
 * the ordering this teaches.
 */
static bool snp_rmp_psc(CPUX86State *env, hwaddr gpa, uint64_t op)
{
    CPUState *cs = env_cpu(env);

    if (!snp_rmp_enabled(env)) {
        return true;
    }

    switch (op) {
    case GHCB_MSR_PSC_OP_PRIVATE:
        snp_rmp_set(env, gpa, SNP_PAGE_PRIVATE_UNVALIDATED);
        break;
    case GHCB_MSR_PSC_OP_SHARED:
        snp_rmp_set(env, gpa, SNP_PAGE_SHARED);
        break;
    default:
        /* PSMASH/UNSMASH are page-size operations; only 4KiB is modelled. */
        return true;
    }

    /*
     * Both directions remove an access that may already be cached, so the TLB
     * has to be dropped.  Validation is the one transition that only *adds*
     * access, and an unvalidated page cannot have a cached entry -- the fill
     * that would have created it faulted.
     */
    tlb_flush(cs);
    return true;
}

/*
 * PVALIDATE (F2 0F 01 FF): RAX linear address, ECX page size, EDX validate
 * flag.  EAX returns a status and CF is set when the RMP entry was already in
 * the requested state.
 *
 * It also arms #VC reflection, on the first execution: see SnpTcgState.
 */
void helper_pvalidate(CPUX86State *env)
{
    SnpTcgState *st = snp_get_state();
    CPUState *cs = env_cpu(env);
    uint64_t gva = env->regs[R_EAX];
    uint32_t page_size = (uint32_t)env->regs[R_ECX];
    bool validate = env->regs[R_EDX] & 1;
    uint64_t align = page_size ? (2 * MiB) : (4 * KiB);
    TranslateForDebugResult dbg;
    bool mapped_private = false;
    hwaddr gpa;
    SnpPageState cur;

    if (!st->vc_armed) {
        qemu_mutex_lock(&st->lock);
        st->vc_armed = true;
        qemu_mutex_unlock(&st->lock);
        snp_dma_arm();
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: first PVALIDATE; #VC reflection and the DMA "
                      "filter are now live\n");
    }

    env->eflags &= ~CC_C;

    if (page_size > 1 || (gva & (align - 1))) {
        env->regs[R_EAX] = PVALIDATE_FAIL_INPUT;
        return;
    }
    if (page_size) {
        /* RMP page size is not modelled, so only the 4KiB form is accepted. */
        env->regs[R_EAX] = PVALIDATE_FAIL_SIZEMISMATCH;
        return;
    }

    /*
     * PVALIDATE takes a linear address.  Translating it through the walker
     * would re-enter the RMP check on the very page being validated, so use
     * the debug walk, which does not consult page state.
     */
    if (!x86_cpu_translate_for_debug_c(cs, gva & TARGET_PAGE_MASK, &dbg,
                                       &mapped_private)) {
        /*
         * Unmapped.  Each mode keeps the answer it has always given: a guest
         * may deliberately leave a page unmapped as a NULL guard and walk over
         * it, and changing that at the same time as the check below would be
         * changing two things at once.
         */
        env->regs[R_EAX] = snp_rmp_enabled(env) ? PVALIDATE_FAIL_INPUT
                                                : PVALIDATE_SUCCESS;
        return;
    }

    /*
     * The page must be mapped *private*.  PVALIDATE on a mapping without the
     * C-bit does not return a status -- it raises #PF with the reserved bit
     * set -- so a guest cannot discover this by checking the result, and one
     * that shares a page and later walks over it again dies here rather than
     * being told.  This is checked whether or not the RMP is modelled: it is
     * a property of the instruction, not of page state, and it is how the
     * guest's own GHCB page went unnoticed until hardware refused it.
     */
    if (!mapped_private) {
        env->cr[2] = gva;
        raise_exception_err_ra(env, EXCP0E_PAGE,
                               PG_ERROR_P_MASK | PG_ERROR_RSVD_MASK, GETPC());
    }

    if (!snp_rmp_enabled(env)) {
        env->regs[R_EAX] = PVALIDATE_SUCCESS;
        return;
    }

    gpa = dbg.physaddr & ~snp_cbit_mask(env);

    cur = snp_rmp_get(env, gpa);
    if (cur == SNP_PAGE_SHARED) {
        /* The guest must move the page to private first, via a PSC. */
        env->regs[R_EAX] = PVALIDATE_FAIL_PERMISSION;
        return;
    }

    if ((cur == SNP_PAGE_PRIVATE_VALIDATED) == validate) {
        /* Already in the requested state: CF set, no change, no flush. */
        env->eflags |= CC_C;
        env->regs[R_EAX] = PVALIDATE_SUCCESS;
        return;
    }

    snp_rmp_set(env, gpa, validate ? SNP_PAGE_PRIVATE_VALIDATED
                                   : SNP_PAGE_PRIVATE_UNVALIDATED);
    if (!validate) {
        /* Rescinding removes access, so a cached translation must go. */
        tlb_flush(cs);
    }
    env->regs[R_EAX] = PVALIDATE_SUCCESS;
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
        /*
         * GHCBData[55:52] is the page operation and GHCBData[51:12] the GFN,
         * per the GHCB specification's Page State Change MSR protocol -- which
         * is also what Linux's GHCB_MSR_PSC_REQ_GFN() encodes.  This decoded
         * 63:56 until it was checked against the specification; a guest that
         * matched was matching a bug, not an interface.
         */
        uint64_t op = (val >> 52) & 0xf;
        hwaddr gpa = val & MAKE_64BIT_MASK(12, 40);

        /*
         * Reject an operation the architecture does not define -- a guest that
         * sends one has a bug worth surfacing.
         */
        if (op < GHCB_MSR_PSC_OP_PRIVATE || op > GHCB_MSR_PSC_OP_UNSMASH) {
            env->snp_ghcb_msr = GHCB_MSR_PSC_RESP | (1ULL << 32);
            break;
        }
        snp_rmp_psc(env, gpa, op);
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
 * GHCB page access.  Narrow, typed accessors on top of address_space_read/write
 * rather than a mapped struct: the GHCB is inherently read-modify-write (the
 * guest writes a request, we write the reply), which address_space_map() is
 * documented not to sanction.
 */
typedef struct GhcbCtx {
    CPUX86State *env;
    AddressSpace *as;
    MemTxAttrs attrs;
    hwaddr base;
    uint64_t valid_in;      /* bitmap as the guest left it   */
    uint64_t valid_out;     /* bits we set, written back once */
    uint64_t valid_in_hi;
    uint64_t valid_out_hi;
    bool failed;
} GhcbCtx;

static bool ghcb_read(GhcbCtx *c, uint32_t off, void *buf, size_t len)
{
    if (address_space_read(c->as, c->base + off, c->attrs, buf, len)
        != MEMTX_OK) {
        c->failed = true;
        return false;
    }
    return true;
}

static bool ghcb_write(GhcbCtx *c, uint32_t off, const void *buf, size_t len)
{
    if (address_space_write(c->as, c->base + off, c->attrs, buf, len)
        != MEMTX_OK) {
        c->failed = true;
        return false;
    }
    return true;
}

static uint64_t ghcb_get(GhcbCtx *c, uint32_t off)
{
    uint64_t v = 0;

    ghcb_read(c, off, &v, sizeof(v));
    return v;
}

/* Every field written must have its valid bit set, or the guest ignores it. */
static void ghcb_set(GhcbCtx *c, uint32_t off, uint64_t val)
{
    unsigned bit = GHCB_BIT(off);

    ghcb_write(c, off, &val, sizeof(val));
    if (bit < 64) {
        c->valid_out |= 1ULL << bit;
    } else {
        c->valid_out_hi |= 1ULL << (bit - 64);
    }
}

static bool ghcb_is_valid(GhcbCtx *c, uint32_t off)
{
    unsigned bit = GHCB_BIT(off);

    return bit < 64 ? (c->valid_in & (1ULL << bit))
                    : (c->valid_in_hi & (1ULL << (bit - 64)));
}

static bool ghcb_begin(GhcbCtx *c, CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t usage = 0;

    c->env = env;
    c->attrs = cpu_get_mem_attrs(env);
    c->as = cpu_addressspace(cs, c->attrs);
    c->base = env->snp_ghcb_gpa;
    c->valid_out = c->valid_out_hi = 0;
    c->failed = false;

    c->valid_in = ghcb_get(c, GHCB_OFF_VALID_BITMAP);
    c->valid_in_hi = ghcb_get(c, GHCB_OFF_VALID_BITMAP + 8);
    if (c->failed) {
        return false;
    }

    if (!ghcb_read(c, GHCB_OFF_USAGE, &usage, sizeof(usage))) {
        return false;
    }
    if (usage != GHCB_USAGE_STANDARD) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: GHCB usage %u is not the standard protocol\n",
                      usage);
        return false;
    }
    return true;
}

static void ghcb_end(GhcbCtx *c, uint64_t exitinfo2)
{
    uint64_t lo = c->valid_in | c->valid_out;
    uint64_t hi = c->valid_in_hi | c->valid_out_hi;

    ghcb_write(c, GHCB_OFF_VALID_BITMAP, &lo, sizeof(lo));
    ghcb_write(c, GHCB_OFF_VALID_BITMAP + 8, &hi, sizeof(hi));
    /* SW_EXITINFO2 is the completion status, so write it last and unguarded. */
    ghcb_write(c, GHCB_OFF_SW_EXITINFO2, &exitinfo2, sizeof(exitinfo2));
}

/* NAE: port I/O.  SW_EXITINFO1 is the SVM IOIO intercept encoding. */
static uint64_t ghcb_nae_ioio(GhcbCtx *c)
{
    CPUX86State *env = c->env;
    uint64_t info1 = ghcb_get(c, GHCB_OFF_SW_EXITINFO1);
    uint32_t port = info1 >> GHCB_IOIO_PORT_SHIFT;
    bool is_in = info1 & GHCB_IOIO_TYPE_IN;
    unsigned size;

    if (!ghcb_is_valid(c, GHCB_OFF_SW_EXITINFO1)) {
        return GHCB_EXITINFO2_INVALID;
    }
    if (info1 & (GHCB_IOIO_STR | GHCB_IOIO_REP)) {
        /* String I/O uses SW_SCRATCH and the shared buffer; not modelled. */
        qemu_log_mask(LOG_UNIMP, "sev-snp: string I/O over the GHCB\n");
        return GHCB_EXITINFO2_INVALID;
    }

    if (info1 & GHCB_IOIO_SIZE_8) {
        size = 1;
    } else if (info1 & GHCB_IOIO_SIZE_16) {
        size = 2;
    } else if (info1 & GHCB_IOIO_SIZE_32) {
        size = 4;
    } else {
        return GHCB_EXITINFO2_INVALID;
    }

    if (is_in) {
        uint64_t val = size == 1 ? helper_inb(env, port)
                     : size == 2 ? helper_inw(env, port)
                                 : helper_inl(env, port);
        ghcb_set(c, GHCB_OFF_RAX, val);
    } else {
        uint32_t val;

        if (!ghcb_is_valid(c, GHCB_OFF_RAX)) {
            return GHCB_EXITINFO2_INVALID;
        }
        val = ghcb_get(c, GHCB_OFF_RAX);
        if (size == 1) {
            helper_outb(env, port, val);
        } else if (size == 2) {
            helper_outw(env, port, val);
        } else {
            helper_outl(env, port, val);
        }
    }
    return GHCB_EXITINFO2_OK;
}

static uint64_t ghcb_nae_cpuid(GhcbCtx *c)
{
    uint32_t a, b, d, cx;

    if (!ghcb_is_valid(c, GHCB_OFF_RAX)) {
        return GHCB_EXITINFO2_INVALID;
    }
    cpu_x86_cpuid(c->env, (uint32_t)ghcb_get(c, GHCB_OFF_RAX),
                  (uint32_t)ghcb_get(c, GHCB_OFF_RCX), &a, &b, &cx, &d);
    ghcb_set(c, GHCB_OFF_RAX, a);
    ghcb_set(c, GHCB_OFF_RBX, b);
    ghcb_set(c, GHCB_OFF_RCX, cx);
    ghcb_set(c, GHCB_OFF_RDX, d);
    return GHCB_EXITINFO2_OK;
}

/*
 * The underlying helpers work on the architectural registers, so save and
 * restore the guest's RAX/RCX/RDX around the call: an NAE event passes its
 * arguments in the GHCB and must not disturb registers the guest did not offer.
 */
static uint64_t ghcb_nae_msr(GhcbCtx *c)
{
    CPUX86State *env = c->env;
    bool is_write = ghcb_get(c, GHCB_OFF_SW_EXITINFO1) & 1;
    target_ulong save_rax = env->regs[R_EAX];
    target_ulong save_rcx = env->regs[R_ECX];
    target_ulong save_rdx = env->regs[R_EDX];
    uint64_t status = GHCB_EXITINFO2_OK;

    if (!ghcb_is_valid(c, GHCB_OFF_RCX)) {
        return GHCB_EXITINFO2_INVALID;
    }

    env->regs[R_ECX] = (uint32_t)ghcb_get(c, GHCB_OFF_RCX);
    if (is_write) {
        env->regs[R_EAX] = (uint32_t)ghcb_get(c, GHCB_OFF_RAX);
        env->regs[R_EDX] = (uint32_t)ghcb_get(c, GHCB_OFF_RDX);
        helper_wrmsr(env);
    } else {
        helper_rdmsr(env);
    }

    if (!is_write) {
        uint64_t lo = (uint32_t)env->regs[R_EAX];
        uint64_t hi = (uint32_t)env->regs[R_EDX];

        env->regs[R_EAX] = save_rax;
        env->regs[R_EDX] = save_rdx;
        env->regs[R_ECX] = save_rcx;
        ghcb_set(c, GHCB_OFF_RAX, lo);
        ghcb_set(c, GHCB_OFF_RDX, hi);
        return status;
    }

    env->regs[R_EAX] = save_rax;
    env->regs[R_ECX] = save_rcx;
    env->regs[R_EDX] = save_rdx;
    return status;
}

/* Dispatch an NAE event through the registered GHCB page. */
/* --- the guest-message protocol and the attestation report --------------- */

/*
 * The secrets page.  On hardware the AMD-SP fills this in and the hypervisor
 * maps it into the guest; firmware then tells the guest where it is, through
 * metadata a -kernel boot does not have.  So its address is a property here and
 * the guest is told out-of-band -- which is what firmware would be doing
 * anyway.
 * The VMPCKs in it are fixed, published constants. That is deliberate and it
 * is the whole point: they are not secret, cannot be, and a guest must never
 * treat a key obtained this way as one. What a guest can do with them is
 * real AEAD path rather than a bypass of it.
 */
typedef struct QEMU_PACKED SnpSecretsPage {
    uint32_t version;
    uint32_t imi_en_and_flags;
    uint32_t fms;
    uint32_t reserved1;
    uint8_t gosvw[16];
    uint8_t vmpck[SNP_VMPCK_COUNT][SNP_VMPCK_LEN];
    uint8_t os_area[96];
    uint8_t reserved2[3840];
} SnpSecretsPage;
QEMU_BUILD_BUG_ON(sizeof(SnpSecretsPage) != 4096);

hwaddr snp_secrets_gpa(CPUX86State *env)
{
    return env_archcpu(env)->sev_snp_secrets_gpa;
}

static void snp_vmpck_fill(uint8_t *out, unsigned index)
{
    unsigned i;

    /*
     * Derived from the index so the four keys differ -- a guest that uses the
     * wrong VMPCK must fail the tag rather than accidentally succeed.
     */
    for (i = 0; i < SNP_VMPCK_LEN; i++) {
        out[i] = (uint8_t)(0xA0 + index * 0x11 + i);
    }
}

static void snp_write_secrets_page(void *opaque)
{
    CPUX86State *env = &X86_CPU(first_cpu)->env;
    hwaddr gpa = snp_secrets_gpa(env);
    SnpSecretsPage page = { 0 };
    unsigned i;

    if (!gpa) {
        return;
    }

    page.version = cpu_to_le32(3);
    for (i = 0; i < SNP_VMPCK_COUNT; i++) {
        snp_vmpck_fill(page.vmpck[i], i);
    }

    if (address_space_write(&address_space_memory, gpa,
                            MEMTXATTRS_UNSPECIFIED, &page,
                            sizeof(page)) != MEMTX_OK) {
        warn_report("sev-snp: could not place the secrets page at GPA 0x%"
                    HWADDR_PRIx, gpa);
        return;
    }
    warn_report_once("sev-snp: secrets page placed with FIXED, PUBLISHED "
                     "VMPCKs. They are not secret, cannot be, and a guest must "
                     "never treat them as key material.");
}


/* struct snp_guest_msg_hdr, as the ABI and the Linux driver define it. */
typedef struct QEMU_PACKED SnpMsgHdr {
    uint8_t authtag[32];
    uint64_t msg_seqno;
    uint8_t rsvd1[8];
    uint8_t algo;
    uint8_t hdr_version;
    uint16_t hdr_sz;
    uint8_t msg_type;
    uint8_t msg_version;
    uint16_t msg_sz;
    uint32_t rsvd2;
    uint8_t msg_vmpck;
    uint8_t rsvd3[35];
} SnpMsgHdr;
QEMU_BUILD_BUG_ON(sizeof(SnpMsgHdr) != SNP_MSG_HDR_LEN);
QEMU_BUILD_BUG_ON(offsetof(SnpMsgHdr, algo) != SNP_MSG_AAD_OFF);

/* MSG_REPORT_REQ. */
typedef struct QEMU_PACKED SnpReportReq {
    uint8_t report_data[SNP_REPORTDATA_LEN];
    uint32_t vmpl;
    uint8_t reserved[28];
} SnpReportReq;
QEMU_BUILD_BUG_ON(sizeof(SnpReportReq) != 96);

/* ATTESTATION_REPORT. */
typedef struct QEMU_PACKED SnpAttestationReport {
    uint32_t version;
    uint32_t guest_svn;
    uint64_t policy;
    uint8_t family_id[16];
    uint8_t image_id[16];
    uint32_t vmpl;
    uint32_t signature_algo;
    uint64_t platform_version;
    uint64_t platform_info;
    uint32_t flags;
    uint32_t reserved0;
    uint8_t report_data[SNP_REPORTDATA_LEN];
    uint8_t measurement[SNP_MEASUREMENT_LEN];
    uint8_t host_data[32];
    uint8_t id_key_digest[SNP_MEASUREMENT_LEN];
    uint8_t author_key_digest[SNP_MEASUREMENT_LEN];
    uint8_t report_id[32];
    uint8_t report_id_ma[32];
    uint64_t reported_tcb;
    uint8_t reserved1[24];
    uint8_t chip_id[64];
    uint64_t committed_tcb;
    uint8_t current_build;
    uint8_t current_minor;
    uint8_t current_major;
    uint8_t reserved2;
    uint8_t committed_build;
    uint8_t committed_minor;
    uint8_t committed_major;
    uint8_t reserved3;
    uint64_t launch_tcb;
    uint8_t reserved4[168];
    uint8_t signature[512];
} SnpAttestationReport;
QEMU_BUILD_BUG_ON(sizeof(SnpAttestationReport) != SNP_REPORT_LEN);

/* MSG_REPORT_RSP: a status, a length, then the report. */
typedef struct QEMU_PACKED SnpReportRsp {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];
    SnpAttestationReport report;
} SnpReportRsp;

/*
 * The IV is the message sequence number, little-endian, zero-padded to 96 bits.
 * Request and response therefore must not share a sequence number, or the same
 * key and nonce would be used twice; the response uses seqno + 1 and the guest
 * advances by two, which is what the Linux driver does.
 */
static void snp_msg_iv(uint8_t *iv, uint64_t seqno)
{
    uint64_t le = cpu_to_le64(seqno);

    memset(iv, 0, SNP_GCM_IV_LEN);
    memcpy(iv, &le, sizeof(le));
}

static void snp_fill_report(CPUX86State *env, SnpAttestationReport *r,
                            const SnpReportReq *req)
{
    SnpTcgState *s = snp_get_state();
    size_t i;

    memset(r, 0, sizeof(*r));
    r->version = cpu_to_le32(2);
    r->vmpl = req->vmpl;
    r->signature_algo = cpu_to_le32(1);        /* ECDSA P-384 with SHA-384 */
    memcpy(r->report_data, req->report_data, SNP_REPORTDATA_LEN);

    QEMU_LOCK_GUARD(&s->lock);
    memcpy(r->measurement, s->measurement, SNP_MEASUREMENT_LEN);

    /*
     * Not a signature.  Filling this with the marker rather than with plausible
     * random bytes is the point: a relying party, or a guest that forgets where
     * its report came from, sees immediately what this is.
     */
    for (i = 0; i < sizeof(r->signature); i += sizeof(SNP_TCG_FAKE_SIG) - 1) {
        size_t n = MIN(sizeof(SNP_TCG_FAKE_SIG) - 1, sizeof(r->signature) - i);

        memcpy(r->signature + i, SNP_TCG_FAKE_SIG, n);
    }

    warn_report_once("sev-snp: produced a NON-GENUINE attestation report. The "
                     "signature field is a fixed marker, not a signature. It "
                     "has no attestation meaning and must never be sent to a "
                     "relying party.");
}

/*
 * SNP_GUEST_REQUEST: SW_EXITINFO1 is the request page GPA, SW_EXITINFO2 the
 * response page GPA.  Both are shared pages; the message inside is sealed with
 * the VMPCK, so the guest has to get the AEAD, the AAD and the sequence number
 * right before it sees anything.
 */
static uint64_t ghcb_nae_guest_request(GhcbCtx *c, CPUX86State *env)
{
    hwaddr req_gpa, rsp_gpa;
    SnpMsgHdr req_hdr, rsp_hdr;
    SnpReportReq req = { 0 };
    SnpReportRsp rsp = { 0 };
    uint8_t vmpck[SNP_VMPCK_LEN];
    uint8_t iv[SNP_GCM_IV_LEN];
    uint8_t ct[sizeof(SnpReportReq)];
    g_autofree uint8_t *rsp_ct = NULL;
    uint16_t msg_sz;

    if (!ghcb_is_valid(c, GHCB_OFF_SW_EXITINFO1) ||
        !ghcb_is_valid(c, GHCB_OFF_SW_EXITINFO2)) {
        return GHCB_EXITINFO2_INVALID;
    }
    req_gpa = ghcb_get(c, GHCB_OFF_SW_EXITINFO1);
    rsp_gpa = ghcb_get(c, GHCB_OFF_SW_EXITINFO2);

    if (address_space_read(&address_space_memory, req_gpa,
                           MEMTXATTRS_UNSPECIFIED, &req_hdr,
                           sizeof(req_hdr)) != MEMTX_OK) {
        return GHCB_EXITINFO2_INVALID;
    }

    if (req_hdr.algo != SNP_AEAD_AES_256_GCM ||
        req_hdr.hdr_version != SNP_MSG_HDR_VERSION ||
        req_hdr.msg_vmpck >= SNP_VMPCK_COUNT) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: guest request with algo %u, hdr_version %u, "
                      "vmpck %u\n", req_hdr.algo, req_hdr.hdr_version,
                      req_hdr.msg_vmpck);
        return GHCB_EXITINFO2_INVALID;
    }
    if (req_hdr.msg_type != SNP_MSG_REPORT_REQ) {
        qemu_log_mask(LOG_UNIMP,
                      "sev-snp: unimplemented guest message type %u\n",
                      req_hdr.msg_type);
        return GHCB_EXITINFO2_INVALID;
    }

    msg_sz = le16_to_cpu(req_hdr.msg_sz);
    if (msg_sz != sizeof(SnpReportReq)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: MSG_REPORT_REQ is %u bytes, expected %zu\n",
                      msg_sz, sizeof(SnpReportReq));
        return GHCB_EXITINFO2_INVALID;
    }

    if (address_space_read(&address_space_memory, req_gpa + SNP_MSG_HDR_LEN,
                           MEMTXATTRS_UNSPECIFIED, ct,
                           sizeof(ct)) != MEMTX_OK) {
        return GHCB_EXITINFO2_INVALID;
    }

    snp_vmpck_fill(vmpck, req_hdr.msg_vmpck);
    snp_msg_iv(iv, le64_to_cpu(req_hdr.msg_seqno));

    if (!snp_gcm_decrypt(vmpck, iv, SNP_GCM_IV_LEN,
                         (const uint8_t *)&req_hdr + SNP_MSG_AAD_OFF,
                         SNP_MSG_AAD_LEN, ct, (uint8_t *)&req,
                         sizeof(req), req_hdr.authtag)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: guest request failed authentication; check the "
                      "VMPCK, the sequence number and that the AAD is the "
                      "header from offset 0x30\n");
        return GHCB_EXITINFO2_INVALID;
    }

    /* Build the response. */
    rsp.status = cpu_to_le32(SNP_GUEST_RSP_OK);
    rsp.report_size = cpu_to_le32(sizeof(SnpAttestationReport));
    snp_fill_report(env, &rsp.report, &req);

    memset(&rsp_hdr, 0, sizeof(rsp_hdr));
    rsp_hdr.algo = SNP_AEAD_AES_256_GCM;
    rsp_hdr.hdr_version = SNP_MSG_HDR_VERSION;
    rsp_hdr.hdr_sz = cpu_to_le16(SNP_MSG_HDR_LEN);
    rsp_hdr.msg_type = SNP_MSG_REPORT_RSP;
    rsp_hdr.msg_version = req_hdr.msg_version;
    rsp_hdr.msg_sz = cpu_to_le16(sizeof(SnpReportRsp));
    rsp_hdr.msg_vmpck = req_hdr.msg_vmpck;
    rsp_hdr.msg_seqno = cpu_to_le64(le64_to_cpu(req_hdr.msg_seqno) + 1);

    rsp_ct = g_malloc0(sizeof(SnpReportRsp));
    snp_msg_iv(iv, le64_to_cpu(rsp_hdr.msg_seqno));
    if (!snp_gcm_encrypt(vmpck, iv, SNP_GCM_IV_LEN,
                         (const uint8_t *)&rsp_hdr + SNP_MSG_AAD_OFF,
                         SNP_MSG_AAD_LEN, (const uint8_t *)&rsp, rsp_ct,
                         sizeof(SnpReportRsp), rsp_hdr.authtag)) {
        return GHCB_EXITINFO2_INVALID;
    }

    if (address_space_write(&address_space_memory, rsp_gpa,
                            MEMTXATTRS_UNSPECIFIED, &rsp_hdr,
                            sizeof(rsp_hdr)) != MEMTX_OK ||
        address_space_write(&address_space_memory, rsp_gpa + SNP_MSG_HDR_LEN,
                            MEMTXATTRS_UNSPECIFIED, rsp_ct,
                            sizeof(SnpReportRsp)) != MEMTX_OK) {
        return GHCB_EXITINFO2_INVALID;
    }

    return GHCB_EXITINFO2_OK;
}

static void snp_ghcb_page_protocol(CPUX86State *env, int next_eip_addend)
{
    GhcbCtx c;
    uint64_t exit_code, status;

    if (!ghcb_begin(&c, env)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: unusable GHCB at 0x%" PRIx64 "\n",
                      env->snp_ghcb_gpa);
        return;
    }

    exit_code = ghcb_get(&c, GHCB_OFF_SW_EXITCODE);
    if (!ghcb_is_valid(&c, GHCB_OFF_SW_EXITCODE)) {
        ghcb_end(&c, GHCB_EXITINFO2_INVALID);
        return;
    }

    switch (exit_code) {
    case SVM_EXIT_IOIO:
        status = ghcb_nae_ioio(&c);
        break;
    case SVM_EXIT_CPUID:
        status = ghcb_nae_cpuid(&c);
        break;
    case SVM_EXIT_MSR:
        status = ghcb_nae_msr(&c);
        break;
    case SVM_EXIT_SNP_GUEST_REQUEST:
        status = ghcb_nae_guest_request(&c, env);
        break;
    case SVM_EXIT_SNP_EXT_GUEST_REQUEST:
        /*
         * Refused outright, like TDVMCALL<GetQuote>.  The extended request
         * returns a certificate chain, and there is no chain here that is not a
         * lie; a guest asking for one should find out now.
         */
        warn_report_once("sev-snp: refusing SNP_EXT_GUEST_REQUEST; there is no "
                         "certificate chain and the emulation will not invent "
                         "one");
        status = GHCB_EXITINFO2_INVALID;
        break;
    case SVM_EXIT_HLT:
        ghcb_end(&c, GHCB_EXITINFO2_OK);
        /* Halt on the guest's behalf, past the VMGEXIT. */
        env->eip += next_eip_addend;
        helper_hlt(env);
        /* not reached */
    default:
        qemu_log_mask(LOG_UNIMP,
                      "sev-snp: unimplemented NAE exit code 0x%" PRIx64 "\n",
                      exit_code);
        status = GHCB_EXITINFO2_INVALID;
        break;
    }

    ghcb_end(&c, c.failed ? GHCB_EXITINFO2_INVALID : status);
}

/*
 * VMGEXIT (F3 0F 01 D9).  A request in the GHCB MSR runs the MSR protocol;
 * otherwise the register holds the address of the GHCB page to use.
 *
 * That last part is the whole of the contract and it is easy to get wrong in
 * an emulator's favour.  The hypervisor learns where the GHCB is from this
 * register at the moment of the exit -- not from the GHCB Registration
 * exchange, which is a separate and optional step saying which page the guest
 * intends to use.  This used to ignore the register and fall back to whatever
 * REG_GPA had recorded, which is a kindness KVM does not extend: it answers a
 * zeroed register with "vmgexit: GHCB gpa is not set" and re-enters the guest,
 * so a guest that never learned to write the address livelocks -- and does so
 * with no console, because the console is what it was trying to reach.
 */
void helper_vmgexit(CPUX86State *env, int next_eip_addend)
{
    uint64_t gpa;

    if (snp_msr_is_request(env->snp_ghcb_msr)) {
        snp_ghcb_msr_protocol(env);
        return;
    }

    gpa = SNP_GHCB_MSR_DATA(env->snp_ghcb_msr);
    if (!gpa) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: VMGEXIT with neither a GHCB MSR request nor a "
                      "GHCB address in the MSR: GHCB gpa is not set\n");
        return;
    }

    /*
     * A registration, if one was made, is binding: the guest asked for that
     * page and may not then exit through another.
     */
    if (env->snp_ghcb_gpa && gpa != env->snp_ghcb_gpa) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-snp: VMGEXIT names GHCB 0x%" PRIx64 " but 0x%"
                      PRIx64 " is the registered one\n",
                      gpa, env->snp_ghcb_gpa);
        return;
    }
    env->snp_ghcb_gpa = gpa;

    snp_ghcb_page_protocol(env, next_eip_addend);
}

#endif /* TARGET_X86_64 */
