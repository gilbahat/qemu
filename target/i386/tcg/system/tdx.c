/*
 * Emulated Intel TDX guest environment for TCG.
 *
 * Implements the guest-visible TDCALL interface.  See tdx.h for the security
 * caveats: this provides no confidentiality and no genuine attestation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "crypto/hash.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "hw/core/boards.h"
#include "hw/core/qdev.h"
#include "system/memory.h"
#include "migration/vmstate.h"
#include "hw/i386/tdx-dma.h"
#include "hw/i386/x86-launch-image.h"
#include "tcg/helper-tcg.h"
#include "hw/core/loader.h"
#include "exec/target_page.h"
#include "qemu/lockable.h"
#include "exec/cputlb.h"
#include "system/system.h"
#include "system/runstate.h"
#include "system/reset.h"
#include "qemu/timer.h"
#include "tdx.h"

#ifdef TARGET_X86_64

/*
 * MRTD and the RTMRs belong to the TD, not to a vCPU, so they live in a
 * singleton rather than in X86CPU.  Created on first use and shared by every
 * vCPU of the guest.
 */
typedef struct TdxTcgState {
    QemuMutex lock;
    uint8_t mrtd[TDX_MEASUREMENT_LEN];
    uint8_t rtmr[TDX_RTMR_COUNT][TDX_MEASUREMENT_LEN];
    /*
     * #VE reflection is armed by the guest's first TDCALL.  A real TD boots
     * TDX-aware firmware from its reset vector, but a direct -kernel boot runs
     * the ordinary (TDX-unaware) firmware as a loader shim, which would fault
     * on its own port I/O long before the TD payload runs.  Treating the first
     * TDCALL as "the TD-aware code has taken over" keeps reflection scoped to
     * the guest under test.  See docs/system/i386/tdx-tcg.rst.
     */
    bool ve_armed;
    bool mrtd_valid;

    /*
     * A GetQuote in flight.  Quoting is asynchronous on hardware -- the VMM
     * hands the report to a service and answers later -- so it is asynchronous
     * here too, and the guest has to poll the status field as it would.
     */
    bool quote_pending;
    uint64_t quote_gpa;
    uint64_t quote_size;
    QEMUTimer *quote_timer;

    /*
     * Secure-EPT-lite.  Only pages whose state differs from the mode default
     * are stored, so there is nothing to size against RAM and nothing to grow
     * on hotplug.  Keys are page frame numbers.
     */
    GHashTable *sept;

    /* Flattened form of sept, live only across a migration. */
    uint32_t sept_count;
    uint64_t *sept_pfn;
    uint8_t *sept_st;
} TdxTcgState;

static TdxTcgState *tdx_state;

/*
 * TD-scoped state has to survive migration.  The RTMRs especially: a
 * measurement register that silently resets across a snapshot would change the
 * attestation report of a running TD, which is the one thing it must never do.
 * ve_armed matters for a different reason -- losing it turns #VE reflection off
 * and the TD stops conforming with no indication that anything happened.
 */
/*
 * Page state has to migrate for the same reason the RTMRs do: a TD that has
 * accepted its memory and is then migrated would otherwise find every page back
 * at the mode default -- pending under strict -- and take a #VE on its own next
 * instruction.  Flattened into parallel arrays because a GHashTable has no
 * VMSTATE representation.
 */
static int tdx_pre_save(void *opaque)
{
    TdxTcgState *s = opaque;
    GHashTableIter it;
    gpointer k, v;
    uint32_t i = 0;

    s->sept_count = s->sept ? g_hash_table_size(s->sept) : 0;
    g_free(s->sept_pfn);
    g_free(s->sept_st);
    s->sept_pfn = g_new0(uint64_t, s->sept_count);
    s->sept_st = g_new0(uint8_t, s->sept_count);

    if (s->sept) {
        g_hash_table_iter_init(&it, s->sept);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            s->sept_pfn[i] = GPOINTER_TO_SIZE(k);
            s->sept_st[i] = GPOINTER_TO_SIZE(v);
            i++;
        }
    }
    return 0;
}

static int tdx_post_load(void *opaque, int version_id)
{
    TdxTcgState *s = opaque;
    uint32_t i;

    /*
     * Re-arm a quote that was in flight when the source was stopped; without
     * this the guest would poll a status that never changes.
     */
    if (s->quote_pending && s->quote_timer) {
        timer_mod(s->quote_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + TDX_QUOTE_DELAY_MS);
    }

    if (!s->sept) {
        s->sept = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_remove_all(s->sept);
    for (i = 0; i < s->sept_count; i++) {
        g_hash_table_insert(s->sept, GSIZE_TO_POINTER(s->sept_pfn[i]),
                            GSIZE_TO_POINTER(s->sept_st[i]));
    }
    return 0;
}

static const VMStateDescription vmstate_tdx_tcg = {
    .name = "tdx-tcg",
    .version_id = 2,
    .minimum_version_id = 2,
    .pre_save = tdx_pre_save,
    .post_load = tdx_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8_ARRAY(mrtd, TdxTcgState, TDX_MEASUREMENT_LEN),
        VMSTATE_UINT8_2DARRAY(rtmr, TdxTcgState, TDX_RTMR_COUNT,
                              TDX_MEASUREMENT_LEN),
        VMSTATE_BOOL(ve_armed, TdxTcgState),
        VMSTATE_BOOL(mrtd_valid, TdxTcgState),
        VMSTATE_BOOL(quote_pending, TdxTcgState),
        VMSTATE_UINT64(quote_gpa, TdxTcgState),
        VMSTATE_UINT64(quote_size, TdxTcgState),
        VMSTATE_UINT32(sept_count, TdxTcgState),
        VMSTATE_VARRAY_UINT32_ALLOC(sept_pfn, TdxTcgState, sept_count, 0,
                                    vmstate_info_uint64, uint64_t),
        VMSTATE_VARRAY_UINT32_ALLOC(sept_st, TdxTcgState, sept_count, 0,
                                    vmstate_info_uint8, uint8_t),
        VMSTATE_END_OF_LIST()
    }
};

/*
 * A TD does not survive a reset -- the TDX module tears it down and the next
 * boot is a different TD.  Page state that outlived the guest that created it
 * would make a reset loop report nonsense, so drop it here.  The measurement
 * registers go too, for the same reason.
 */
static bool tdx_sha384(const struct iovec *iov, size_t niov, uint8_t *out);
static TdxTcgState *tdx_get_state(void);

/*
 * MRTD: the measurement of the launch image.
 *
 * Hardware builds this from the TDH.MEM.PAGE.ADD and TDH.MR.EXTEND sequence the
 * VMM performs, then seals it with TDH.MR.FINALIZE.  There is no such sequence
 * here -- a -kernel boot places the payload with the ordinary loader -- so this
 * hashes the launch image as loaded instead: for every page belonging to a
 * loaded image, the GPA followed by the page contents, in address order.
 * Including the GPA makes it position-sensitive, which is the property
 * hardware's page-add sequence has and the reason it is worth having.
 *
 * It is therefore **not** the MRTD a real TD would report for the same payload,
 * and must not be compared against one.  What it does give a guest is a root
 * measurement that is stable across boots and changes when the payload changes,
 * which is what an attestation flow can actually be tested against.
 */
/*
 * Measured at the transition to running, not at machine-init-done: ROMs are
 * copied into guest memory by the initial reset, which happens *after* every
 * machine-init-done notifier (see qemu_machine_creation_done()), so at that
 * point the image is not in memory yet.  A plain reset handler is no good
 * either -- rom_reset() is registered after those notifiers, so it would run
 * second.  By the time the VM starts running the image is in place and no vCPU
 * has executed, which is exactly launch time.
 *
 * Membership is asked of rom_ptr(), but the bytes are read from guest memory.
 * rom_ptr() bounds its answer by romsize while the buffer behind it is only
 * datasize long -- a segment with a .bss tail has romsize > datasize -- so
 * reading a whole page through it walks off the end of the allocation.  Guest
 * memory holds the data followed by the zero fill, which is what was launched.
 */
static void tdx_measure_launch_image(void *opaque, bool running, RunState state)
{
    TdxTcgState *td = opaque;
    ram_addr_t ram_size = current_machine->ram_size;
    g_autoptr(GByteArray) buf = g_byte_array_new();
    g_autofree uint8_t *page = g_malloc0(TARGET_PAGE_SIZE);
    struct iovec iov;
    hwaddr gpa;
    unsigned pages = 0;

    if (!running || td->mrtd_valid) {
        return;
    }

    for (gpa = 0; gpa < ram_size; gpa += TARGET_PAGE_SIZE) {
        uint64_t le_gpa;

        const void *src;
        size_t valid;

        if (x86_launch_image_page(gpa, &src, &valid)) {
            /*
             * Measure the emulator's own copy: for this load path the bytes are
             * not in guest memory yet, and once they are the guest has already
             * been running.
             */
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

    QEMU_LOCK_GUARD(&td->lock);
    if (!pages) {
        warn_report("tdx: no launch image found to measure; MRTD stays zero");
        return;
    }
    iov.iov_base = buf->data;
    iov.iov_len = buf->len;
    if (!tdx_sha384(&iov, 1, td->mrtd)) {
        warn_report("tdx: failed to compute MRTD; it stays zero");
        return;
    }
    td->mrtd_valid = true;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "tdx: MRTD computed over %u launch pages\n", pages);
}

static void tdx_reset(void *opaque)
{
    TdxTcgState *s = opaque;

    QEMU_LOCK_GUARD(&s->lock);
    if (s->sept) {
        g_hash_table_remove_all(s->sept);
    }
    /*
     * MRTD is kept: it measures the launch image, which a reset does not
     * change, and the machine-init-done notifier that computes it runs only
     * once.  The RTMRs are runtime measurements and do go.
     */
    memset(s->rtmr, 0, sizeof(s->rtmr));
    s->ve_armed = false;
}

static TdxTcgState *tdx_get_state(void)
{
    if (!tdx_state) {
        tdx_state = g_new0(TdxTcgState, 1);
        qemu_mutex_init(&tdx_state->lock);
        vmstate_register(NULL, 0, &vmstate_tdx_tcg, tdx_state);
        qemu_register_reset(tdx_reset, tdx_state);
        qemu_add_vm_change_state_handler(tdx_measure_launch_image,
                                        tdx_state);
    }
    return tdx_state;
}

void tdx_tcg_init(void)
{
    tdx_get_state();
}

static G_NORETURN void tdx_raise_ve(CPUX86State *env, uint32_t reason,
                                    uint64_t qual, uint64_t gla, uint64_t gpa,
                                    uint32_t instr_len, uint32_t instr_info,
                                    uintptr_t ra);

/*
 * Secure-EPT-lite.  Structurally identical to the SNP RMP-lite: only pages
 * differing from the mode default are stored, and the default depends on the
 * mode and on whether the page is part of the launch image.
 */
static bool tdx_gpa_is_ram(CPUX86State *env, hwaddr gpa)
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
 * Under LAZY every page starts accepted, so a TD that has not adopted
 * TDG.MEM.PAGE.ACCEPT runs unchanged and only pages it explicitly converts are
 * enforced.  Under STRICT guest RAM is private and pending as it is on hardware
 * after TDH.MEM.PAGE.ADD, and only the launch image is accepted -- rom_ptr() is
 * the oracle for that, so a -kernel payload's .bss starts pending exactly as it
 * would on hardware.
 */
static TdxPageState tdx_sept_default(CPUX86State *env, hwaddr gpa)
{
    X86CPU *cpu = env_archcpu(env);

    if (!tdx_gpa_is_ram(env, gpa)) {
        return TDX_PAGE_SHARED;      /* MMIO is always shared to a TD */
    }
    if (cpu->tdx_sept == TDX_SEPT_LAZY) {
        return TDX_PAGE_PRIVATE_ACCEPTED;
    }
    /*
     * Two oracles, because there are two ways an image reaches guest memory.
     * rom_ptr() covers what the loader placed as a ROM; the launch-image
     * registry covers the -kernel paths that publish through fw_cfg and let a
     * DMA option ROM copy it in, where there is no ROM to find and the bytes
     * are not in memory until the guest itself has run.
     */
    if (rom_ptr(gpa & TARGET_PAGE_MASK, 1) ||
        x86_launch_image_contains(gpa & TARGET_PAGE_MASK)) {
        return TDX_PAGE_PRIVATE_ACCEPTED;
    }
    return TDX_PAGE_PRIVATE_PENDING;
}

static gpointer tdx_sept_key(hwaddr gpa)
{
    return GSIZE_TO_POINTER(gpa >> TARGET_PAGE_BITS);
}

static TdxPageState tdx_sept_get(CPUX86State *env, hwaddr gpa)
{
    TdxTcgState *s = tdx_get_state();
    gpointer v;
    bool found;

    QEMU_LOCK_GUARD(&s->lock);
    found = s->sept &&
            g_hash_table_lookup_extended(s->sept, tdx_sept_key(gpa), NULL, &v);
    return found ? GPOINTER_TO_SIZE(v) : tdx_sept_default(env, gpa);
}

static void tdx_sept_set(CPUX86State *env, hwaddr gpa, TdxPageState st)
{
    TdxTcgState *s = tdx_get_state();

    QEMU_LOCK_GUARD(&s->lock);
    if (!s->sept) {
        s->sept = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_insert(s->sept, tdx_sept_key(gpa), GSIZE_TO_POINTER(st));
}

bool tdx_sept_enabled(CPUX86State *env)
{
    return env_archcpu(env)->tdx_guest &&
           env_archcpu(env)->tdx_sept != TDX_SEPT_OFF;
}

bool tdx_sept_gpa_is_shared(CPUX86State *env, hwaddr gpa)
{
    return tdx_sept_get(env, gpa) == TDX_PAGE_SHARED;
}

TdxSeptResult tdx_sept_check(CPUX86State *env, hwaddr gpa, bool shared)
{
    TdxPageState st = tdx_sept_get(env, gpa);

    if (shared) {
        return st == TDX_PAGE_SHARED ? TDX_SEPT_OK : TDX_SEPT_ALIAS_MISMATCH;
    }
    switch (st) {
    case TDX_PAGE_PRIVATE_ACCEPTED:
        return TDX_SEPT_OK;
    case TDX_PAGE_PRIVATE_PENDING:
        return TDX_SEPT_NOT_ACCEPTED;
    default:
        return TDX_SEPT_ALIAS_MISMATCH;
    }
}

/*
 * Convert a page.  Moving to private leaves it pending: the guest must accept
 * it before use, which is the ordering this teaches.  Only transitions that
 * remove access need a TLB flush -- a pending page can have no cached entry,
 * because the fill that would have created it faulted -- so accepting is free,
 * which matters when a TD accepts gigabytes a page at a time.
 */
static void tdx_sept_convert(CPUX86State *env, hwaddr gpa, bool to_shared)
{
    CPUState *cs = env_cpu(env);

    if (!tdx_sept_enabled(env)) {
        return;
    }
    tdx_sept_set(env, gpa, to_shared ? TDX_PAGE_SHARED
                                     : TDX_PAGE_PRIVATE_PENDING);
    tlb_flush(cs);
}

/*
 * An EPT violation, reported to the TD as #VE.  Bit 3 of the qualification says
 * the mapping was not present, which is how hardware distinguishes a page the
 * guest still has to accept from an ordinary permission failure.
 */
G_NORETURN void tdx_sept_fault(CPUX86State *env, TdxSeptResult res, hwaddr gpa,
                               bool shared, MMUAccessType access_type,
                               uintptr_t ra)
{
    uint64_t qual;

    switch (access_type) {
    case MMU_DATA_STORE:
        qual = 1 << 1;
        break;
    case MMU_INST_FETCH:
        qual = 1 << 2;
        break;
    default:
        qual = 1 << 0;
        break;
    }
    qual |= 1 << 3;

    qemu_log_mask(LOG_GUEST_ERROR,
                  "tdx: EPT violation: %s access to GPA 0x%" HWADDR_PRIx
                  " which is %s\n",
                  shared ? "SHARED-alias" : "private", gpa,
                  res == TDX_SEPT_NOT_ACCEPTED ? "not accepted"
                      : "mapped with the other alias");

    tdx_raise_ve(env, TDX_EXIT_REASON_EPT_VIOLATION, qual, 0,
                 shared ? (gpa | tdx_shared_mask(env)) : gpa, 0, 0, ra);
}

/*
 * Strip the emulated SHARED bit (GPA bit GPAW-1) from a guest-supplied
 * address.  A TDCALL operand names a page by its GPA, and the SHARED bit is
 * not part of the address, so it comes off before any bounds check or access.
 */
static uint64_t tdx_strip_shared(X86CPU *cpu, uint64_t gpa)
{
    return gpa & ~(1ULL << (cpu->tdx_gpaw - 1));
}

/*
 * Validate a guest-supplied GPA.  Modelled on the checks helper_vmrun() makes
 * before touching a VMCB (alignment, then physical-address bound), but a TDCALL
 * reports failure as a status code rather than raising an exception.
 */
static bool tdx_gpa_ok(X86CPU *cpu, uint64_t gpa, uint64_t align,
                       uint32_t operand_id, uint64_t *status)
{
    if (gpa & (align - 1)) {
        *status = TDX_ALIGN_ERROR | operand_id;
        return false;
    }
    if (gpa & ((~0ULL) << cpu->phys_bits)) {
        *status = TDX_OPERAND_ADDR_RANGE_ERROR | operand_id;
        return false;
    }
    return true;
}

/* TDG.VP.INFO (leaf 1): report the TD's configuration to the guest. */
static void tdx_vp_info(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);
    MachineState *ms = MACHINE(qdev_get_machine());

    env->regs[R_EAX] = TDX_SUCCESS;

    /* RCX: GPAW in bits 5:0; all other bits reserved and zero. */
    env->regs[R_ECX] = cpu->tdx_gpaw & 0x3f;

    /* RDX: TD ATTRIBUTES.  DEBUG (bit 0) is rejected at realize. */
    env->regs[R_EDX] = cpu->tdx_attributes;

    /* R8: NUM_VCPUS in 31:0, MAX_VCPUS in 63:32. */
    env->regs[R_R8] = (uint64_t)ms->smp.cpus |
                      ((uint64_t)ms->smp.max_cpus << 32);

    /* R9: VCPU_INDEX. */
    env->regs[R_R9] = (uint32_t)cs->cpu_index;

    /* R10 bit 0 would advertise TDG.SYS.RD/RDALL, which we do not implement. */
    env->regs[R_R10] = 0;
    env->regs[R_R11] = 0;
}

/*
 * TDG.MEM.PAGE.ACCEPT (leaf 6).  There is no SEPT emulation and all guest
 * memory is ordinary RAM, so accepting a page is a validated no-op.
 */
/* --- TDVMCALL<GetQuote> --------------------------------------------------- */

/* The buffer the guest shares: a header, the TDREPORT in, the Quote out. */
typedef struct QEMU_PACKED TdxQuoteHdr {
    uint64_t version;
    uint64_t status;
    uint32_t in_len;
    uint32_t out_len;
} TdxQuoteHdr;
QEMU_BUILD_BUG_ON(sizeof(TdxQuoteHdr) != TDX_QUOTE_HDR_LEN);

/* DCAP Quote v4 header. */
typedef struct QEMU_PACKED TdxQuoteHeader {
    uint16_t version;
    uint16_t att_key_type;
    uint32_t tee_type;
    uint16_t qe_svn;
    uint16_t pce_svn;
    uint8_t qe_vendor_id[16];
    uint8_t user_data[20];
} TdxQuoteHeader;
QEMU_BUILD_BUG_ON(sizeof(TdxQuoteHeader) != 48);

/* TDQuoteBody: the measurements a relying party would judge. */
typedef struct QEMU_PACKED TdxQuoteBody {
    uint8_t tee_tcb_svn[16];
    uint8_t mrseam[TDX_MEASUREMENT_LEN];
    uint8_t mrsignerseam[TDX_MEASUREMENT_LEN];
    uint8_t seamattributes[8];
    uint8_t tdattributes[8];
    uint8_t xfam[8];
    uint8_t mrtd[TDX_MEASUREMENT_LEN];
    uint8_t mrconfigid[TDX_MEASUREMENT_LEN];
    uint8_t mrowner[TDX_MEASUREMENT_LEN];
    uint8_t mrownerconfig[TDX_MEASUREMENT_LEN];
    uint8_t rtmr[TDX_RTMR_COUNT][TDX_MEASUREMENT_LEN];
    uint8_t reportdata[TDX_REPORTDATA_LEN];
} TdxQuoteBody;
QEMU_BUILD_BUG_ON(sizeof(TdxQuoteBody) != TDX_QUOTE_BODY_LEN);

/*
 * The signature section.  Shaped like the real thing so a parser can walk it,
 * but the signature and key are the not-real marker and the certification-data
 * type is 0 -- real types are 1..7, and inventing a PCK chain is the one thing
 * this must never do.
 */
typedef struct QEMU_PACKED TdxQuoteSig {
    uint8_t signature[TDX_QUOTE_SIG_LEN];
    uint8_t attest_pub_key[TDX_QUOTE_PUBKEY_LEN];
    uint16_t cert_data_type;
    uint32_t cert_data_size;
} TdxQuoteSig;

static void tdx_fill_marker(uint8_t *dst, size_t len)
{
    size_t i;

    for (i = 0; i < len; i += sizeof(TDX_TCG_FAKE_SIG) - 1) {
        size_t n = MIN(sizeof(TDX_TCG_FAKE_SIG) - 1, len - i);

        memcpy(dst + i, TDX_TCG_FAKE_SIG, n);
    }
}

/*
 * Build the Quote from the TDREPORT the guest submitted, so the measurements
 * and REPORTDATA in it are the ones it asked about rather than freshly
 * invented.  Offsets are into TDREPORT_STRUCT: TD_INFO starts at 512, and
 * REPORTDATA sits at 128 inside REPORTMACSTRUCT.
 */
static void tdx_build_quote(const uint8_t *report, GByteArray *out)
{
    TdxQuoteHeader hdr = { 0 };
    TdxQuoteBody body = { 0 };
    TdxQuoteSig sig = { 0 };
    uint32_t sig_len = cpu_to_le32(sizeof(sig));

    hdr.version = cpu_to_le16(TDX_QUOTE_V4);
    hdr.att_key_type = cpu_to_le16(TDX_ATT_KEY_ECDSA_P256);
    hdr.tee_type = cpu_to_le32(TDX_TEE_TYPE_TDX);
    memcpy(hdr.qe_vendor_id, TDX_TCG_FAKE_CPUSVN,
           MIN(sizeof(hdr.qe_vendor_id), sizeof(TDX_TCG_FAKE_CPUSVN) - 1));

    memcpy(body.reportdata, report + 128, TDX_REPORTDATA_LEN);
    memcpy(body.tdattributes, report + 512, 8);
    memcpy(body.xfam, report + 520, 8);
    memcpy(body.mrtd, report + 528, TDX_MEASUREMENT_LEN);
    memcpy(body.mrconfigid, report + 576, TDX_MEASUREMENT_LEN);
    memcpy(body.mrowner, report + 624, TDX_MEASUREMENT_LEN);
    memcpy(body.mrownerconfig, report + 672, TDX_MEASUREMENT_LEN);
    memcpy(body.rtmr, report + 720, sizeof(body.rtmr));

    tdx_fill_marker(sig.signature, sizeof(sig.signature));
    tdx_fill_marker(sig.attest_pub_key, sizeof(sig.attest_pub_key));
    sig.cert_data_type = 0;
    sig.cert_data_size = 0;

    g_byte_array_append(out, (const uint8_t *)&hdr, sizeof(hdr));
    g_byte_array_append(out, (const uint8_t *)&body, sizeof(body));
    g_byte_array_append(out, (const uint8_t *)&sig_len, sizeof(sig_len));
    g_byte_array_append(out, (const uint8_t *)&sig, sizeof(sig));
}

/* The emulated quoting service answering, some virtual milliseconds later. */
static void tdx_quote_complete(void *opaque)
{
    TdxTcgState *td = opaque;
    g_autoptr(GByteArray) quote = g_byte_array_new();
    g_autofree uint8_t *report = g_malloc0(TDX_REPORT_LEN);
    TdxQuoteHdr hdr;
    uint64_t gpa;
    uint64_t size;

    qemu_mutex_lock(&td->lock);
    if (!td->quote_pending) {
        qemu_mutex_unlock(&td->lock);
        return;
    }
    gpa = td->quote_gpa;
    size = td->quote_size;
    td->quote_pending = false;
    qemu_mutex_unlock(&td->lock);

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK ||
        address_space_read(&address_space_memory, gpa + sizeof(hdr),
                           MEMTXATTRS_UNSPECIFIED, report,
                           TDX_REPORT_LEN) != MEMTX_OK) {
        return;
    }

    tdx_build_quote(report, quote);

    if (sizeof(hdr) + quote->len > size) {
        /*
         * Too small.  Report the size needed and fail, which is what lets a
         * guest ask once with a small buffer and then allocate properly.
         */
        hdr.status = cpu_to_le64(GET_QUOTE_ERROR);
        hdr.out_len = cpu_to_le32(quote->len);
    } else {
        address_space_write(&address_space_memory, gpa + sizeof(hdr),
                            MEMTXATTRS_UNSPECIFIED, quote->data, quote->len);
        hdr.status = cpu_to_le64(GET_QUOTE_SUCCESS);
        hdr.out_len = cpu_to_le32(quote->len);
    }
    address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                        &hdr, sizeof(hdr));

    warn_report_once("tdx: produced a NON-GENUINE Quote. Its signature is a "
                     "fixed marker, not a signature, and it carries no "
                     "certification data. It is not evidence and must never be "
                     "sent to a relying party or a verification service.");
}

/*
 * TDVMCALL<GetQuote>: R12 the shared GPA of the buffer, R13 its length.
 *
 * The buffer has to be genuinely shared -- alias bit set and the page
 * converted -- which is the point at which a TD first needs working shared
 * memory for something that is not a device.
 */
static void tdx_get_quote(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    TdxTcgState *td = tdx_get_state();
    uint64_t raw_gpa = env->regs[R_R12];
    uint64_t size = env->regs[R_R13];
    uint64_t gpa = tdx_strip_shared(cpu, raw_gpa);
    TdxQuoteHdr hdr;
    uint64_t status;

    env->regs[R_EAX] = TDX_SUCCESS;

    if (!(raw_gpa & tdx_shared_mask(env))) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "tdx: GetQuote buffer at GPA 0x%" PRIx64 " is not in the "
                      "SHARED alias; the quoting service cannot reach TD "
                      "private memory\n", raw_gpa);
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }
    if (gpa & 0xfff) {
        env->regs[R_R10] = TDVMCALL_ALIGN_ERROR;
        return;
    }
    if (!tdx_gpa_ok(cpu, gpa, 4096, TDX_OPERAND_ID_RCX, &status) ||
        size < sizeof(hdr) + TDX_REPORT_LEN) {
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }
    if (tdx_sept_enabled(env) && !tdx_sept_gpa_is_shared(env, gpa)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "tdx: GetQuote buffer at GPA 0x%" PRIx64 " carries the "
                      "SHARED alias but was never converted with "
                      "TDVMCALL<MapGPA>\n", gpa);
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK) {
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }
    if (le64_to_cpu(hdr.version) != TDX_QUOTE_VERSION ||
        le32_to_cpu(hdr.in_len) != TDX_REPORT_LEN) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "tdx: GetQuote header version %" PRIu64 " in_len %u; "
                      "expected version %d and a %d-byte TDREPORT\n",
                      le64_to_cpu(hdr.version), le32_to_cpu(hdr.in_len),
                      TDX_QUOTE_VERSION, TDX_REPORT_LEN);
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }

    qemu_mutex_lock(&td->lock);
    if (td->quote_pending) {
        qemu_mutex_unlock(&td->lock);
        env->regs[R_R10] = TDVMCALL_GPA_INUSE;
        return;
    }
    td->quote_pending = true;
    td->quote_gpa = gpa;
    td->quote_size = size;
    qemu_mutex_unlock(&td->lock);

    /* Answer later; the guest polls the status field until it changes. */
    hdr.status = cpu_to_le64(GET_QUOTE_IN_FLIGHT);
    hdr.out_len = 0;
    address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                        &hdr, sizeof(hdr));

    if (!td->quote_timer) {
        td->quote_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, tdx_quote_complete,
                                       td);
    }
    timer_mod(td->quote_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + TDX_QUOTE_DELAY_MS);

    env->regs[R_R10] = TDVMCALL_SUCCESS;
}

static void tdx_mem_page_accept(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    uint64_t gpa = env->regs[R_ECX];
    uint64_t level = gpa & 7;
    uint64_t status;

    if (level != 0) {
        /* Only 4KiB pages are modelled. */
        env->regs[R_EAX] = TDX_PAGE_SIZE_MISMATCH | TDX_OPERAND_ID_RCX;
        return;
    }

    gpa = tdx_strip_shared(cpu, gpa & ~7ULL);
    if (!tdx_gpa_ok(cpu, gpa, 4096, TDX_OPERAND_ID_RCX, &status)) {
        env->regs[R_EAX] = status;
        return;
    }

    if (tdx_sept_enabled(env)) {
        switch (tdx_sept_get(env, gpa)) {
        case TDX_PAGE_PRIVATE_PENDING:
            /*
             * Accepting only adds access, and a pending page can have no
             * cached translation -- the fill that would have made one faulted
             * -- so no TLB flush is needed here.  That matters: a TD accepting
             * 4GiB performs a million of these.
             */
            tdx_sept_set(env, gpa, TDX_PAGE_PRIVATE_ACCEPTED);
            break;
        case TDX_PAGE_PRIVATE_ACCEPTED:
            env->regs[R_EAX] = TDX_PAGE_ALREADY_ACCEPTED;
            return;
        default:
            /* Shared: the guest must convert it to private first. */
            env->regs[R_EAX] = TDX_PAGE_ATTR_CONFLICT | TDX_OPERAND_ID_RCX;
            return;
        }
    }

    env->regs[R_EAX] = TDX_SUCCESS;
}

/*
 * TDVMCALL<Instruction.IO>: R12 access size, R13 direction (0 read, 1 write),
 * R14 port, R15 data for a write.  A read returns the value in R11.
 */
static uint64_t tdx_vmcall_io(CPUX86State *env)
{
    uint64_t size = env->regs[R_R12];
    /*
     * R13 is 0 for a read and 1 for a write, which is the opposite way round
     * from the exit qualification bit a guest derives it from -- and this read
     * it the wrong way for as long as the guest in this tree did, so the two
     * agreed and every emulated test passed. A TDX host disagreed on the first
     * inb().
     */
    uint64_t is_write = env->regs[R_R13];
    uint32_t port = (uint32_t)env->regs[R_R14];
    uint32_t data = (uint32_t)env->regs[R_R15];

    if (size != 1 && size != 2 && size != 4) {
        return TDVMCALL_INVALID_OPERAND;
    }
    if (is_write > 1) {
        return TDVMCALL_INVALID_OPERAND;
    }

    if (!is_write) {
        uint64_t val;

        switch (size) {
        case 1:
            val = helper_inb(env, port);
            break;
        case 2:
            val = helper_inw(env, port);
            break;
        default:
            val = helper_inl(env, port);
            break;
        }
        env->regs[R_R11] = val;
    } else {
        switch (size) {
        case 1:
            helper_outb(env, port, data);
            break;
        case 2:
            helper_outw(env, port, data);
            break;
        default:
            helper_outl(env, port, data);
            break;
        }
    }
    return TDVMCALL_SUCCESS;
}

/*
 * TDVMCALL<#VE.RequestMMIO>: R12 size, R13 direction (0 read, 1 write),
 * R14 GPA, R15 data for a write.  A read returns the value in R11.  This is
 * the counterpart of the #VE raised by tdx_mmio_check(): the guest cannot
 * touch device memory directly, so it asks the VMM to do it.
 */
static uint64_t tdx_vmcall_mmio(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    uint64_t size = env->regs[R_R12];
    /* 0 is a read and 1 is a write; see tdx_vmcall_io(). */
    uint64_t is_write = env->regs[R_R13];
    uint64_t gpa = tdx_strip_shared(cpu, env->regs[R_R14]);
    uint64_t data = env->regs[R_R15];
    uint8_t buf[8];

    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return TDVMCALL_INVALID_OPERAND;
    }
    if (is_write > 1) {
        return TDVMCALL_INVALID_OPERAND;
    }

    if (!is_write) {
        if (address_space_read(cpu_addressspace(cs, attrs), gpa, attrs, buf,
                               size) != MEMTX_OK) {
            return TDVMCALL_INVALID_OPERAND;
        }
        data = 0;
        memcpy(&data, buf, size);
        env->regs[R_R11] = data;
    } else {
        memcpy(buf, &data, size);
        if (address_space_write(cpu_addressspace(cs, attrs), gpa, attrs, buf,
                                size) != MEMTX_OK) {
            return TDVMCALL_INVALID_OPERAND;
        }
    }
    return TDVMCALL_SUCCESS;
}

/* TDVMCALL<Instruction.CPUID>: R12 leaf, R13 subleaf -> R11..R14 = EAX..EDX. */
static uint64_t tdx_vmcall_cpuid(CPUX86State *env)
{
    uint32_t eax, ebx, ecx, edx;

    cpu_x86_cpuid(env, (uint32_t)env->regs[R_R12], (uint32_t)env->regs[R_R13],
                  &eax, &ebx, &ecx, &edx);
    env->regs[R_R11] = eax;
    env->regs[R_R12] = ebx;
    env->regs[R_R13] = ecx;
    env->regs[R_R14] = edx;
    return TDVMCALL_SUCCESS;
}

/*
 * TDVMCALL<Instruction.RDMSR/WRMSR>.  The underlying helpers work on the
 * architectural registers, so the guest's RAX/RCX/RDX are saved and restored
 * around the call: a TDVMCALL passes its arguments in R12/R13 and must not
 * clobber the general-purpose registers the guest did not offer.
 */
static uint64_t tdx_vmcall_msr(CPUX86State *env, bool write)
{
    target_ulong save_rax = env->regs[R_EAX];
    target_ulong save_rcx = env->regs[R_ECX];
    target_ulong save_rdx = env->regs[R_EDX];
    uint64_t val;

    env->regs[R_ECX] = (uint32_t)env->regs[R_R12];
    if (write) {
        val = env->regs[R_R13];
        env->regs[R_EAX] = (uint32_t)val;
        env->regs[R_EDX] = (uint32_t)(val >> 32);
        helper_wrmsr(env);
    } else {
        helper_rdmsr(env);
        val = ((uint64_t)(uint32_t)env->regs[R_EDX] << 32) |
              (uint32_t)env->regs[R_EAX];
    }

    env->regs[R_EAX] = save_rax;
    env->regs[R_ECX] = save_rcx;
    env->regs[R_EDX] = save_rdx;

    if (!write) {
        env->regs[R_R11] = val;
    }
    return TDVMCALL_SUCCESS;
}

/*
 * TDG.VP.VMCALL (leaf 0).  The guest selects a sub-function in R11 and the
 * completion status is returned in R10, with RAX reporting only whether the
 * TDCALL itself was well-formed.
 */
static void tdx_vp_vmcall(CPUX86State *env, int next_eip_addend)
{
    X86CPU *cpu = env_archcpu(env);
    uint64_t subfn = env->regs[R_R11];
    uint64_t status;

    /* R10 == 0 selects the GHCI standard sub-function block. */
    if (env->regs[R_R10] != 0) {
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        return;
    }

    switch (subfn) {
    case TDVMCALL_INSTR_IO:
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = tdx_vmcall_io(env);
        return;

    case TDVMCALL_INSTR_CPUID:
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = tdx_vmcall_cpuid(env);
        return;

    case TDVMCALL_REQUEST_MMIO:
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = tdx_vmcall_mmio(env);
        return;

    case TDVMCALL_INSTR_RDMSR:
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = tdx_vmcall_msr(env, false);
        return;

    case TDVMCALL_INSTR_WRMSR:
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = tdx_vmcall_msr(env, true);
        return;

    case TDVMCALL_INSTR_HLT:
        /*
         * Halt on the guest's behalf.  EIP must be advanced past the TDCALL
         * first, exactly as helper_mwait() does, or the halt would resume by
         * re-executing this instruction forever.
         */
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_SUCCESS;
        env->eip += next_eip_addend;
        helper_hlt(env);
        /* not reached */

    default:
        break;
    }

    switch (subfn) {
    case TDVMCALL_MAP_GPA: {
        uint64_t gpa = tdx_strip_shared(cpu, env->regs[R_R12]);
        uint64_t size = env->regs[R_R13];

        if (size == 0 || (size & 0xfff) ||
            !tdx_gpa_ok(cpu, gpa, 4096, TDX_OPERAND_ID_RCX, &status)) {
            env->regs[R_EAX] = TDX_SUCCESS;
            env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
            return;
        }
        /*
         * R12 bit GPAW-1 selects the direction: the guest asks for the alias it
         * intends to use next.  Converting to private leaves the page pending,
         * so the guest must accept it before use.
         *
         * Only the first page of the range is converted: a range request is
         * accepted as a whole but modelled one page at a time by the guest
         * looping, which is what Linux does anyway.  A partial conversion is
         * reported so a guest that assumes range semantics finds out here.
         */
        bool to_shared = !!(env->regs[R_R12] & tdx_shared_mask(env));

        if (tdx_sept_enabled(env) && size > 4096) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "tdx: MapGPA of 0x%" PRIx64 " bytes at GPA 0x%"
                          PRIx64 "; only the first page is converted\n",
                          size, gpa);
            env->regs[R_EAX] = TDX_SUCCESS;
            env->regs[R_R10] = TDVMCALL_RETRY;
            env->regs[R_R11] = gpa + 4096;
            tdx_sept_convert(env, gpa, to_shared);
            break;
        }

        tdx_sept_convert(env, gpa, to_shared);
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_SUCCESS;
        break;
    }

    case TDVMCALL_GET_QUOTE:
        tdx_get_quote(env);
        break;

    default:
        qemu_log_mask(LOG_UNIMP,
                      "tdx: unimplemented TDG.VP.VMCALL sub-function 0x%"
                      PRIx64 "\n", subfn);
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
        break;
    }
}

/* TDREPORT_STRUCT and its components (Intel TDX Module ABI). */
typedef struct QEMU_PACKED TdxReportMac {
    uint8_t report_type[4];
    uint8_t reserved1[12];
    uint8_t cpusvn[16];
    uint8_t tee_tcb_info_hash[TDX_MEASUREMENT_LEN];
    uint8_t tee_info_hash[TDX_MEASUREMENT_LEN];
    uint8_t reportdata[TDX_REPORTDATA_LEN];
    uint8_t reserved2[32];
    uint8_t mac[32];
} TdxReportMac;
QEMU_BUILD_BUG_ON(sizeof(TdxReportMac) != 256);

typedef struct QEMU_PACKED TdxTdInfo {
    uint64_t attributes;
    uint64_t xfam;
    uint8_t mrtd[TDX_MEASUREMENT_LEN];
    uint8_t mrconfigid[TDX_MEASUREMENT_LEN];
    uint8_t mrowner[TDX_MEASUREMENT_LEN];
    uint8_t mrownerconfig[TDX_MEASUREMENT_LEN];
    uint8_t rtmr[TDX_RTMR_COUNT][TDX_MEASUREMENT_LEN];
    uint8_t servtd_hash[TDX_MEASUREMENT_LEN];
    uint8_t reserved[64];
} TdxTdInfo;
QEMU_BUILD_BUG_ON(sizeof(TdxTdInfo) != 512);

typedef struct QEMU_PACKED TdxReport {
    TdxReportMac report_mac;
    uint8_t tee_tcb_info[239];
    uint8_t reserved[17];
    TdxTdInfo td_info;
} TdxReport;
QEMU_BUILD_BUG_ON(sizeof(TdxReport) != TDX_REPORT_LEN);

static bool tdx_sha384(const struct iovec *iov, size_t niov, uint8_t *out)
{
    size_t len = TDX_MEASUREMENT_LEN;

    return qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA384, iov, niov,
                               &out, &len, NULL) == 0;
}

/*
 * TDG.MR.RTMR.EXTEND (leaf 2): RTMR[index] = SHA384(RTMR[index] || data),
 * where data is 48 bytes read from a 64-byte-aligned GPA in RCX.
 */
static void tdx_mr_rtmr_extend(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);
    TdxTcgState *td = tdx_get_state();
    uint64_t gpa = tdx_strip_shared(cpu, env->regs[R_ECX]);
    uint64_t index = env->regs[R_EDX];
    uint8_t data[TDX_MEASUREMENT_LEN];
    uint8_t digest[TDX_MEASUREMENT_LEN];
    uint64_t status;
    struct iovec iov[2];

    if (index >= TDX_RTMR_COUNT) {
        env->regs[R_EAX] = TDX_OPERAND_INVALID | TDX_OPERAND_ID_RDX;
        return;
    }
    if (!tdx_gpa_ok(cpu, gpa, TDX_RTMR_EXTEND_ALIGN, TDX_OPERAND_ID_RCX,
                    &status)) {
        env->regs[R_EAX] = status;
        return;
    }

    if (address_space_read(cpu_addressspace(cs, cpu_get_mem_attrs(env)), gpa,
                           cpu_get_mem_attrs(env), data, sizeof(data))
        != MEMTX_OK) {
        env->regs[R_EAX] = TDX_OPERAND_ADDR_RANGE_ERROR | TDX_OPERAND_ID_RCX;
        return;
    }

    qemu_mutex_lock(&td->lock);
    iov[0].iov_base = td->rtmr[index];
    iov[0].iov_len = TDX_MEASUREMENT_LEN;
    iov[1].iov_base = data;
    iov[1].iov_len = sizeof(data);
    if (!tdx_sha384(iov, 2, digest)) {
        qemu_mutex_unlock(&td->lock);
        env->regs[R_EAX] = TDX_OPERAND_BUSY;
        return;
    }
    memcpy(td->rtmr[index], digest, TDX_MEASUREMENT_LEN);
    qemu_mutex_unlock(&td->lock);

    env->regs[R_EAX] = TDX_SUCCESS;
}

/*
 * TDG.MR.REPORT (leaf 4).  Produces a structurally valid TDREPORT whose
 * authentication is deliberately absent -- see TDX_TCG_FAKE_MAC.  The hashes
 * over TEE_TCB_INFO and TD_INFO are computed honestly so that guest-side
 * parsers can be developed, but nothing here is verifiable evidence.
 */
static void tdx_mr_report(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);
    TdxTcgState *td = tdx_get_state();
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);
    uint64_t report_gpa = tdx_strip_shared(cpu, env->regs[R_ECX]);
    uint64_t data_gpa = tdx_strip_shared(cpu, env->regs[R_EDX]);
    uint64_t subtype = env->regs[R_R8];
    uint64_t status;
    TdxReport report;
    struct iovec iov[1];

    if (subtype != 0) {
        env->regs[R_EAX] = TDX_OPERAND_INVALID | TDX_OPERAND_ID_R8;
        return;
    }
    if (!tdx_gpa_ok(cpu, report_gpa, TDX_REPORT_ALIGN, TDX_OPERAND_ID_RCX,
                    &status) ||
        !tdx_gpa_ok(cpu, data_gpa, TDX_REPORTDATA_ALIGN, TDX_OPERAND_ID_RDX,
                    &status)) {
        env->regs[R_EAX] = status;
        return;
    }

    warn_report_once("tdx: TDG.MR.REPORT produced a NON-GENUINE TDREPORT. The "
                     "REPORTMACSTRUCT MAC is a fixed constant, not a MAC. It "
                     "has no attestation meaning and must never be submitted "
                     "to a quoting service or a relying party.");

    memset(&report, 0, sizeof(report));
    report.report_mac.report_type[0] = 0x81; /* TTYPE_TDX */

    QEMU_BUILD_BUG_ON(sizeof(TDX_TCG_FAKE_MAC) - 1 !=
                      sizeof(report.report_mac.mac));
    memcpy(report.report_mac.mac, TDX_TCG_FAKE_MAC,
           sizeof(report.report_mac.mac));
    QEMU_BUILD_BUG_ON(sizeof(TDX_TCG_FAKE_CPUSVN) - 1 !=
                      sizeof(report.report_mac.cpusvn));
    memcpy(report.report_mac.cpusvn, TDX_TCG_FAKE_CPUSVN,
           sizeof(report.report_mac.cpusvn));

    if (address_space_read(as, data_gpa, attrs, report.report_mac.reportdata,
                           TDX_REPORTDATA_LEN) != MEMTX_OK) {
        env->regs[R_EAX] = TDX_OPERAND_ADDR_RANGE_ERROR | TDX_OPERAND_ID_RDX;
        return;
    }

    /* TEE_TCB_INFO is a sentinel, not a plausible TDX module SVN. */
    memcpy(report.tee_tcb_info, TDX_TCG_FAKE_MAC,
           MIN(sizeof(TDX_TCG_FAKE_MAC) - 1, sizeof(report.tee_tcb_info)));

    qemu_mutex_lock(&td->lock);
    report.td_info.attributes = cpu->tdx_attributes;
    report.td_info.xfam = 0;
    memcpy(report.td_info.mrtd, td->mrtd, TDX_MEASUREMENT_LEN);
    memcpy(report.td_info.rtmr, td->rtmr, sizeof(report.td_info.rtmr));
    qemu_mutex_unlock(&td->lock);

    iov[0].iov_base = report.tee_tcb_info;
    iov[0].iov_len = sizeof(report.tee_tcb_info);
    tdx_sha384(iov, 1, report.report_mac.tee_tcb_info_hash);
    iov[0].iov_base = &report.td_info;
    iov[0].iov_len = sizeof(report.td_info);
    tdx_sha384(iov, 1, report.report_mac.tee_info_hash);

    if (address_space_write(as, report_gpa, attrs, &report, sizeof(report))
        != MEMTX_OK) {
        env->regs[R_EAX] = TDX_OPERAND_ADDR_RANGE_ERROR | TDX_OPERAND_ID_RCX;
        return;
    }

    env->regs[R_EAX] = TDX_SUCCESS;
}

/*
 * TDG.VP.VEINFO.GET (leaf 3).  A TD guest retrieves #VE information only
 * through this call -- there is no VE-info page and no IA32_VE_INFO_ADDRESS
 * MSR; those are plain-VMX constructs.
 */
static void tdx_vp_veinfo_get(CPUX86State *env)
{
    if (!env->tdx_ve_valid) {
        env->regs[R_EAX] = TDX_NO_VE_INFO;
        return;
    }

    env->regs[R_EAX] = TDX_SUCCESS;
    env->regs[R_ECX] = env->tdx_ve_exit_reason;
    env->regs[R_EDX] = env->tdx_ve_exit_qual;
    env->regs[R_R8] = env->tdx_ve_gla;
    env->regs[R_R9] = env->tdx_ve_gpa;
    env->regs[R_R10] = (uint64_t)env->tdx_ve_instr_len |
                       ((uint64_t)env->tdx_ve_instr_info << 32);

    /* Consumed: a further #VE may now be delivered. */
    env->tdx_ve_valid = false;
}

/*
 * Latch #VE information and raise vector 20.  Real TDX turns a #VE raised
 * while VE_INFO is still valid into #DF, which is what stops a guest with a
 * broken handler from looping forever.
 */
static G_NORETURN void tdx_raise_ve(CPUX86State *env, uint32_t reason,
                                    uint64_t qual, uint64_t gla, uint64_t gpa,
                                    uint32_t instr_len, uint32_t instr_info,
                                    uintptr_t ra)
{
    if (env->tdx_ve_valid) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "tdx: #VE (reason %u) while VE_INFO still valid; "
                      "injecting #DF as the TDX module would\n", reason);
        raise_exception_err_ra(env, EXCP08_DBLE, 0, ra);
    }

    env->tdx_ve_exit_reason = reason;
    env->tdx_ve_exit_qual = qual;
    env->tdx_ve_gla = gla;
    env->tdx_ve_gpa = gpa;
    env->tdx_ve_instr_len = instr_len;
    env->tdx_ve_instr_info = instr_info;
    env->tdx_ve_valid = true;

    qemu_log_mask(LOG_GUEST_ERROR,
                  "tdx: injecting #VE (exit reason %u) at RIP 0x" TARGET_FMT_lx
                  "\n", reason, env->eip);
    raise_exception_ra(env, EXCP14_VE, ra);
}

/* Is this #VE class enabled, and has the TD payload taken over yet? */
static bool tdx_ve_enabled(CPUX86State *env, uint32_t class)
{
    return (env_archcpu(env)->tdx_ve_mask & class) && tdx_get_state()->ve_armed;
}

/* HLT reflection: exit qualification bit 0 mirrors RFLAGS.IF. */
void helper_tdx_ve_hlt(CPUX86State *env, uint32_t instr_len)
{
    if (!tdx_ve_enabled(env, TDX_VE_HLT)) {
        return;
    }
    tdx_raise_ve(env, TDX_EXIT_REASON_HLT,
                 (env->eflags & IF_MASK) ? 1 : 0, 0, 0, instr_len, 0, GETPC());
}

/*
 * MMIO reflection.  A TD maps device memory as shared, and an access to it
 * exits to the VMM; the guest sees an EPT violation reported as #VE and
 * services it with TDVMCALL<#VE.RequestMMIO>.  Reflecting here rather than at
 * the instruction is what makes the model faithful: the guest cannot tell
 * which instruction touched MMIO, only that a physical address did, which is
 * exactly the information hardware gives it.
 */
void tdx_mmio_check(CPUX86State *env, hwaddr paddr, MMUAccessType access_type,
                    uintptr_t ra)
{
    CPUState *cs = env_cpu(env);
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    hwaddr xlat, len = 1;
    MemoryRegion *mr;
    uint64_t qual;

    if (!tdx_ve_enabled(env, TDX_VE_MMIO)) {
        return;
    }

    mr = address_space_translate(cpu_addressspace(cs, attrs), paddr, &xlat,
                                 &len, access_type == MMU_DATA_STORE, attrs);
    if (memory_region_is_ram(mr) || memory_region_is_romd(mr)) {
        return;
    }

    /* EPT violation qualification: bit 0 read, bit 1 write, bit 2 fetch. */
    switch (access_type) {
    case MMU_DATA_STORE:
        qual = 1 << 1;
        break;
    case MMU_INST_FETCH:
        qual = 1 << 2;
        break;
    default:
        qual = 1 << 0;
        break;
    }

    tdx_raise_ve(env, TDX_EXIT_REASON_EPT_VIOLATION, qual, 0, paddr, 0, 0, ra);
}

/*
 * Port I/O reflection.  The exit qualification is built at translate time,
 * where the access size, direction, string form and REP prefix are known.
 */
void helper_tdx_ve_io(CPUX86State *env, uint32_t port, uint32_t qual,
                      uint32_t instr_len)
{
    if (!tdx_ve_enabled(env, TDX_VE_IO)) {
        return;
    }
    tdx_raise_ve(env, TDX_EXIT_REASON_IO_INSTRUCTION,
                 qual | ((uint64_t)port << 16), 0, 0, instr_len, 0, GETPC());
}

/*
 * MSR classification.  A real TD handles many MSRs natively and only reflects
 * the rest, so this is emphatically not "reflect everything": the MSRs below
 * are part of ordinary long-mode and TLS setup, and a TD that took #VE on them
 * could not boot.  An EFER *write* is #GP in a TD, not #VE, but modelling that
 * would break guests that legitimately set LME during their own boot, so it is
 * treated as native here and noted in the docs.
 */
static bool tdx_msr_is_native(uint32_t idx)
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
        return true;
    default:
        return false;
    }
}

void helper_tdx_ve_msr(CPUX86State *env, uint32_t is_write, uint32_t instr_len)
{
    uint32_t idx = (uint32_t)env->regs[R_ECX];

    if (!tdx_ve_enabled(env, TDX_VE_MSR) || tdx_msr_is_native(idx)) {
        return;
    }
    tdx_raise_ve(env,
                 is_write ? TDX_EXIT_REASON_MSR_WRITE : TDX_EXIT_REASON_MSR_READ,
                 idx, 0, 0, instr_len, 0, GETPC());
}

/*
 * CPUID reflection.  Leaf 0 and the TDX identification leaf are always
 * answered natively: a guest that could not execute them would have no way to
 * discover it is running in a TD, nor to find the TDCALL interface with which
 * to service the #VE.
 */
void helper_tdx_ve_cpuid(CPUX86State *env, uint32_t instr_len)
{
    uint32_t leaf = (uint32_t)env->regs[R_EAX];

    if (!tdx_ve_enabled(env, TDX_VE_CPUID) ||
        leaf == 0 || leaf == TDX_CPUID_LEAF) {
        return;
    }
    tdx_raise_ve(env, TDX_EXIT_REASON_CPUID, leaf, 0, 0, instr_len, 0, GETPC());
}

void helper_tdcall(CPUX86State *env, int next_eip_addend)
{
    uint64_t leaf = env->regs[R_EAX];
    TdxTcgState *td = tdx_get_state();

    /* The guest is TD-aware from here on; start reflecting #VE. */
    if (!td->ve_armed) {
        qemu_mutex_lock(&td->lock);
        td->ve_armed = true;
        qemu_mutex_unlock(&td->lock);
        tdx_dma_arm();
    }

    switch (leaf) {
    case TDG_VP_VMCALL:
        tdx_vp_vmcall(env, next_eip_addend);
        break;
    case TDG_VP_INFO:
        tdx_vp_info(env);
        break;
    case TDG_MR_RTMR_EXTEND:
        tdx_mr_rtmr_extend(env);
        break;
    case TDG_VP_VEINFO_GET:
        tdx_vp_veinfo_get(env);
        break;
    case TDG_MR_REPORT:
        tdx_mr_report(env);
        break;
    case TDG_MEM_PAGE_ACCEPT:
        tdx_mem_page_accept(env);
        break;
    default:
        /*
         * The TDX module reports an unknown leaf as an invalid operand; it
         * never raises #UD.  This matters: a guest may issue its first TDCALL
         * before installing an IDT, where any fault is a silent triple fault.
         */
        qemu_log_mask(LOG_UNIMP,
                      "tdx: unimplemented TDCALL leaf 0x%" PRIx64 "\n", leaf);
        env->regs[R_EAX] = TDX_OPERAND_INVALID | TDX_OPERAND_ID_RAX;
        break;
    }
}

#endif /* TARGET_X86_64 */
