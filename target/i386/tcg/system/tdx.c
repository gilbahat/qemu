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
#include "tcg/helper-tcg.h"
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
} TdxTcgState;

static TdxTcgState *tdx_state;

static TdxTcgState *tdx_get_state(void)
{
    if (!tdx_state) {
        tdx_state = g_new0(TdxTcgState, 1);
        qemu_mutex_init(&tdx_state->lock);
    }
    return tdx_state;
}

/*
 * Strip the emulated SHARED bit (GPA bit GPAW-1) from a guest-supplied
 * address.  TCG pins phys_bits to TCG_PHYS_ADDR_BITS (40) while the reported
 * GPAW defaults to 48, so the SHARED bit sits above the addressable range and
 * must be removed before any bounds check or memory access.
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

    env->regs[R_EAX] = TDX_SUCCESS;
}

/*
 * TDVMCALL<Instruction.IO>: R12 access size, R13 direction (0 write, 1 read),
 * R14 port, R15 data for a write.  A read returns the value in R11.
 */
static uint64_t tdx_vmcall_io(CPUX86State *env)
{
    uint64_t size = env->regs[R_R12];
    uint64_t is_read = env->regs[R_R13];
    uint32_t port = (uint32_t)env->regs[R_R14];
    uint32_t data = (uint32_t)env->regs[R_R15];

    if (size != 1 && size != 2 && size != 4) {
        return TDVMCALL_INVALID_OPERAND;
    }
    if (is_read > 1) {
        return TDVMCALL_INVALID_OPERAND;
    }

    if (is_read) {
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
         * Private and shared memory are the same RAM here, so the transition
         * is a no-op.  Report success so a guest that maps buffers shared
         * before doing I/O behaves as it would on real hardware.
         */
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_SUCCESS;
        break;
    }

    case TDVMCALL_GET_QUOTE:
        /*
         * Deliberately refused.  A Quote is the only form in which a TDREPORT
         * becomes remote evidence, and the emulated report is unauthenticated
         * by construction, so no quoting path is provided.
         */
        warn_report_once("tdx: refusing TDVMCALL<GetQuote>; the emulated TD "
                         "has no attestation key and cannot produce evidence");
        env->regs[R_EAX] = TDX_SUCCESS;
        env->regs[R_R10] = TDVMCALL_INVALID_OPERAND;
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
