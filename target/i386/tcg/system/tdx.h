/*
 * Emulated Intel TDX guest environment for TCG.
 *
 * This models the *guest-visible* TDX ABI (CPUID.0x21, TDCALL, #VE) so that a
 * TD guest can be developed and exercised without TDX hardware.  It is NOT
 * Intel TDX: there is no memory encryption, no measured launch, no isolation
 * from the host, and no genuine attestation.
 *
 * Distinct from target/i386/kvm/tdx.c, which drives real TDX via KVM.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef I386_TCG_SYSTEM_TDX_H
#define I386_TCG_SYSTEM_TDX_H

/*
 * TDCALL leaf numbers (Intel TDX Module ABI).  Only the leaves listed here are
 * recognised; everything else returns TDX_OPERAND_INVALID.
 */
#define TDG_VP_VMCALL                   0ULL
#define TDG_VP_INFO                     1ULL
#define TDG_MR_RTMR_EXTEND              2ULL
#define TDG_VP_VEINFO_GET               3ULL
#define TDG_MR_REPORT                   4ULL
#define TDG_MEM_PAGE_ACCEPT             6ULL

/*
 * TDX status codes.  Bit 63 signals an error; a nonzero value with bit 63
 * clear is a warning.  Success is zero.  Guests rely on the distinction, and
 * may test either "!= 0" or "bit 63 set" depending on the leaf, so warnings
 * must not be reported as errors.
 */
#define TDX_SUCCESS                     0x0000000000000000ULL
#define TDX_PAGE_ALREADY_ACCEPTED       0x00000B0A00000000ULL
#define TDX_OPERAND_INVALID             0xC000010000000000ULL
#define TDX_OPERAND_ADDR_RANGE_ERROR    0xC000010100000000ULL
#define TDX_OPERAND_BUSY                0x8000020000000000ULL
#define TDX_ALIGN_ERROR                 0xC000030000000000ULL
#define TDX_NO_VE_INFO                  0xC000070000000000ULL
#define TDX_PAGE_SIZE_MISMATCH          0xC0000B0B00000000ULL

/* Operand identifiers, ORed into bits 31:0 of a status code. */
#define TDX_OPERAND_ID_RAX              0x00000000U
#define TDX_OPERAND_ID_RCX              0x00000001U
#define TDX_OPERAND_ID_RDX              0x00000002U
#define TDX_OPERAND_ID_R8               0x00000008U

/*
 * TDG.VP.VMCALL sub-function numbers and completion status.  The
 * "Instruction.*" service routines reuse the VMX exit-reason numbering, which
 * is what lets a guest handle a #VE by passing the exit reason it just read
 * from TDG.VP.VEINFO.GET straight back as the sub-function.
 */
#define TDVMCALL_INSTR_CPUID            10ULL
#define TDVMCALL_INSTR_HLT              12ULL
#define TDVMCALL_INSTR_IO               30ULL
#define TDVMCALL_INSTR_RDMSR            31ULL
#define TDVMCALL_INSTR_WRMSR            32ULL
#define TDVMCALL_MAP_GPA                0x10001ULL
#define TDVMCALL_GET_QUOTE              0x10002ULL
#define TDVMCALL_SUCCESS                0x0000000000000000ULL
#define TDVMCALL_RETRY                  0x0000000000000001ULL
#define TDVMCALL_INVALID_OPERAND        0x8000000000000000ULL

/* TD ATTRIBUTES bits. */
#define TDX_TD_ATTR_DEBUG               (1ULL << 0)
#define TDX_TD_ATTR_SEPT_VE_DISABLE     (1ULL << 28)

/*
 * #VE reflection classes, selected by the x-tdx-ve-* properties and cached in
 * X86CPU::tdx_ve_mask.  Real TDX reflects all of these, but a guest being
 * ported to TDX typically handles none of them at first, so each class is
 * individually selectable and can be adopted one at a time.
 */
#define TDX_VE_IO                       (1U << 0)
#define TDX_VE_MSR                      (1U << 1)
#define TDX_VE_CPUID                    (1U << 2)
#define TDX_VE_HLT                      (1U << 3)

/* #VE exit reasons; TDX reuses the VMX basic exit-reason numbering. */
#define TDX_EXIT_REASON_CPUID           10
#define TDX_EXIT_REASON_HLT             12
#define TDX_EXIT_REASON_IO_INSTRUCTION  30
#define TDX_EXIT_REASON_MSR_READ        31
#define TDX_EXIT_REASON_MSR_WRITE       32
#define TDX_EXIT_REASON_EPT_VIOLATION   48

/* Measurement register geometry: SHA-384 digests, four RTMRs. */
#define TDX_MEASUREMENT_LEN             48
#define TDX_RTMR_COUNT                  4
#define TDX_REPORTDATA_LEN              64
#define TDX_REPORT_LEN                  1024
#define TDX_REPORT_ALIGN                1024
#define TDX_REPORTDATA_ALIGN            64
#define TDX_RTMR_EXTEND_ALIGN           64

/*
 * The emulated TDREPORT is deliberately not authenticated.  The MAC field is
 * this fixed string rather than a keyed hash, so two reports over different
 * REPORTDATA are byte-identical in the MAC -- immediately detectable by any
 * verifier, and impossible to pass off as genuine evidence.  There is no
 * quoting path: TDVMCALL<GetQuote> is refused.
 */
#define TDX_TCG_FAKE_MAC    "QEMU-TCG-EMULATED-TDX-NOT-REAL!!"
#define TDX_TCG_FAKE_CPUSVN "EMULATED-TDX\0\0\0\0"

/* CPUID.0x21:0 identification leaf, "IntelTDX    " in EBX:EDX:ECX. */
#define TDX_CPUID_LEAF                  0x21
#define TDX_CPUID_SIG_EBX               0x65746E49U /* "Inte" */
#define TDX_CPUID_SIG_EDX               0x5844546CU /* "lTDX" */
#define TDX_CPUID_SIG_ECX               0x20202020U /* "    " */

#endif /* I386_TCG_SYSTEM_TDX_H */
