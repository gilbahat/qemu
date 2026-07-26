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
/*
 * Returned when TDG.MEM.PAGE.ACCEPT names a page whose attributes do not allow
 * it -- here, one the guest has converted to shared.  Taken from the TDX module
 * specification; like TDX_PAGE_ALREADY_ACCEPTED it is not cross-checked against
 * anything else in tree.
 */
#define TDX_PAGE_ATTR_CONFLICT          0xC0000B0900000000ULL

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
#define TDVMCALL_REQUEST_MMIO           48ULL
#define TDVMCALL_MAP_GPA                0x10001ULL
#define TDVMCALL_GET_QUOTE              0x10002ULL
#define TDVMCALL_SUCCESS                0x0000000000000000ULL
#define TDVMCALL_RETRY                  0x0000000000000001ULL
#define TDVMCALL_INVALID_OPERAND        0x8000000000000000ULL
#define TDVMCALL_GPA_INUSE              0x8000000000000001ULL
#define TDVMCALL_ALIGN_ERROR            0x8000000000000002ULL

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
#define TDX_VE_MMIO                     (1U << 4)

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
/*
 * TDVMCALL<GetQuote>.  The guest hands over a shared buffer holding a TDREPORT
 * and gets back a Quote; on hardware the VMM forwards it to a Quoting Enclave,
 * which signs it with a key whose PCK certificate chains to Intel's root.
 *
 * Everything about the *flow* is modelled: the buffer must be shared and
 * converted, the call completes asynchronously so the guest has to poll, and
 * the reply is a structurally correct Quote v4 reflecting the report submitted.
 *
 * The signature is not.  There is no attestation key and there never can be, so
 * the signature and attestation-key fields carry TDX_TCG_FAKE_SIG and the
 * certification-data type is left at 0 rather than fabricating a PCK chain --
 * a DCAP verifier rejects the result immediately, which is correct.
 */
#define TDX_QUOTE_VERSION               1
#define TDX_QUOTE_HDR_LEN               24

#define GET_QUOTE_SUCCESS               0x0000000000000000ULL
#define GET_QUOTE_IN_FLIGHT             0xffffffffffffffffULL
#define GET_QUOTE_ERROR                 0x8000000000000000ULL
#define GET_QUOTE_SERVICE_UNAVAILABLE   0x8000000000000001ULL

/* DCAP Quote v4 for TDX. */
#define TDX_QUOTE_V4                    4
#define TDX_ATT_KEY_ECDSA_P256          2
#define TDX_TEE_TYPE_TDX                0x00000081U
#define TDX_QUOTE_BODY_LEN              584
#define TDX_QUOTE_SIG_LEN               64
#define TDX_QUOTE_PUBKEY_LEN            64

/* How long the emulated quoting service takes, in virtual milliseconds. */
#define TDX_QUOTE_DELAY_MS              100

#define TDX_TCG_FAKE_SIG    "QEMU-TCG-EMULATED-TDX-QUOTE-NOT-REAL-EVIDENCE!!!"

#define TDX_TCG_FAKE_MAC    "QEMU-TCG-EMULATED-TDX-NOT-REAL!!"
#define TDX_TCG_FAKE_CPUSVN "EMULATED-TDX\0\0\0\0"

/* CPUID.0x21:0 identification leaf, "IntelTDX    " in EBX:EDX:ECX. */
#define TDX_CPUID_LEAF                  0x21
#define TDX_CPUID_SIG_EBX               0x65746E49U /* "Inte" */
#define TDX_CPUID_SIG_EDX               0x5844546CU /* "lTDX" */
#define TDX_CPUID_SIG_ECX               0x20202020U /* "    " */

/*
 * Reflect a TD's MMIO access as #VE, as an EPT violation on shared memory.
 * A no-op unless the MMIO class is enabled and reflection is armed.  Called
 * from x86_cpu_tlb_fill() once a translation has succeeded.
 */
void tdx_mmio_check(CPUX86State *env, hwaddr paddr, MMUAccessType access_type,
                    uintptr_t ra);

/*
 * Create the VM-scoped singleton and register its VMState section.  Called at
 * TCG realize so the section exists before an incoming migration needs it.
 */
void tdx_tcg_init(void);

/*
 * Secure-EPT-lite modes, selected by x-tdx-sept.
 *
 * LAZY exists for the same reason the SNP equivalent does: guest RAM is private
 * and unaccepted on real hardware, so under STRICT a TD that does not accept
 * its memory faults on its first instruction fetch.  That is the truth and it
 * is what a conformance run wants, but it leaves no way to adopt the shared
 * alias and TDG.MEM.PAGE.ACCEPT a page at a time.
 */
#define TDX_SEPT_OFF                    0
#define TDX_SEPT_LAZY                   1
#define TDX_SEPT_STRICT                 2

/*
 * Per-page state.  A TD's memory starts private and pending; the guest accepts
 * it before use, and MapGPA moves pages between private and shared.
 */
typedef enum {
    TDX_PAGE_SHARED = 0,
    TDX_PAGE_PRIVATE_PENDING,
    TDX_PAGE_PRIVATE_ACCEPTED,
} TdxPageState;

/*
 * Every one of these is an EPT violation delivered as #VE on hardware, so
 * unlike SNP -- where a polarity mismatch is invisible to the guest and kills
 * the VM -- there is a single fault path and the guest can handle all of them.
 */
typedef enum {
    TDX_SEPT_OK = 0,
    TDX_SEPT_NOT_ACCEPTED,   /* private access to a page not yet accepted */
    TDX_SEPT_ALIAS_MISMATCH, /* alias used disagrees with the page's state */
} TdxSeptResult;

/* Is page-state enforcement on?  False unless x-tdx-sept says otherwise. */
bool tdx_sept_enabled(CPUX86State *env);

/* Check an access against the page's state; @shared is the PTE's SHARED bit. */
TdxSeptResult tdx_sept_check(CPUX86State *env, hwaddr gpa, bool shared);

/* Reflect an EPT violation as #VE.  Does not return. */
G_NORETURN void tdx_sept_fault(CPUX86State *env, TdxSeptResult res, hwaddr gpa,
                               bool shared, MMUAccessType access_type,
                               uintptr_t ra);

/* Is this GPA shared?  What the DMA filter asks. */
bool tdx_sept_gpa_is_shared(CPUX86State *env, hwaddr gpa);

/*
 * The emulated SHARED GPA bit (GPA bit GPAW-1), or 0 when x-tdx-guest is off.
 * Callers strip it from any address taken out of a page-table entry or CR3: the
 * phys_bits == GPAW invariant keeps it out of the walker's reserved-bit mask,
 * but it is still inside PG_ADDRESS_MASK and would otherwise be folded into the
 * physical address -- pointing the access at RAM that does not exist.
 *
 * Folding the SHARED alias back onto the same page is what makes the model
 * work without encryption: private and shared are the same memory here, so a
 * page-state change moves an attribute and not any data.  On hardware the two
 * aliases are distinct Secure-EPT entries and a conversion loses the contents.
 *
 * Inline for the same reason snp_cbit_mask() is: target/i386/helper.c needs it
 * and is built even where tdx.c is not.
 */
static inline uint64_t tdx_shared_mask(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);

    return cpu->tdx_guest ? (1ULL << (cpu->tdx_gpaw - 1)) : 0;
}

#endif /* I386_TCG_SYSTEM_TDX_H */
