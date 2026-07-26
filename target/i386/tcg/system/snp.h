/*
 * Emulated AMD SEV-SNP guest environment for TCG.
 *
 * Models the *guest-visible* SEV-SNP ABI (CPUID.0x8000001F, the SEV MSRs,
 * VMGEXIT, #VC) so that an SNP guest can be developed and exercised without SEV
 * hardware.  It is NOT SEV-SNP: there is no memory encryption, no RMP enforced
 * by hardware, no isolation from the host, and no attestation.
 *
 * Distinct from target/i386/sev.c, which drives real SEV via KVM.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef I386_TCG_SYSTEM_SNP_H
#define I386_TCG_SYSTEM_SNP_H

/* CPUID.0x8000001F:EAX feature bits. */
#define SNP_CPUID_SEV                   (1U << 1)
#define SNP_CPUID_SEV_ES                (1U << 3)
#define SNP_CPUID_SEV_SNP               (1U << 4)

/*
 * MSR_AMD64_SEV (SEV_STATUS) is read-only and tells the guest which of the
 * three modes it is running under.  MSR_AMD64_SEV_ES_GHCB is the GHCB MSR
 * protocol register, the only channel a guest has before it owns a GHCB page.
 */
#define MSR_AMD64_SEV_ES_GHCB           0xc0010130
#define MSR_AMD64_SEV                   0xc0010131
#define MSR_AMD64_SEV_ENABLED           (1ULL << 0)
#define MSR_AMD64_SEV_ES_ENABLED        (1ULL << 1)
#define MSR_AMD64_SEV_SNP_ENABLED       (1ULL << 2)

/*
 * #VC reflection classes.  Selected by the x-sev-snp-relax-* properties, which
 * switch a class *off*: a real SNP guest takes #VC on all of these, so the
 * default is to reflect everything and relax individually while porting.
 */
#define SNP_VC_IO                       (1U << 0)
#define SNP_VC_MSR                      (1U << 1)
#define SNP_VC_CPUID                    (1U << 2)
#define SNP_VC_HLT                      (1U << 3)
#define SNP_VC_ALL                      (SNP_VC_IO | SNP_VC_MSR | \
                                         SNP_VC_CPUID | SNP_VC_HLT)

/*
 * GHCB MSR protocol: the low 12 bits are the info code.  A page-aligned value
 * with a zero info field is a registered GHCB GPA rather than a request, which
 * is how an in-flight request is distinguished from an idle register.
 */
#define SNP_GHCB_MSR_INFO_MASK          0xfffULL
#define SNP_GHCB_MSR_INFO(v)            ((v) & SNP_GHCB_MSR_INFO_MASK)
#define SNP_GHCB_MSR_DATA(v)            ((v) & ~SNP_GHCB_MSR_INFO_MASK)

/* GHCB MSR protocol info codes: even values request, odd values respond. */
#define GHCB_MSR_SEV_INFO_RESP          0x001
#define GHCB_MSR_SEV_INFO_REQ           0x002
#define GHCB_MSR_CPUID_REQ              0x004
#define GHCB_MSR_CPUID_RESP             0x005
#define GHCB_MSR_PREF_GPA_REQ           0x010
#define GHCB_MSR_PREF_GPA_RESP          0x011
#define GHCB_MSR_REG_GPA_REQ            0x012
#define GHCB_MSR_REG_GPA_RESP           0x013
#define GHCB_MSR_PSC_REQ                0x014
#define GHCB_MSR_PSC_RESP               0x015
#define GHCB_MSR_HV_FT_REQ              0x080
#define GHCB_MSR_HV_FT_RESP             0x081
#define GHCB_MSR_TERM_REQ               0x100

/* "No preference" for the preferred-GHCB-GPA request. */
#define GHCB_MSR_PREF_GPA_NONE          0xfffffffffffffULL

/* Protocol versions we speak, reported in the SEV information response. */
#define GHCB_PROTOCOL_MIN               1
#define GHCB_PROTOCOL_MAX               2

/* Page-state-change operations, in bits [63:56] of a PSC request. */
#define GHCB_MSR_PSC_OP_PRIVATE         1
#define GHCB_MSR_PSC_OP_SHARED          2
#define GHCB_MSR_PSC_OP_PSMASH          3
#define GHCB_MSR_PSC_OP_UNSMASH         4

/* Hypervisor features; bit 0 says SNP itself is supported. */
#define GHCB_HV_FT_SNP                  (1ULL << 0)

/* PVALIDATE / RMPADJUST status codes returned in EAX. */
#define PVALIDATE_SUCCESS               0
#define PVALIDATE_FAIL_INPUT            1
#define PVALIDATE_FAIL_PERMISSION       2
#define PVALIDATE_FAIL_SIZEMISMATCH     6

/*
 * GHCB page layout.  Only the fields an NAE event needs are named; the valid
 * bitmap at 0x3F0 covers everything below it, one bit per 8 bytes, so a field's
 * bit index is simply its offset divided by 8.
 */
#define GHCB_OFF_RAX                    0x1f8
#define GHCB_OFF_RCX                    0x308
#define GHCB_OFF_RDX                    0x310
#define GHCB_OFF_RBX                    0x318
#define GHCB_OFF_SW_EXITCODE            0x390
#define GHCB_OFF_SW_EXITINFO1           0x398
#define GHCB_OFF_SW_EXITINFO2           0x3a0
#define GHCB_OFF_SW_SCRATCH             0x3a8
#define GHCB_OFF_VALID_BITMAP           0x3f0
#define GHCB_OFF_PROTOCOL_VERSION       0xffa
#define GHCB_OFF_USAGE                  0xffc
#define GHCB_SIZE                       0x1000

#define GHCB_BIT(off)                   ((off) / 8)
#define GHCB_USAGE_STANDARD             0

/* SW_EXITINFO1 encoding for SVM_EXIT_IOIO, as in the SVM intercept. */
#define GHCB_IOIO_TYPE_IN               (1U << 0)
#define GHCB_IOIO_STR                   (1U << 2)
#define GHCB_IOIO_REP                   (1U << 3)
#define GHCB_IOIO_SIZE_8                (1U << 4)
#define GHCB_IOIO_SIZE_16               (1U << 5)
#define GHCB_IOIO_SIZE_32               (1U << 6)
#define GHCB_IOIO_PORT_SHIFT            16

/* SW_EXITINFO2 is a completion status; nonzero means the request failed. */
#define GHCB_EXITINFO2_OK               0
#define GHCB_EXITINFO2_INVALID          1

/*
 * The #VC error code is the GHCB SW_EXITCODE, which for non-automatic exits is
 * the SVM exit code -- so target/i386/svm.h supplies these directly, the same
 * way TDX reuses the VMX exit reasons.
 */

/*
 * RMP-lite modes, selected by x-sev-snp-rmp.
 *
 * LAZY exists because enforcement is all-or-nothing otherwise: guest RAM is
 * private on hardware, so under STRICT a guest that does not yet set the C-bit
 * faults on its first instruction fetch.  That is the truth, and it is what a
 * conformance run wants -- but it leaves no way to adopt the C-bit gradually.
 * Under LAZY a page is shared until the guest asks for it, so polarity is
 * enforced only where the guest has claimed to have done the work.
 */
#define SNP_RMP_OFF                     0
#define SNP_RMP_LAZY                    1
#define SNP_RMP_STRICT                  2

/* Per-page state.  Private-but-unvalidated is the state PVALIDATE clears. */
typedef enum {
    SNP_PAGE_SHARED = 0,
    SNP_PAGE_PRIVATE_UNVALIDATED,
    SNP_PAGE_PRIVATE_VALIDATED,
} SnpPageState;

typedef enum {
    SNP_RMP_OK = 0,
    SNP_RMP_NOT_VALIDATED,   /* private access to an unvalidated page */
    SNP_RMP_MISMATCH,        /* C-bit disagrees with the page's state */
} SnpRmpResult;

/*
 * A private access to a page the guest has not validated is the one RMP
 * failure the architecture routes back to the guest, because only the guest
 * can fix it.  Reported as a nested-page-fault NAE with the page-not-validated
 * sub-case.
 *
 * Note: this constant comes from the GHCB specification's #VC error codes and
 * is the one value here not cross-checked against another source in tree.
 */
#define SNP_EXIT_PAGE_NOT_VALIDATED     (SVM_EXIT_NPF | 0x4)

/*
 * The C-bit mask, or 0 when the emulated SNP guest is off.  Callers strip it
 * from any address taken out of a page-table entry or CR3: the
 * phys_bits == cbitpos + 1 invariant keeps it out of the walker's reserved-bit
 * mask, but it is still inside PG_ADDRESS_MASK and would otherwise be folded
 * into the physical address.
 *
 * Inline, because target/i386/helper.c needs it and is built even when
 * snp.c is not -- a --disable-tcg build would otherwise fail to link.
 */
static inline uint64_t snp_cbit_mask(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);

    return cpu->sev_snp_guest ? (1ULL << cpu->sev_snp_cbitpos) : 0;
}

/* Is page-state enforcement on?  False unless x-sev-snp-rmp says otherwise. */
bool snp_rmp_enabled(CPUX86State *env);

/* Check an access against the page's state; @priv is the PTE's C-bit. */
SnpRmpResult snp_rmp_check(CPUX86State *env, hwaddr gpa, bool priv);

/* Report an RMP failure: #VC for the guest, or terminate for a mismatch. */
void snp_rmp_fault(CPUX86State *env, SnpRmpResult res, hwaddr gpa, bool priv,
                   uintptr_t ra);

/*
 * Create the VM-scoped singleton and register its VMState section.  Called at
 * TCG realize so the section exists before an incoming migration needs it.
 */
void snp_tcg_init(void);

#endif /* I386_TCG_SYSTEM_SNP_H */
