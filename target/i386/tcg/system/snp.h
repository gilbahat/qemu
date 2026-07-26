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

#endif /* I386_TCG_SYSTEM_SNP_H */
