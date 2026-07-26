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
 * The #VC error code is the GHCB SW_EXITCODE, which for non-automatic exits is
 * the SVM exit code -- so target/i386/svm.h supplies these directly, the same
 * way TDX reuses the VMX exit reasons.
 */

#endif /* I386_TCG_SYSTEM_SNP_H */
