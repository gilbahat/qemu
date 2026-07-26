/*
 * Emulated AMD SEV-SNP guest interface (TCG) regression test.
 *
 * Runs with -cpu max,x-sev-snp-guest=on and checks what a guest uses to
 * discover it is running under SNP: the CPUID feature leaf, the C-bit position
 * it reports, and the SEV_STATUS and GHCB MSRs.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define CPUID_SEV               (1U << 1)
#define CPUID_SEV_ES            (1U << 3)
#define CPUID_SEV_SNP           (1U << 4)

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define MSR_AMD64_SEV           0xc0010131
#define SEV_ENABLED             (1ULL << 0)
#define SEV_ES_ENABLED          (1ULL << 1)
#define SEV_SNP_ENABLED         (1ULL << 2)

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static void native_cpuid(unsigned int leaf, unsigned int *a, unsigned int *b,
                         unsigned int *c, unsigned int *d)
{
    unsigned int ra = leaf, rb, rc = 0, rd;

    __asm__ __volatile__("cpuid"
                         : "+a"(ra), "=b"(rb), "+c"(rc), "=d"(rd));
    *a = ra; *b = rb; *c = rc; *d = rd;
}

static unsigned long rdmsr(unsigned int idx)
{
    unsigned int lo, hi;

    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(idx));
    return ((unsigned long)hi << 32) | lo;
}

static void wrmsr(unsigned int idx, unsigned long val)
{
    __asm__ __volatile__("wrmsr"
                         : : "c"(idx), "a"((unsigned int)val),
                             "d"((unsigned int)(val >> 32)));
}

int main(void)
{
    unsigned int a, b, c, d;
    unsigned int cbitpos, reduction, phys_bits;
    unsigned long status;

    ml_printf("Emulated SEV-SNP guest interface test\n");

    /* The leaf must be reachable: it sits above the default max extended leaf. */
    native_cpuid(0x80000000, &a, &b, &c, &d);
    check(a >= 0x8000001F, "CPUID.0x80000000 max extended leaf < 0x8000001F");

    native_cpuid(0x8000001F, &a, &b, &c, &d);
    check((a & CPUID_SEV) != 0, "CPUID.0x8000001F EAX: SEV not reported");
    check((a & CPUID_SEV_ES) != 0, "CPUID.0x8000001F EAX: SEV-ES not reported");
    check((a & CPUID_SEV_SNP) != 0, "CPUID.0x8000001F EAX: SEV-SNP not reported");

    cbitpos = b & 0x3f;
    reduction = (b >> 6) & 0x3f;
    check(cbitpos >= 32 && cbitpos <= 51, "C-bit position out of range");
    check(reduction == 1, "reported physical address reduction != 1 bit");

    /*
     * The C-bit has to be the topmost physical address bit, or it would alias
     * a real one.  CPUID.0x80000008:EAX[7:0] carries the width.
     */
    native_cpuid(0x80000008, &a, &b, &c, &d);
    phys_bits = a & 0xff;
    check(phys_bits == cbitpos + 1, "phys_bits != cbitpos + 1");

    status = rdmsr(MSR_AMD64_SEV);
    check((status & SEV_ENABLED) != 0, "SEV_STATUS: SEV bit clear");
    check((status & SEV_ES_ENABLED) != 0, "SEV_STATUS: SEV-ES bit clear");
    check((status & SEV_SNP_ENABLED) != 0, "SEV_STATUS: SEV-SNP bit clear");

    /* The GHCB MSR is the guest's own scratch register; it must round-trip. */
    wrmsr(MSR_AMD64_SEV_ES_GHCB, 0x1234abcd000ULL);
    check(rdmsr(MSR_AMD64_SEV_ES_GHCB) == 0x1234abcd000ULL,
          "GHCB MSR did not round-trip");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP interface checks passed\n");
    return 0;
}
