/*
 * Emulated AMD SEV-SNP RMP-lite / C-bit test.
 *
 * Checks that PVALIDATE tracks per-page state, that page-state changes move it,
 * and that the two are ordered the way hardware requires: a page must be
 * claimed as private before it can be validated.
 *
 * Run with x-sev-snp-rmp=1 (lazy): pages are shared until the guest claims
 * them, so this test -- whose page tables carry no C-bit -- runs normally while
 * still exercising the state machine on the one page it does claim.
 *
 * Port I/O is relaxed for the same reason as sev-snp-vc: the first PVALIDATE
 * arms reflection, this test installs no #VC handler, and its own output is
 * port I/O.  Reflection is that test's subject; page state is this one's.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define PVALIDATE_SUCCESS           0
#define PVALIDATE_FAIL_INPUT        1
#define PVALIDATE_FAIL_PERMISSION   2
#define PVALIDATE_FAIL_SIZEMISMATCH 6

#define MSR_AMD64_SEV_ES_GHCB       0xc0010130
#define GHCB_MSR_PSC_REQ            0x014
#define GHCB_MSR_PSC_RESP           0x015
#define PSC_OP_PRIVATE              1
#define PSC_OP_SHARED               2

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static void wrmsr(unsigned int idx, unsigned long val)
{
    __asm__ __volatile__("wrmsr"
                         : : "c"(idx), "a"((unsigned int)val),
                             "d"((unsigned int)(val >> 32)));
}

static unsigned long rdmsr(unsigned int idx)
{
    unsigned int lo, hi;

    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(idx));
    return ((unsigned long)hi << 32) | lo;
}

static void vmgexit(void)
{
    __asm__ __volatile__(".byte 0xf3,0x0f,0x01,0xd9" : : : "memory");
}

/* PVALIDATE: RAX linear address, ECX page size, EDX validate flag. */
static unsigned int pvalidate(unsigned long gva, unsigned int page_size,
                              unsigned int validate, unsigned int *cf)
{
    unsigned int status;
    unsigned long flags;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff\n\t"
                         "pushfq\n\t"
                         "pop %1"
                         : "=a"(status), "=r"(flags)
                         : "a"(gva), "c"(page_size), "d"(validate)
                         : "cc", "memory");
    if (cf) {
        *cf = flags & 1;
    }
    return status;
}

static unsigned long psc(unsigned long gpa, unsigned long op)
{
    wrmsr(MSR_AMD64_SEV_ES_GHCB,
          GHCB_MSR_PSC_REQ | (op << 56) | (gpa & ~0xfffUL));
    vmgexit();
    return rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static unsigned int cbitpos(void)
{
    unsigned int a, b, c, d;

    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(0x8000001F), "c"(0));
    return b & 0x3f;
}

static char scratch[8192] __attribute__((aligned(4096)));

int main(void)
{
    unsigned long cbit = 1UL << cbitpos();
    unsigned long page = ((unsigned long)scratch + 0xfff) & ~0xfffUL;
    unsigned int cf, status;
    unsigned long resp;

    ml_printf("Emulated SEV-SNP RMP-lite test (C-bit %d)\n", (int)cbitpos());

    /* A shared page cannot be validated: the guest must claim it first. */
    status = pvalidate(page, 0, 1, &cf);
    check(status == PVALIDATE_FAIL_PERMISSION,
          "PVALIDATE of a shared page was not refused");

    /*
     * A 2MiB request is refused because RMP page size is not modelled -- but
     * only once it is 2MiB-aligned, since alignment is checked first.  The
     * address need not be mapped: the size check comes before translation.
     */
    status = pvalidate(2 * 1024 * 1024, 1, 1, &cf);
    check(status == PVALIDATE_FAIL_SIZEMISMATCH, "2MiB PVALIDATE not refused");

    /* Misaligned input is refused, at either size. */
    status = pvalidate(page + 1, 0, 1, &cf);
    check(status == PVALIDATE_FAIL_INPUT, "misaligned PVALIDATE not refused");
    status = pvalidate(page, 1, 1, &cf);
    check(status == PVALIDATE_FAIL_INPUT, "2MiB-misaligned not refused");

    /* Claim the page. */
    resp = psc(page, PSC_OP_PRIVATE);
    check((resp & 0xfff) == GHCB_MSR_PSC_RESP, "PSC response code");
    check((resp >> 32) == 0, "PSC to private reported an error");

    /* Private but unvalidated: now PVALIDATE does real work, so CF is clear. */
    status = pvalidate(page, 0, 1, &cf);
    check(status == PVALIDATE_SUCCESS, "PVALIDATE after PSC to private");
    check(cf == 0, "PVALIDATE set CF for a real state change");

    /* And validating twice is again a no-op. */
    status = pvalidate(page, 0, 1, &cf);
    check(cf == 1, "second PVALIDATE did not report no-change");

    /* Clear the GHCB MSR so a later #VC is not read as a nested request. */
    wrmsr(MSR_AMD64_SEV_ES_GHCB, 0);

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP RMP-lite checks passed (cbit 0x%lx)\n", cbit);
    return 0;
}
