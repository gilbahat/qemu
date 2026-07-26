/*
 * Emulated AMD SEV-SNP GHCB MSR protocol test.
 *
 * Drives each request the way a guest does before it owns a GHCB page: write
 * the request into MSR_AMD64_SEV_ES_GHCB, execute VMGEXIT, read the response
 * back out of the same register.
 *
 * Where a response can be cross-checked against another source it is -- the
 * C-bit against CPUID.0x8000001F, and the CPUID request against the native
 * instruction -- so a reply that is merely well-formed does not pass.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130

#define GHCB_MSR_SEV_INFO_RESP  0x001
#define GHCB_MSR_SEV_INFO_REQ   0x002
#define GHCB_MSR_CPUID_REQ      0x004
#define GHCB_MSR_CPUID_RESP     0x005
#define GHCB_MSR_PREF_GPA_REQ   0x010
#define GHCB_MSR_PREF_GPA_RESP  0x011
#define GHCB_MSR_REG_GPA_REQ    0x012
#define GHCB_MSR_REG_GPA_RESP   0x013
#define GHCB_MSR_PSC_REQ        0x014
#define GHCB_MSR_PSC_RESP       0x015
#define GHCB_MSR_HV_FT_REQ      0x080
#define GHCB_MSR_HV_FT_RESP     0x081

#define INFO(v)                 ((v) & 0xfff)

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
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

/* VMGEXIT, F3 0F 01 D9 -- spelled out so no assembler support is needed. */
static void vmgexit(void)
{
    __asm__ __volatile__(".byte 0xf3,0x0f,0x01,0xd9" : : : "memory");
}

/* One MSR-protocol transaction: write the request, VMGEXIT, read the reply. */
static unsigned long ghcb_msr_call(unsigned long req)
{
    wrmsr(MSR_AMD64_SEV_ES_GHCB, req);
    vmgexit();
    return rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static void native_cpuid(unsigned int leaf, unsigned int *a, unsigned int *b,
                         unsigned int *c, unsigned int *d)
{
    unsigned int ra = leaf, rb, rc = 0, rd;

    __asm__ __volatile__("cpuid"
                         : "+a"(ra), "=b"(rb), "+c"(rc), "=d"(rd));
    *a = ra; *b = rb; *c = rc; *d = rd;
}

int main(void)
{
    unsigned long resp;
    unsigned int a, b, c, d;
    unsigned int cbitpos, reported;
    static char ghcb_page[8192] __attribute__((aligned(4096)));
    unsigned long ghcb_gpa = (unsigned long)ghcb_page;
    unsigned int reg;

    ml_printf("Emulated SEV-SNP GHCB MSR protocol test\n");

    /* SEV information: protocol range, and the C-bit position. */
    resp = ghcb_msr_call(GHCB_MSR_SEV_INFO_REQ);
    check(INFO(resp) == GHCB_MSR_SEV_INFO_RESP, "SEV info response code");
    check(((resp >> 48) & 0xffff) >= ((resp >> 32) & 0xffff),
          "SEV info: max protocol < min protocol");

    reported = (resp >> 24) & 0xff;
    native_cpuid(0x8000001F, &a, &b, &c, &d);
    cbitpos = b & 0x3f;
    check(reported == cbitpos,
          "SEV info C-bit disagrees with CPUID.0x8000001F");

    /* CPUID request: each register, cross-checked against the instruction. */
    native_cpuid(1, &a, &b, &c, &d);
    for (reg = 0; reg < 4; reg++) {
        unsigned int want = (reg == 0) ? a : (reg == 1) ? b :
                            (reg == 2) ? c : d;

        resp = ghcb_msr_call(GHCB_MSR_CPUID_REQ |
                             ((unsigned long)1 << 32) |
                             ((unsigned long)reg << 30));
        check(INFO(resp) == GHCB_MSR_CPUID_RESP, "CPUID response code");
        check(((resp >> 30) & 3) == reg, "CPUID response echoed wrong register");
        check((unsigned int)(resp >> 32) == want,
              "CPUID via GHCB MSR != native CPUID");
    }

    /* Preferred GPA: we have no preference. */
    resp = ghcb_msr_call(GHCB_MSR_PREF_GPA_REQ);
    check(INFO(resp) == GHCB_MSR_PREF_GPA_RESP, "preferred GPA response code");

    /* Register a GHCB page and check the address is echoed back. */
    resp = ghcb_msr_call(GHCB_MSR_REG_GPA_REQ | ghcb_gpa);
    check(INFO(resp) == GHCB_MSR_REG_GPA_RESP, "register GPA response code");
    check((resp & ~0xfffUL) == ghcb_gpa, "register GPA did not echo the page");

    /* Page state change: a defined operation succeeds... */
    resp = ghcb_msr_call(GHCB_MSR_PSC_REQ | ((unsigned long)2 << 56) |
                         ghcb_gpa);
    check(INFO(resp) == GHCB_MSR_PSC_RESP, "PSC response code");
    check((resp >> 32) == 0, "PSC to shared reported an error");

    /* ...and an undefined one does not. */
    resp = ghcb_msr_call(GHCB_MSR_PSC_REQ | ((unsigned long)9 << 56) |
                         ghcb_gpa);
    check(INFO(resp) == GHCB_MSR_PSC_RESP, "PSC response code (bad op)");
    check((resp >> 32) != 0, "PSC accepted an undefined operation");

    /* Hypervisor features: SNP itself must be advertised. */
    resp = ghcb_msr_call(GHCB_MSR_HV_FT_REQ);
    check(INFO(resp) == GHCB_MSR_HV_FT_RESP, "HV features response code");
    check((resp >> 12) & 1, "HV features: SNP bit not set");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP GHCB MSR protocol checks passed\n");
    return 0;
}
