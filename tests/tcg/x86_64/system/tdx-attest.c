/*
 * Emulated Intel TDX attestation-flow test.
 *
 * Nothing here checks that a report is trustworthy -- it cannot be, there is no
 * key, and the emulation refuses to pretend otherwise.  What is checkable is
 * the flow a guest has to get right, and that is what this drives:
 *
 *   - the report is structurally what the ABI says, and its operands' alignment
 *     rules are enforced;
 *   - REPORTDATA the guest supplies comes back in the report;
 *   - MRTD is a real measurement of the launch image rather than zeros;
 *   - extending an RTMR changes the report, is a function of the data extended
 *     (same data twice gives the same register, different data does not), and
 *     leaves the other registers alone;
 *   - the MAC is the fixed not-real marker, so a guest cannot mistake this for
 *     evidence, and quoting is refused outright.
 *
 * The last of those is the one worth keeping: it locks in that the emulation
 * never produces something that could be passed off as genuine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define TDX_SUCCESS                 0x0000000000000000UL
#define TDX_OPERAND_INVALID         0xC000010000000000UL

#define TDG_VP_VMCALL               0UL
#define TDG_MR_RTMR_EXTEND          2UL
#define TDG_MR_REPORT               4UL
#define TDVMCALL_GET_QUOTE          0x10002UL
#define TDVMCALL_SUCCESS            0UL

#define QUOTE_HDR_LEN               24
#define GET_QUOTE_SUCCESS           0UL
#define GET_QUOTE_IN_FLIGHT         0xffffffffffffffffUL
#define QUOTE_V4                    4
#define TEE_TYPE_TDX                0x81
#define FAKE_SIG "QEMU-TCG-EMULATED-TDX-QUOTE-NOT-REAL-EVIDENCE!!!"

#define MEASUREMENT_LEN             48
#define RTMR_COUNT                  4
#define REPORTDATA_LEN              64
#define REPORT_LEN                  1024

/* TDREPORT offsets, from the TDX module ABI. */
#define OFF_REPORTTYPE              0
#define OFF_CPUSVN                  16
#define OFF_TEE_TCB_INFO_HASH       32
#define OFF_TEE_INFO_HASH           80
#define OFF_REPORTDATA              128
#define OFF_MAC                     224
#define OFF_TDINFO                  512
#define OFF_MRTD                    (OFF_TDINFO + 16)
#define OFF_RTMR0                   (OFF_TDINFO + 16 + 4 * MEASUREMENT_LEN)

#define FAKE_MAC                    "QEMU-TCG-EMULATED-TDX-NOT-REAL!!"

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static unsigned long tdcall2(unsigned long leaf, unsigned long rcx,
                             unsigned long rdx)
{
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status)
                         : "a"(leaf), "c"(rcx), "d"(rdx)
                         : "r8", "r9", "r10", "r11", "memory");
    return status;
}

/* TDG.MR.REPORT: RCX report buffer, RDX REPORTDATA, R8 sub-type. */
static unsigned long mr_report(void *report, const void *reportdata)
{
    register unsigned long r8 __asm__("r8") = 0;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status), "+r"(r8)
                         : "a"(TDG_MR_REPORT), "c"((unsigned long)report),
                           "d"((unsigned long)reportdata)
                         : "r9", "r10", "r11", "memory");
    return status;
}

/* TDG.MR.RTMR.EXTEND: RCX 64-byte data, RDX register index. */
static unsigned long rtmr_extend(const void *data, unsigned long index)
{
    return tdcall2(TDG_MR_RTMR_EXTEND, (unsigned long)data, index);
}

static unsigned long get_quote(unsigned long gpa, unsigned long size)
{
    register unsigned long r10 __asm__("r10") = 0;
    register unsigned long r11 __asm__("r11") = TDVMCALL_GET_QUOTE;
    register unsigned long r12 __asm__("r12") = gpa;
    register unsigned long r13 __asm__("r13") = size;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status), "+r"(r10), "+r"(r11), "+r"(r12),
                           "+r"(r13)
                         : "a"(TDG_VP_VMCALL), "c"(0xfc00)
                         : "memory");
    /* R10 carries the TDVMCALL-level status. */
    return r10;
}

/* TDVMCALL<MapGPA>, to convert the quote buffer to shared. */
static unsigned long map_gpa(unsigned long gpa_with_alias, unsigned long size)
{
    register unsigned long r10 __asm__("r10") = 0;
    register unsigned long r11 __asm__("r11") = 0x10001UL;
    register unsigned long r12 __asm__("r12") = gpa_with_alias;
    register unsigned long r13 __asm__("r13") = size;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status), "+r"(r10), "+r"(r11), "+r"(r12),
                           "+r"(r13)
                         : "a"(TDG_VP_VMCALL), "c"(0xfc00)
                         : "memory");
    return r10;
}

/* GPAW comes from TDG.VP.INFO RCX[5:0]; the SHARED alias is bit GPAW-1. */
static unsigned long shared_bit(void)
{
    unsigned long gpaw;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=c"(gpaw)
                         : "a"(1UL)
                         : "rdx", "r8", "r9", "r10", "r11", "memory");
    return 1UL << ((gpaw & 0x3f) - 1);
}

static int mem_eq(const void *a, const void *b, unsigned long n)
{
    const unsigned char *p = a, *q = b;
    unsigned long i;

    for (i = 0; i < n; i++) {
        if (p[i] != q[i]) {
            return 0;
        }
    }
    return 1;
}

static int is_zero(const void *a, unsigned long n)
{
    const unsigned char *p = a;
    unsigned long i;

    for (i = 0; i < n; i++) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

static void fill(void *a, unsigned long n, unsigned char seed)
{
    unsigned char *p = a;
    unsigned long i;

    for (i = 0; i < n; i++) {
        p[i] = (unsigned char)(seed + i);
    }
}

static void copy(void *d, const void *s, unsigned long n)
{
    unsigned char *p = d;
    const unsigned char *q = s;
    unsigned long i;

    for (i = 0; i < n; i++) {
        p[i] = q[i];
    }
}

static unsigned char report[REPORT_LEN] __attribute__((aligned(1024)));
static unsigned char report2[REPORT_LEN] __attribute__((aligned(1024)));
static unsigned char reportdata[REPORTDATA_LEN] __attribute__((aligned(64)));
static unsigned char extdata[64] __attribute__((aligned(64)));
static unsigned char saved_rtmr[RTMR_COUNT][MEASUREMENT_LEN];
static unsigned char mrtd[MEASUREMENT_LEN];
static unsigned char qbuf[8192] __attribute__((aligned(4096)));

/*
 * Page tables, needed only for the quoting part -- and that is the lesson.  The
 * quote buffer has to be shared, and a shared page has to be reached through
 * the SHARED alias, so this is the first thing in a TD needing a page-table
 * entry it can change at runtime.  boot.S's tables are fixed, so build our own.
 */
static unsigned long pml4[512] __attribute__((aligned(4096)));
static unsigned long pdp[512] __attribute__((aligned(4096)));
static unsigned long pd[4][512] __attribute__((aligned(4096)));
static unsigned long pt[512] __attribute__((aligned(4096)));
static unsigned long split_base;

static void build_tables(unsigned long split_addr)
{
    unsigned long g, i;

    for (i = 0; i < 512; i++) {
        pml4[i] = 0;
        pdp[i] = 0;
    }
    for (g = 0; g < 4; g++) {
        for (i = 0; i < 512; i++) {
            pd[g][i] = (g << 30) | (i << 21) | 0xe7;
        }
        pdp[g] = (unsigned long)&pd[g][0] | 7;
    }
    pml4[0] = (unsigned long)pdp | 7;

    split_base = split_addr & ~0x1fffffUL;
    for (i = 0; i < 512; i++) {
        pt[i] = (split_base + i * 4096) | 0x67;
    }
    pd[split_base >> 30][(split_base >> 21) & 0x1ff] = (unsigned long)pt | 7;

    __asm__ __volatile__("mov %0, %%cr3"
                         : : "r"((unsigned long)pml4) : "memory");
}

static void share_page(unsigned long va, unsigned long bit)
{
    map_gpa(va | bit, 4096);
    pt[(va - split_base) / 4096] |= bit;
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

static const unsigned char *rtmr_of(const unsigned char *r, int i)
{
    return r + OFF_RTMR0 + i * MEASUREMENT_LEN;
}

int main(void)
{
    unsigned long status;
    int i;

    ml_printf("Emulated TDX attestation-flow test\n");

    build_tables((unsigned long)qbuf);

    /* --- the report, and its operand rules ------------------------------- */

    fill(reportdata, sizeof(reportdata), 0x40);
    check(mr_report(report, reportdata) == TDX_SUCCESS, "TDG.MR.REPORT failed");

    /* REPORTDATA must come back verbatim: it is the guest's nonce. */
    check(mem_eq(report + OFF_REPORTDATA, reportdata, REPORTDATA_LEN),
          "REPORTDATA was not reflected into the report");

    /* A misaligned report buffer must be refused, not quietly accepted. */
    status = mr_report(report + 8, reportdata);
    check(status != TDX_SUCCESS, "a misaligned report buffer was accepted");
    status = mr_report(report, reportdata + 8);
    check(status != TDX_SUCCESS, "misaligned REPORTDATA was accepted");

    /* --- the measurement of the launch image ----------------------------- */

    copy(mrtd, report + OFF_MRTD, MEASUREMENT_LEN);
    check(!is_zero(mrtd, MEASUREMENT_LEN),
          "MRTD is zero: the launch image was never measured");
    ml_printf("MRTD[0..7] = %x %x %x %x %x %x %x %x\n",
              mrtd[0], mrtd[1], mrtd[2], mrtd[3],
              mrtd[4], mrtd[5], mrtd[6], mrtd[7]);

    /* The hashes over TEE_TCB_INFO and TD_INFO are computed, not stubbed. */
    check(!is_zero(report + OFF_TEE_TCB_INFO_HASH, MEASUREMENT_LEN),
          "TEE_TCB_INFO_HASH is zero");
    check(!is_zero(report + OFF_TEE_INFO_HASH, MEASUREMENT_LEN),
          "TEE_INFO_HASH is zero");

    /* --- nothing here may look like evidence ----------------------------- */

    check(mem_eq(report + OFF_MAC, FAKE_MAC, 32),
          "the report MAC is not the not-real marker");

    /* --- quoting ---------------------------------------------------------- */

    {
        unsigned long sb = shared_bit();
        unsigned long buf = (unsigned long)qbuf;
        /*
         * volatile: the quoting service writes these behind the guest's back,
         * so the poll below has to re-read them rather than cache the first
         * value it saw.
         */
        volatile unsigned long *hdr = (volatile unsigned long *)buf;
        /* volatile for the same reason: written by the service, not by us. */
        volatile unsigned int *lens = (volatile unsigned int *)(buf + 16);
        unsigned char *qdata = (unsigned char *)(buf + QUOTE_HDR_LEN);
        unsigned long spins;

        /* A private buffer must be refused: the service cannot reach it. */
        check(get_quote(buf, sizeof(qbuf)) != TDVMCALL_SUCCESS,
              "GetQuote accepted a buffer that is not in the SHARED alias");

        /* Convert it *and* map it through the alias -- both are required. */
        share_page(buf, sb);
        share_page(buf + 4096, sb);

        /* An unaligned buffer is refused. */
        check(get_quote((buf + 8) | sb, sizeof(qbuf)) != TDVMCALL_SUCCESS,
              "GetQuote accepted a misaligned buffer");

        /* Now a well-formed request. */
        hdr[0] = 1;                        /* version   */
        hdr[1] = 0;                        /* status    */
        lens[0] = REPORT_LEN;              /* in_len    */
        lens[1] = 0;                       /* out_len   */
        copy(qdata, report, REPORT_LEN);

        check(get_quote(buf | sb, sizeof(qbuf)) == TDVMCALL_SUCCESS,
              "GetQuote refused a well-formed request");

        /* Asynchronous: the guest waits for the status to change. */
        check(hdr[1] == GET_QUOTE_IN_FLIGHT,
              "GetQuote did not report the request as in flight");
        for (spins = 0; hdr[1] == GET_QUOTE_IN_FLIGHT; spins++) {
            if (spins > 400000000UL) {
                break;
            }
        }
        check(hdr[1] == GET_QUOTE_SUCCESS, "the quote never completed");
        check(lens[1] > QUOTE_HDR_LEN, "the quote has no length");

        /* A structurally valid Quote v4 for TDX. */
        check(qdata[0] == QUOTE_V4 && qdata[1] == 0, "quote version is not 4");
        check(qdata[4] == TEE_TYPE_TDX, "quote tee_type is not TDX");

        /*
         * It must carry the measurements and the nonce from the report that was
         * submitted -- otherwise it is answering about something else.
         */
        check(mem_eq(qdata + 48 + 136, mrtd, MEASUREMENT_LEN),
              "the quote does not carry the MRTD from the report");
        check(mem_eq(qdata + 48 + 520, reportdata, REPORTDATA_LEN),
              "the quote does not carry the REPORTDATA from the report");

        /* And it must be unmistakably not evidence. */
        check(mem_eq(qdata + 48 + 584 + 4, FAKE_SIG, 40),
              "the quote signature is not the not-real marker");
        ml_printf("quote: %d bytes, version %d, tee 0x%x\n",
                  (int)lens[1], (int)qdata[0], (int)qdata[4]);
    }

    /* --- the RTMRs -------------------------------------------------------- */

    for (i = 0; i < RTMR_COUNT; i++) {
        copy(saved_rtmr[i], rtmr_of(report, i), MEASUREMENT_LEN);
    }

    /* An out-of-range index must be refused. */
    fill(extdata, sizeof(extdata), 0x10);
    check(rtmr_extend(extdata, RTMR_COUNT) != TDX_SUCCESS,
          "an out-of-range RTMR index was accepted");
    check(rtmr_extend(extdata + 8, 0) != TDX_SUCCESS,
          "misaligned RTMR data was accepted");

    /* Extending RTMR[1] must change it, and only it. */
    check(rtmr_extend(extdata, 1) == TDX_SUCCESS, "RTMR extend failed");
    check(mr_report(report, reportdata) == TDX_SUCCESS, "second report failed");
    check(!mem_eq(rtmr_of(report, 1), saved_rtmr[1], MEASUREMENT_LEN),
          "extending RTMR[1] did not change it");
    check(mem_eq(rtmr_of(report, 0), saved_rtmr[0], MEASUREMENT_LEN),
          "extending RTMR[1] disturbed RTMR[0]");
    check(mem_eq(rtmr_of(report, 2), saved_rtmr[2], MEASUREMENT_LEN),
          "extending RTMR[1] disturbed RTMR[2]");
    check(mem_eq(mrtd, report + OFF_MRTD, MEASUREMENT_LEN),
          "extending an RTMR changed MRTD");

    /*
     * The register has to be a function of what was extended, and of nothing
     * else.  Extend the same bytes into RTMR[2], which is still at its initial
     * value like RTMR[1] was, and the two must agree.
     */
    check(rtmr_extend(extdata, 2) == TDX_SUCCESS, "RTMR[2] extend failed");
    check(mr_report(report, reportdata) == TDX_SUCCESS, "third report failed");
    check(mem_eq(rtmr_of(report, 1), rtmr_of(report, 2), MEASUREMENT_LEN),
          "the same data extended from the same state gave different results");

    /* And different data must give a different register. */
    fill(extdata, sizeof(extdata), 0x99);
    check(rtmr_extend(extdata, 3) == TDX_SUCCESS, "RTMR[3] extend failed");
    check(mr_report(report2, reportdata) == TDX_SUCCESS,
          "fourth report failed");
    check(!mem_eq(rtmr_of(report2, 3), rtmr_of(report2, 1), MEASUREMENT_LEN),
          "different data extended from the same state gave the same result");

    /* A report is otherwise stable: nothing varies run to run within a boot. */
    check(mr_report(report, reportdata) == TDX_SUCCESS, "fifth report failed");
    check(mem_eq(report, report2, REPORT_LEN),
          "two reports with the same inputs differ");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All TDX attestation-flow checks passed\n");
    return 0;
}
