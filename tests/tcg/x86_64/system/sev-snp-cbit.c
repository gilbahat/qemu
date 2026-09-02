/*
 * Emulated AMD SEV-SNP C-bit test.
 *
 * The other SNP tests build their own tables (snp-ptes.h) only so far as they
 * need one validatable page.  This one is about what the C-bit does once it is
 * set, so it maps two pages encrypted and drives the private side of the
 * check:
 *
 *   - a page it has claimed and validated is usable with C=1;
 *   - a page it has claimed but *not* validated raises #VC on first touch, and
 *     the handler can PVALIDATE it and let the access retry -- which is how a
 *     real guest validates memory on demand.
 *
 * The second case also checks that validation needs no TLB flush.  If it did,
 * and the emulation skipped it, the retried access would fault forever.
 *
 * Run in lazy mode (x-sev-snp-rmp=1): pages start shared, so the test's own
 * code, stack and page tables keep working with C=0 while the two pages under
 * test are moved to private.  Port I/O is relaxed, as in sev-snp-rmp -- the
 * first PVALIDATE arms reflection and this test's #VC handler is for page
 * faults, not for servicing I/O.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#include "snp-ptes.h"

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_PSC_REQ        0x014
#define PSC_OP_PRIVATE          1

#define SNP_EXIT_PAGE_NOT_VALIDATED  0x404


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

static unsigned int pvalidate(unsigned long gva, unsigned int validate)
{
    unsigned int status;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff"
                         : "=a"(status)
                         : "a"(gva), "c"(0), "d"(validate)
                         : "cc", "memory");
    return status;
}

/* Move a page to guest-private.  It comes back unvalidated, as on hardware. */
static unsigned long psc_private(unsigned long gpa)
{
    wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_PSC_REQ |
          ((unsigned long)PSC_OP_PRIVATE << 52) | (gpa & ~0xfffUL));
    vmgexit();
    return rdmsr(MSR_AMD64_SEV_ES_GHCB) >> 32;
}

static unsigned char arena[4 * SNP_PAGE_SIZE] __attribute__((aligned(4096)));

/* --- #VC handler --------------------------------------------------------- */

struct idt_entry {
    unsigned short offset_lo;
    unsigned short selector;
    unsigned char  ist;
    unsigned char  type_attr;
    unsigned short offset_mid;
    unsigned int   offset_hi;
    unsigned int   zero;
} __attribute__((packed));

struct idt_ptr {
    unsigned short limit;
    unsigned long  base;
} __attribute__((packed));

static struct idt_entry idt[32];
extern void vc_entry(void);

static volatile unsigned long vc_count;
static volatile unsigned long vc_code;
static volatile unsigned long vc_expect_page;

/*
 * frame[0] is the #VC error code, which is the GHCB SW_EXITCODE; frame[1] is
 * RIP.  #VC is a fault, so RIP already points at the faulting instruction and
 * iret retries it -- which is exactly what is wanted here: validate the page
 * and let the access complete.
 *
 * A real guest would have to work out which page faulted, since the error code
 * carries only the exit reason.  This test knows, so it says so in advance.
 */
void vc_handle(unsigned long *frame);
void vc_handle(unsigned long *frame)
{
    vc_count++;
    vc_code = frame[0];

    if (frame[0] == SNP_EXIT_PAGE_NOT_VALIDATED && vc_expect_page) {
        pvalidate(vc_expect_page, 1);
        vc_expect_page = 0;
        return;
    }

    /*
     * Nothing to fix, so retrying would loop forever.  Report and step over a
     * single byte; the test will fail on the counters either way.
     */
    failures++;
    ml_printf("FAIL: unexpected #VC, error code 0x%lx\n", frame[0]);
    frame[1] += 1;
}

__asm__(".globl vc_entry\n"
        "vc_entry:\n"
        "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n"
        "  push %rdi\n  push %r8\n   push %r9\n   push %r10\n"
        "  push %r11\n  sub $8, %rsp\n"
        "  lea 80(%rsp), %rdi\n"
        "  call vc_handle\n"
        "  add $8, %rsp\n"
        "  pop %r11\n  pop %r10\n  pop %r9\n   pop %r8\n"
        "  pop %rdi\n  pop %rsi\n  pop %rdx\n  pop %rcx\n"
        "  pop %rax\n"
        "  add $8, %rsp\n"
        "  iretq\n");

static void idt_init(void)
{
    unsigned long addr = (unsigned long)vc_entry;
    struct idt_ptr ptr = { .limit = sizeof(idt) - 1,
                           .base = (unsigned long)idt };
    unsigned short cs;

    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs));
    idt[29].offset_lo  = addr & 0xffff;
    idt[29].selector   = cs;
    idt[29].type_attr  = 0x8e;
    idt[29].offset_mid = (addr >> 16) & 0xffff;
    idt[29].offset_hi  = addr >> 32;
    __asm__ __volatile__("lidt %0" : : "m"(ptr));
}

int main(void)
{
    unsigned long page_a = (unsigned long)arena;
    unsigned long page_b = page_a + SNP_PAGE_SIZE;
    volatile unsigned long *a = (volatile unsigned long *)page_a;
    volatile unsigned long *b = (volatile unsigned long *)page_b;

    ml_printf("Emulated SEV-SNP C-bit test\n");

    idt_init();

    snp_tables_init(page_a);
    ml_printf("running on self-built page tables\n");

    /* A shared page must still be reachable with C=0 -- the baseline. */
    *a = 0x1111;
    check(*a == 0x1111, "shared page not usable with C=0");
    check(vc_count == 0, "a shared C=0 access raised #VC");

    /*
     * Page A: claim it, map it encrypted, then validate it.  This is the
     * ordering a guest is supposed to follow, and it must just work.
     *
     * The mapping has to come first.  PVALIDATE takes a linear address and
     * the walk decides which page it means, so on a mapping with C=0 it does
     * not return a status at all -- it raises #PF with the reserved bit set.
     * Linux sets the C-bit in the PTE before validating for the same reason.
     */
    check(psc_private(page_a) == 0, "page-state change to private failed");
    snp_map_private(page_a);
    check(pvalidate(page_a, 1) == 0, "PVALIDATE of a claimed page failed");

    *a = 0x2222;
    check(*a == 0x2222, "validated private page not usable with C=1");
    check(vc_count == 0, "a validated private access raised #VC");

    /*
     * Page B: claim it but skip the validation, then map it encrypted.  The
     * first touch must raise #VC, and the handler's PVALIDATE must make the
     * retried access succeed -- with no flush, since the faulting fill never
     * cached anything.
     */
    check(psc_private(page_b) == 0, "page-state change to private failed");
    snp_map_private(page_b);

    vc_expect_page = page_b;
    *b = 0x3333;

    check(vc_count == 1, "unvalidated access did not raise exactly one #VC");
    check(vc_code == SNP_EXIT_PAGE_NOT_VALIDATED, "#VC error code");
    check(vc_expect_page == 0, "the handler did not run");
    check(*b == 0x3333, "page unusable after the handler validated it");

    /* And it stays validated: no further faults. */
    *b = 0x4444;
    check(*b == 0x4444, "validated page faulted on a second access");
    check(vc_count == 1, "a validated page faulted again");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP C-bit checks passed (1 #VC serviced)\n");
    return 0;
}
