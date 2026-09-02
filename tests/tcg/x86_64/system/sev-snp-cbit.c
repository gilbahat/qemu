/*
 * Emulated AMD SEV-SNP C-bit test.
 *
 * The other SNP tests all run on boot.S's page tables, which carry no C-bit, so
 * they can only ever reach page-state enforcement from the shared side.  This
 * one builds its own page tables, maps two pages encrypted, and drives the
 * private side of the check:
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

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_PSC_REQ        0x014
#define PSC_OP_PRIVATE          1

#define SNP_EXIT_PAGE_NOT_VALIDATED  0x404

/* Page-table entry bits.  No Global bit: these must respond to invlpg. */
#define PTE_FLAGS               0x067   /* D | A | US | RW | P        */
#define PDE_LARGE_FLAGS         0x0e7   /* PS | D | A | US | RW | P   */
#define PDE_TABLE_FLAGS         0x007   /* US | RW | P                */

#define PAGE_SIZE               4096UL
#define LARGE_PAGE_SIZE         (2UL * 1024 * 1024)

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

/*
 * Read once and cached, because every CPUID reflects as #VC from the first
 * PVALIDATE onwards and map_private() is called well after that.  A real
 * guest caches it for the same reason: the C-bit is what it needs in order to
 * reach a GHCB, so it cannot afford to need a GHCB to ask for it.
 */
static unsigned long cbit_cached;

static unsigned long cbit(void)
{
    unsigned int a, b, c, d;

    if (cbit_cached) {
        return cbit_cached;
    }
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(0x8000001F), "c"(0));
    cbit_cached = 1UL << (b & 0x3f);
    return cbit_cached;
}

/* --- page tables ---------------------------------------------------------- */

/*
 * A fresh identity map of the low 4GiB with 2MiB pages, except for the one
 * 2MiB region holding the pages under test, which is split into 4KiB entries so
 * the C-bit can be set per page.  Everything here lives in .bss and so stays
 * shared, which is what lets the walk itself keep working.
 */
static unsigned long pml4[512] __attribute__((aligned(4096)));
static unsigned long pdp[512] __attribute__((aligned(4096)));
static unsigned long pd[4][512] __attribute__((aligned(4096)));
static unsigned long pt[512] __attribute__((aligned(4096)));

static unsigned char arena[4 * PAGE_SIZE] __attribute__((aligned(4096)));
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
            pd[g][i] = (g << 30) | (i << 21) | PDE_LARGE_FLAGS;
        }
        pdp[g] = (unsigned long)&pd[g][0] | PDE_TABLE_FLAGS;
    }
    pml4[0] = (unsigned long)pdp | PDE_TABLE_FLAGS;

    /* Split the region holding the test pages down to 4KiB granularity. */
    split_base = split_addr & ~(LARGE_PAGE_SIZE - 1);
    for (i = 0; i < 512; i++) {
        pt[i] = (split_base + i * PAGE_SIZE) | PTE_FLAGS;
    }
    pd[split_base >> 30][(split_base >> 21) & 0x1ff] =
        (unsigned long)pt | PDE_TABLE_FLAGS;
}

static unsigned long *pte_for(unsigned long va)
{
    return &pt[(va - split_base) / PAGE_SIZE];
}

static void load_cr3(void)
{
    __asm__ __volatile__("mov %0, %%cr3"
                         : : "r"((unsigned long)pml4) : "memory");
}

static void invlpg(unsigned long va)
{
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

/* Map a page encrypted, and drop any translation cached for it. */
static void map_private(unsigned long va)
{
    *pte_for(va) |= cbit();
    invlpg(va);
}

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
    unsigned long page_b = page_a + PAGE_SIZE;
    volatile unsigned long *a = (volatile unsigned long *)page_a;
    volatile unsigned long *b = (volatile unsigned long *)page_b;

    ml_printf("Emulated SEV-SNP C-bit test\n");

    idt_init();

    (void)cbit();               /* before the first PVALIDATE arms reflection */
    build_tables(page_a);
    load_cr3();
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
    map_private(page_a);
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
    map_private(page_b);

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
