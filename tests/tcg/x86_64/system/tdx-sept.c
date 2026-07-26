/*
 * Emulated Intel TDX page-state test.
 *
 * A TD's memory is private and, until it says otherwise, unaccepted.  The guest
 * accepts pages with TDG.MEM.PAGE.ACCEPT and converts them between private and
 * shared with TDVMCALL<MapGPA>, and the alias it uses in its page tables has to
 * agree with the state it has asked for.  This drives all of that.
 *
 * The mapping half is the part that could not be tested before: with phys_bits
 * pinned below the SHARED bit, a page table carrying that bit simply faulted,
 * so no TD could reach shared memory at all.  Here the test builds its own page
 * tables and maps the same page both ways.
 *
 * Run in lazy mode, so pages start accepted and the test's own memory keeps
 * working, with the pages under test converted explicitly.  I/O is relaxed: the
 * first TDCALL arms #VE reflection and this handler is for EPT violations.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define TDX_SUCCESS                 0x0000000000000000UL
#define TDX_PAGE_ALREADY_ACCEPTED   0x00000B0A00000000UL
#define TDX_PAGE_ATTR_CONFLICT      0xC0000B0900000000UL
#define TDX_PAGE_SIZE_MISMATCH      0xC0000B0B00000000UL
/* A failing TDCALL ORs in the operand that was at fault. */
#define TDX_OPERAND_ID_RCX          0x1UL

#define TDG_VP_INFO                 1UL
#define TDG_VP_VEINFO_GET           3UL
#define TDG_MEM_PAGE_ACCEPT         6UL
#define TDG_VP_VMCALL               0UL

#define TDVMCALL_MAP_GPA            0x10001UL
#define TDVMCALL_SUCCESS            0UL

#define EXIT_REASON_EPT_VIOLATION   48

#define PTE_FLAGS                   0x067
#define PDE_LARGE_FLAGS             0x0e7
#define PDE_TABLE_FLAGS             0x007
#define PAGE_SIZE                   4096UL
#define LARGE_PAGE_SIZE             (2UL * 1024 * 1024)

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

/* TDCALL, 66 0F 01 CC.  Leaf in RAX; returns a status in RAX. */
static unsigned long tdcall(unsigned long leaf, unsigned long rcx,
                            unsigned long rdx, unsigned long r8)
{
    register unsigned long r8r __asm__("r8") = r8;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status)
                         : "a"(leaf), "c"(rcx), "d"(rdx), "r"(r8r)
                         : "memory");
    return status;
}

/* TDVMCALL<MapGPA>: R11 subfunction, R12 GPA (with the alias bit), R13 size. */
static unsigned long map_gpa(unsigned long gpa_with_alias, unsigned long size,
                             unsigned long *r10_out)
{
    register unsigned long r10 __asm__("r10") = 0;
    register unsigned long r11 __asm__("r11") = TDVMCALL_MAP_GPA;
    register unsigned long r12 __asm__("r12") = gpa_with_alias;
    register unsigned long r13 __asm__("r13") = size;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status), "+r"(r10), "+r"(r11), "+r"(r12),
                           "+r"(r13)
                         : "a"(TDG_VP_VMCALL), "c"(0xfc00)
                         : "memory");
    *r10_out = r10;
    return status;
}

static unsigned long accept_page(unsigned long gpa)
{
    return tdcall(TDG_MEM_PAGE_ACCEPT, gpa, 0, 0);
}

/* GPAW is reported in TDG.VP.INFO's RCX[5:0]; the SHARED bit is GPAW-1. */
static unsigned long shared_bit(void)
{
    unsigned long gpaw;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=c"(gpaw)
                         : "a"(TDG_VP_INFO)
                         : "rdx", "r8", "r9", "r10", "r11", "memory");
    return 1UL << ((gpaw & 0x3f) - 1);
}

/* --- page tables, so the SHARED alias can actually be mapped -------------- */

static unsigned long pml4[512] __attribute__((aligned(4096)));
static unsigned long pdp[512] __attribute__((aligned(4096)));
static unsigned long pd[4][512] __attribute__((aligned(4096)));
static unsigned long pt[512] __attribute__((aligned(4096)));
static unsigned long split_base;

static unsigned char arena[4 * PAGE_SIZE] __attribute__((aligned(4096)));

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

    split_base = split_addr & ~(LARGE_PAGE_SIZE - 1);
    for (i = 0; i < 512; i++) {
        pt[i] = (split_base + i * PAGE_SIZE) | PTE_FLAGS;
    }
    pd[split_base >> 30][(split_base >> 21) & 0x1ff] =
        (unsigned long)pt | PDE_TABLE_FLAGS;

    __asm__ __volatile__("mov %0, %%cr3"
                         : : "r"((unsigned long)pml4) : "memory");
}

static unsigned long *pte_for(unsigned long va)
{
    return &pt[(va - split_base) / PAGE_SIZE];
}

static void set_alias(unsigned long va, unsigned long bit, int on)
{
    if (on) {
        *pte_for(va) |= bit;
    } else {
        *pte_for(va) &= ~bit;
    }
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

/* --- #VE handler ---------------------------------------------------------- */

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
extern void ve_entry(void);

static volatile unsigned long ve_count;
static volatile unsigned long ve_last_reason;
static volatile unsigned long ve_last_gpa;
static volatile unsigned long ve_accepted;
static volatile unsigned long ve_realiased;
static unsigned long shared_bit_cached;

/*
 * #VE carries no error code: the reason and the faulting GPA come from
 * TDG.VP.VEINFO.GET, which must be called before returning.  The TDX module
 * refuses to deliver a second #VE while the information from the first is still
 * pending and injects #DF instead, so a handler that skips this survives
 * exactly one fault.
 */
static void veinfo_get(unsigned long *reason, unsigned long *gpa)
{
    register unsigned long r9v __asm__("r9");
    unsigned long rcx;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=c"(rcx), "=r"(r9v)
                         : "a"(TDG_VP_VEINFO_GET)
                         : "rdx", "r8", "r10", "r11", "memory");
    *reason = rcx;
    *gpa = r9v;
}

/*
 * Directed entirely by what the architecture reports, with nothing arranged in
 * advance.  Try to accept the page: if it was merely unaccepted that fixes it,
 * and if the TDX module says the attributes conflict then the page is shared
 * and what needs fixing is the alias in the page table.  Either way the cause is
 * removed and the faulting access retries, which is the contract of #VE.
 */
void ve_handle(void);
void ve_handle(void)
{
    unsigned long reason, gpa, status;

    veinfo_get(&reason, &gpa);
    ve_count++;
    ve_last_reason = reason;
    ve_last_gpa = gpa;

    gpa &= ~0xfffUL;
    gpa &= ~shared_bit_cached;

    status = accept_page(gpa);
    if (status == TDX_SUCCESS) {
        ve_accepted++;
    } else if (status == (TDX_PAGE_ATTR_CONFLICT | TDX_OPERAND_ID_RCX)) {
        set_alias(gpa, shared_bit_cached, 1);
        ve_realiased++;
    }
}

__asm__(".globl ve_entry\n"
        "ve_entry:\n"
        "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n"
        "  push %rdi\n  push %r8\n   push %r9\n   push %r10\n"
        "  push %r11\n  push %r12\n  push %r13\n  sub $8, %rsp\n"
        "  call ve_handle\n"
        "  add $8, %rsp\n"
        "  pop %r13\n  pop %r12\n  pop %r11\n  pop %r10\n"
        "  pop %r9\n   pop %r8\n   pop %rdi\n  pop %rsi\n"
        "  pop %rdx\n  pop %rcx\n  pop %rax\n"
        "  iretq\n");

static void idt_init(void)
{
    unsigned long addr = (unsigned long)ve_entry;
    struct idt_ptr ptr = { .limit = sizeof(idt) - 1,
                           .base = (unsigned long)idt };
    unsigned short cs;

    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs));
    idt[20].offset_lo  = addr & 0xffff;
    idt[20].selector   = cs;
    idt[20].type_attr  = 0x8e;
    idt[20].offset_mid = (addr >> 16) & 0xffff;
    idt[20].offset_hi  = addr >> 32;
    __asm__ __volatile__("lidt %0" : : "m"(ptr));
}

int main(void)
{
    unsigned long shared = shared_bit();

    shared_bit_cached = shared;
    unsigned long page_a = (unsigned long)arena;
    unsigned long page_b = page_a + PAGE_SIZE;
    volatile unsigned long *a = (volatile unsigned long *)page_a;
    volatile unsigned long *b = (volatile unsigned long *)page_b;
    unsigned long status, r10;

    ml_printf("Emulated TDX page-state test (SHARED bit %d)\n",
              (int)__builtin_ctzl(shared));

    idt_init();
    build_tables(page_a);
    ml_printf("running on self-built page tables\n");

    /* Lazy mode: pages start accepted, so accepting again is a no-op. */
    status = accept_page(page_a);
    check(status == TDX_PAGE_ALREADY_ACCEPTED,
          "accepting an accepted page did not report ALREADY_ACCEPTED");

    /* A 2MiB accept is refused: only 4KiB is modelled. */
    status = accept_page((page_a & ~(LARGE_PAGE_SIZE - 1)) | 1);
    check(status == (TDX_PAGE_SIZE_MISMATCH | TDX_OPERAND_ID_RCX),
          "2MiB accept was not refused");

    /*
     * Convert page A to shared and map it through the SHARED alias.  Both
     * halves matter: the conversion has to be recorded, and the alias has to be
     * mappable at all.
     */
    *a = 0x1111;
    status = map_gpa(page_a | shared, PAGE_SIZE, &r10);
    check(status == TDX_SUCCESS && r10 == TDVMCALL_SUCCESS,
          "MapGPA to shared failed");

    set_alias(page_a, shared, 1);
    check(*a == 0x1111, "shared alias does not reach the same memory");
    *a = 0x2222;
    check(*a == 0x2222, "shared page not writable through the alias");
    check(ve_count == 0, "a correctly aliased access raised #VE");

    /* Accepting a shared page is a conflict: convert it back first. */
    status = accept_page(page_a);
    check(status == (TDX_PAGE_ATTR_CONFLICT | TDX_OPERAND_ID_RCX),
          "accepting a shared page was not refused");

    /*
     * Using the private alias for a page that is shared is an EPT violation.
     * The handler cannot fix this one, so count it and put the alias back.
     */
    ve_count = 0;
    ve_realiased = 0;
    set_alias(page_a, shared, 0);
    check(*a == 0x2222, "page unreadable after the handler fixed the alias");
    check(ve_count == 1, "private access to a shared page did not raise #VE");
    check(ve_last_reason == EXIT_REASON_EPT_VIOLATION, "#VE exit reason");
    check(ve_realiased == 1, "the handler did not repair the alias");

    /*
     * Convert page B to shared and back to private.  It comes back *pending*,
     * so the first touch raises #VE and the handler accepts it on demand --
     * which is what a TD does with the memory it is given.
     */
    status = map_gpa(page_b | shared, PAGE_SIZE, &r10);
    check(status == TDX_SUCCESS, "MapGPA of page B to shared failed");
    status = map_gpa(page_b, PAGE_SIZE, &r10);
    check(status == TDX_SUCCESS, "MapGPA of page B back to private failed");

    ve_count = 0;
    ve_accepted = 0;
    *b = 0x3333;
    check(ve_count == 1, "touching a pending page did not raise one #VE");
    check(ve_accepted == 1, "the handler did not accept the page");
    check((ve_last_gpa & ~0xfffUL) == page_b, "#VE reported the wrong GPA");
    check(*b == 0x3333, "page unusable after being accepted on demand");

    /* And it stays accepted. */
    *b = 0x4444;
    check(*b == 0x4444 && ve_count == 1, "accepted page faulted again");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All TDX page-state checks passed (%d #VE serviced)\n",
              (int)ve_count);
    return 0;
}
