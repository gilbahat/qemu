/*
 * Emulated Intel TDX strict-mode test.
 *
 * Strict mode starts guest RAM private and pending, as the TDX module leaves it
 * after TDH.MEM.PAGE.ADD, with only the launch-measured image accepted.  A TD
 * that never accepts its memory therefore faults on its first use of the stack
 * -- which is the point of the mode, but it also means that until something
 * survives it, the mode is only known to reject and not to work.
 *
 * This test is that something.  It links the TDX_ACCEPT_BOOT variant of boot.S,
 * which accepts .bss before the stack is touched -- the one thing TD firmware
 * must do before anything else.  Reaching main() is the headline result.
 *
 * It then accepts RAM outside the launch image on demand, through #VE, which is
 * how a TD takes ownership of the memory it was given.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define TDX_SUCCESS                 0x0000000000000000UL
#define TDX_PAGE_ALREADY_ACCEPTED   0x00000B0A00000000UL

#define TDG_VP_VEINFO_GET           3UL
#define TDG_MEM_PAGE_ACCEPT         6UL

#define EXIT_REASON_EPT_VIOLATION   48

/* Well clear of the payload and of .bss, and inside boot.S's identity map. */
#define PENDING_GPA                 (16UL * 1024 * 1024)

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static unsigned long accept_page(unsigned long gpa)
{
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status)
                         : "a"(TDG_MEM_PAGE_ACCEPT), "c"(gpa)
                         : "rdx", "r8", "r9", "r10", "r11", "memory");
    return status;
}

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

/* --- #VE handler --------------------------------------------------------- */

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

/*
 * VE_INFO has to be consumed or the TDX module refuses to deliver the next #VE
 * and injects #DF instead, so a handler that skips it survives exactly one
 * fault.  Everything this needs comes out of it: accept the page it names and
 * the faulting access retries.
 */
void ve_handle(void);
void ve_handle(void)
{
    unsigned long reason, gpa;

    veinfo_get(&reason, &gpa);
    ve_count++;
    ve_last_reason = reason;
    ve_last_gpa = gpa;

    if (accept_page(gpa & ~0xfffUL) == TDX_SUCCESS) {
        ve_accepted++;
    }
}

__asm__(".globl ve_entry\n"
        "ve_entry:\n"
        "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n"
        "  push %rdi\n  push %r8\n   push %r9\n   push %r10\n"
        "  push %r11\n  sub $8, %rsp\n"
        "  call ve_handle\n"
        "  add $8, %rsp\n"
        "  pop %r11\n  pop %r10\n  pop %r9\n   pop %r8\n"
        "  pop %rdi\n  pop %rsi\n  pop %rdx\n  pop %rcx\n"
        "  pop %rax\n"
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

static char bss_probe[4096] __attribute__((aligned(4096)));

int main(void)
{
    volatile unsigned long *far = (volatile unsigned long *)PENDING_GPA;

    /*
     * Getting here means the payload is running on a stack it accepted itself,
     * under an emulation that would have faulted on the first push otherwise.
     */
    ml_printf("Emulated TDX strict-mode test\n");

    idt_init();

    /* The bootstrap really did accept .bss, so accepting again is a no-op. */
    check(accept_page((unsigned long)bss_probe) == TDX_PAGE_ALREADY_ACCEPTED,
          ".bss page was not already accepted by the bootstrap");
    check(ve_count == 0, "an accepted access raised #VE");

    /*
     * RAM the bootstrap never touched is still pending, as the TDX module
     * leaves it.  This is the fault a TD is expected to handle.
     */
    *far = 0xabcd;

    check(ve_count == 1, "touching pending RAM did not raise one #VE");
    check(ve_last_reason == EXIT_REASON_EPT_VIOLATION, "#VE exit reason");
    check((ve_last_gpa & ~0xfffUL) == PENDING_GPA,
          "#VE reported the wrong GPA");
    check(ve_accepted == 1, "the handler did not accept the page");
    check(*far == 0xabcd, "page unusable after on-demand accept");

    /* Still accepted on the next access. */
    *far = 0x1234;
    check(*far == 0x1234 && ve_count == 1, "accepted page faulted again");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All TDX strict-mode checks passed (1 #VE serviced)\n");
    return 0;
}
