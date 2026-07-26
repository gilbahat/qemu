/*
 * Emulated AMD SEV-SNP strict-mode test.
 *
 * Strict mode starts guest RAM private and unvalidated, exactly as hardware
 * leaves it after SNP_LAUNCH_UPDATE, with only the launch-measured image
 * validated.  A guest that has not adopted the C-bit therefore dies on its
 * first paged access -- which is the point of the mode, but it also means that
 * until something survives it, the mode is only known to reject, not to work.
 *
 * This test is that something.  It links against the SNP_CBIT_BOOT variant of
 * boot.S, which sets the C-bit in the page tables before paging is enabled and
 * validates .bss before the stack is used -- the same two things real SNP
 * firmware must do.  Reaching main() at all is the headline result.
 *
 * It then drives the case boot.S cannot: RAM outside the launch image and
 * outside .bss, which is still private and unvalidated.  Touching it raises
 * #VC, and the handler validates it on demand.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define SNP_EXIT_PAGE_NOT_VALIDATED  0x404

/* Well clear of the payload and of .bss, and inside the identity map. */
#define UNVALIDATED_GPA         (16UL * 1024 * 1024)

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static unsigned int pvalidate(unsigned long gva, unsigned int validate,
                              unsigned int *cf)
{
    unsigned int status;
    unsigned long flags;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff\n\t"
                         "pushfq\n\t"
                         "pop %1"
                         : "=a"(status), "=r"(flags)
                         : "a"(gva), "c"(0), "d"(validate)
                         : "cc", "memory");
    if (cf) {
        *cf = flags & 1;
    }
    return status;
}

static unsigned long read_cr3(void)
{
    unsigned long v;

    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static unsigned int cbitpos(void)
{
    unsigned int a, b, c, d;

    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(0x8000001F), "c"(0));
    return b & 0x3f;
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

void vc_handle(unsigned long *frame);
void vc_handle(unsigned long *frame)
{
    vc_count++;
    vc_code = frame[0];

    /* #VC is a fault, so returning retries the access. */
    if (frame[0] == SNP_EXIT_PAGE_NOT_VALIDATED && vc_expect_page) {
        unsigned int ignored;

        pvalidate(vc_expect_page, 1, &ignored);
        vc_expect_page = 0;
        return;
    }

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

static char bss_probe[4096] __attribute__((aligned(4096)));

int main(void)
{
    unsigned long cbit = 1UL << cbitpos();
    volatile unsigned long *far = (volatile unsigned long *)UNVALIDATED_GPA;
    unsigned int cf;

    /*
     * Getting here means the payload is executing from private memory it
     * mapped encrypted, on a stack it validated itself, under an emulation
     * that would have terminated it for getting either wrong.
     */
    ml_printf("Emulated SEV-SNP strict-mode test (C-bit %d)\n", (int)cbitpos());

    idt_init();

    /* The bootstrap really did set the C-bit: it is live in CR3. */
    check((read_cr3() & cbit) != 0, "CR3 does not carry the C-bit");

    /* And .bss really was validated, so re-validating is a no-op. */
    check(pvalidate((unsigned long)bss_probe, 1, &cf) == 0,
          "PVALIDATE of a .bss page failed");
    check(cf == 1, ".bss page was not already validated by the bootstrap");
    check(vc_count == 0, "a validated access raised #VC");

    /*
     * RAM the bootstrap never touched is private and unvalidated, as hardware
     * leaves it.  This is the fault a guest is expected to handle, and the only
     * way to reach it is from a page mapped with the C-bit set -- which is now
     * the case for every page.
     */
    vc_expect_page = UNVALIDATED_GPA;
    *far = 0xabcd;

    check(vc_count == 1, "touching unvalidated RAM did not raise one #VC");
    check(vc_code == SNP_EXIT_PAGE_NOT_VALIDATED, "#VC error code");
    check(vc_expect_page == 0, "the handler did not run");
    check(*far == 0xabcd, "page unusable after on-demand validation");

    /* Still validated on the next access. */
    *far = 0x1234;
    check(*far == 0x1234 && vc_count == 1, "validated page faulted again");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP strict-mode checks passed (1 #VC serviced)\n");
    return 0;
}
