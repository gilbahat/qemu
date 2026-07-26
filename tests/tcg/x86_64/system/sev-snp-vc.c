/*
 * Emulated AMD SEV-SNP #VC reflection test.
 *
 * Installs an IDT with a #VC (vector 29) handler, arms reflection with
 * PVALIDATE, then executes each intercepted instruction class and checks that
 * the exception arrives with the right GHCB SW_EXITCODE as its error code.
 *
 * The handler cannot service the exit -- that needs the GHCB -- so it records
 * what it saw and steps over the faulting instruction, decoding its length.
 *
 * Port I/O is deliberately relaxed here (x-sev-snp-relax-io=on).  A handler
 * that can only skip cannot service I/O, and both this test's output and the
 * isa-debug-exit write it terminates with are port I/O -- so with the class
 * armed the test could neither report nor exit.  That is not a limitation of
 * the test but the point of the feature: a guest under I/O reflection must
 * service it through the GHCB.  Cover that once VMGEXIT lands.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define SVM_EXIT_CPUID  0x072
#define SVM_EXIT_HLT    0x078
#define SVM_EXIT_MSR    0x07c

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_SEV_INFO_REQ   0x002

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

/* Set by the handler for the test to inspect. */
static volatile unsigned long vc_count;
static volatile unsigned long vc_error_code;

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

/*
 * The handler must work out the faulting instruction's length for itself.
 * Once reflection is armed every port access reflects, including the ones
 * ml_printf() makes, so the test cannot tell the handler in advance what it is
 * about to step over.  Only the encodings this test can provoke are decoded.
 */
static unsigned int insn_len(const unsigned char *p)
{
    switch (p[0]) {
    case 0x0f:                  /* cpuid (0f a2), rdmsr (0f 32) */
        return 2;
    case 0xe4: case 0xe5:       /* in  al/eax, imm8  */
    case 0xe6: case 0xe7:       /* out imm8, al/eax  */
        return 2;
    default:                    /* ec/ed/ee/ef (dx forms), f4 (hlt) */
        return 1;
    }
}

/*
 * Called from vc_entry with a pointer to the interrupt frame, which for #VC
 * begins with the error code: frame[0] error code, frame[1] RIP.
 */
void vc_handle(unsigned long *frame);
void vc_handle(unsigned long *frame)
{
    vc_error_code = frame[0];
    vc_count++;
    frame[1] += insn_len((const unsigned char *)frame[1]);
}

/*
 * Save every caller-saved register, keep the stack 16-byte aligned across the
 * call, then drop the error code before iretq.
 */
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

extern void df_entry(void);

static volatile unsigned long df_count;

/*
 * A #VC raised while the GHCB MSR still holds an unconsumed request escalates
 * to #DF, because servicing it would clobber the request.  Clear the stale
 * request and step over the faulting instruction so the test can carry on --
 * resuming from #DF is not architecturally sound, but this is an emulator and
 * it keeps the test's exit path ordinary.
 */
void df_handle(unsigned long *frame);
void df_handle(unsigned long *frame)
{
    df_count++;
    __asm__ __volatile__("wrmsr"
                         : : "c"(MSR_AMD64_SEV_ES_GHCB), "a"(0), "d"(0));
    frame[1] += insn_len((const unsigned char *)frame[1]);
}

__asm__(".globl df_entry\n"
        "df_entry:\n"
        "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n"
        "  push %rdi\n  push %r8\n   push %r9\n   push %r10\n"
        "  push %r11\n  sub $8, %rsp\n"
        "  lea 80(%rsp), %rdi\n"
        "  call df_handle\n"
        "  add $8, %rsp\n"
        "  pop %r11\n  pop %r10\n  pop %r9\n   pop %r8\n"
        "  pop %rdi\n  pop %rsi\n  pop %rdx\n  pop %rcx\n"
        "  pop %rax\n"
        "  add $8, %rsp\n"
        "  iretq\n");

static void set_gate(int vec, void (*handler)(void))
{
    unsigned long addr = (unsigned long)handler;
    unsigned short cs;

    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs));
    idt[vec].offset_lo  = addr & 0xffff;
    idt[vec].selector   = cs;
    idt[vec].ist        = 0;
    idt[vec].type_attr  = 0x8e;  /* present, DPL 0, 64-bit interrupt gate */
    idt[vec].offset_mid = (addr >> 16) & 0xffff;
    idt[vec].offset_hi  = addr >> 32;
    idt[vec].zero       = 0;
}

static void idt_init(void)
{
    struct idt_ptr ptr = { .limit = sizeof(idt) - 1,
                           .base = (unsigned long)idt };

    set_gate(29, vc_entry);
    set_gate(8, df_entry);
    __asm__ __volatile__("lidt %0" : : "m"(ptr));
}

/* PVALIDATE, F2 0F 01 FF -- spelled out so no assembler support is needed. */
static unsigned int pvalidate(unsigned long gva, unsigned int page_size,
                              unsigned int validate)
{
    unsigned int status;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff"
                         : "=a"(status)
                         : "a"(gva), "c"(page_size), "d"(validate)
                         : "cc", "memory");
    return status;
}

static void wrmsr(unsigned int idx, unsigned long val)
{
    __asm__ __volatile__("wrmsr"
                         : : "c"(idx), "a"((unsigned int)val),
                             "d"((unsigned int)(val >> 32)));
}

static unsigned long expect_vc(unsigned long before)
{
    return vc_count - before;
}

int main(void)
{
    unsigned long n;
    static char page[8192] __attribute__((aligned(4096)));

    ml_printf("Emulated SEV-SNP #VC reflection test\n");

    idt_init();

    /* Nothing should reflect before the first PVALIDATE arms it. */
    n = vc_count;
    __asm__ __volatile__("cpuid" : : "a"(1) : "rbx", "rcx", "rdx");
    check(expect_vc(n) == 0, "CPUID reflected before arming");

    check(pvalidate((unsigned long)page, 0, 1) == 0, "PVALIDATE status");
    check(pvalidate((unsigned long)page + 1, 0, 1) == 1,
          "misaligned PVALIDATE not rejected");
    check(pvalidate((unsigned long)page, 9, 1) == 1,
          "bad page size not rejected");

    /* CPUID: 0f a2, two bytes.  Leaf 1 is not one of the native carve-outs. */
    n = vc_count;
    __asm__ __volatile__("cpuid" : : "a"(1) : "rbx", "rcx", "rdx");
    check(expect_vc(n) == 1, "CPUID did not reflect after arming");
    check(vc_error_code == SVM_EXIT_CPUID, "CPUID #VC error code");

    /* Leaf 0 must stay native, or a guest could never identify itself. */
    n = vc_count;
    __asm__ __volatile__("cpuid" : : "a"(0) : "rbx", "rcx", "rdx");
    check(expect_vc(n) == 0, "CPUID leaf 0 should not reflect");

    n = vc_count;
    __asm__ __volatile__("cpuid" : : "a"(0x8000001F) : "rbx", "rcx", "rdx");
    check(expect_vc(n) == 0, "CPUID.0x8000001F should not reflect");

    /* Relaxed for this test, so it must stay native; see the file comment. */
    n = vc_count;
    __asm__ __volatile__("inb %%dx, %%al" : : "d"(0x71) : "al");
    check(expect_vc(n) == 0, "port I/O reflected despite x-sev-snp-relax-io");

    /* RDMSR: 0f 32, two bytes.  A non-native MSR, so it reflects. */
    n = vc_count;
    __asm__ __volatile__("rdmsr" : : "c"(0x10) : "rax", "rdx");
    check(expect_vc(n) == 1, "RDMSR did not reflect");
    check(vc_error_code == SVM_EXIT_MSR, "MSR #VC error code");

    /* EFER is handled natively; reflecting it would break long-mode setup. */
    n = vc_count;
    __asm__ __volatile__("rdmsr" : : "c"(0xc0000080) : "rax", "rdx");
    check(expect_vc(n) == 0, "EFER should not reflect");

    /* HLT: f4, one byte. */
    n = vc_count;
    __asm__ __volatile__("hlt");
    check(expect_vc(n) == 1, "HLT did not reflect");
    check(vc_error_code == SVM_EXIT_HLT, "HLT #VC error code");

    /*
     * Leave a request in the GHCB MSR unconsumed, then provoke a #VC.  It must
     * escalate to #DF; df_handle() reports the overall result and exits, so
     * reaching the line after this means the rule did not fire.
     */
    wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_SEV_INFO_REQ);
    __asm__ __volatile__("cpuid" : : "a"(1) : "rbx", "rcx", "rdx");
    check(df_count == 1, "#VC with a request in flight did not escalate to #DF");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP #VC checks passed (%d exceptions, %d escalated)\n",
              (int)vc_count, (int)df_count);
    return 0;
}
