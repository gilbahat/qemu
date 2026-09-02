/*
 * Emulated AMD SEV-SNP GHCB page / NAE event test.
 *
 * This is the configuration a real SNP guest runs in: I/O reflection armed,
 * with a #VC handler that services the exception through a registered GHCB
 * rather than skipping it.  Every character this test prints after arming
 * therefore travels out over the GHCB -- if the NAE path were broken the test
 * could not report at all.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#include "snp-ptes.h"

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_REG_GPA_REQ    0x012
#define GHCB_MSR_REG_GPA_RESP   0x013

#define SVM_EXIT_IOIO           0x07b
#define SVM_EXIT_CPUID          0x072

#define GHCB_OFF_RAX            0x1f8
#define GHCB_OFF_RCX            0x308
#define GHCB_OFF_RDX            0x310
#define GHCB_OFF_RBX            0x318
#define GHCB_OFF_SW_EXITCODE    0x390
#define GHCB_OFF_SW_EXITINFO1   0x398
#define GHCB_OFF_SW_EXITINFO2   0x3a0
#define GHCB_OFF_VALID_BITMAP   0x3f0
#define GHCB_OFF_USAGE          0xffc

#define GHCB_BIT(off)           ((off) / 8)

#define IOIO_TYPE_IN            (1U << 0)
#define IOIO_SIZE_8             (1U << 4)
#define IOIO_SIZE_16            (1U << 5)
#define IOIO_SIZE_32            (1U << 6)
#define IOIO_PORT_SHIFT         16

static int failures;
static volatile unsigned long vc_count;

static unsigned char ghcb[4096] __attribute__((aligned(4096)));

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

static void vmgexit(void)
{
    __asm__ __volatile__(".byte 0xf3,0x0f,0x01,0xd9" : : : "memory");
}

static unsigned long *ghcb_at(unsigned int off)
{
    return (unsigned long *)&ghcb[off];
}

static void ghcb_clear(void)
{
    unsigned int i;

    for (i = 0; i < sizeof(ghcb); i++) {
        ghcb[i] = 0;
    }
}

static void ghcb_mark(unsigned int off)
{
    unsigned int bit = GHCB_BIT(off);

    ghcb_at(GHCB_OFF_VALID_BITMAP)[bit / 64] |= 1UL << (bit % 64);
}

static int ghcb_valid(unsigned int off)
{
    unsigned int bit = GHCB_BIT(off);

    return (ghcb_at(GHCB_OFF_VALID_BITMAP)[bit / 64] >> (bit % 64)) & 1;
}

/*
 * Service one port-I/O NAE event.  This is the whole point of the GHCB: the
 * guest cannot touch the port itself, so it describes the access and asks.
 */
static unsigned long size_bit(unsigned int size)
{
    return size == 1 ? IOIO_SIZE_8 : size == 2 ? IOIO_SIZE_16 : IOIO_SIZE_32;
}

static unsigned long ghcb_in(unsigned int port, unsigned int size)
{
    ghcb_clear();
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_IOIO;
    *ghcb_at(GHCB_OFF_SW_EXITINFO1) = IOIO_TYPE_IN | size_bit(size) |
        ((unsigned long)port << IOIO_PORT_SHIFT);
    ghcb_mark(GHCB_OFF_SW_EXITCODE);
    ghcb_mark(GHCB_OFF_SW_EXITINFO1);
    vmgexit();
    return *ghcb_at(GHCB_OFF_RAX);
}

static void ghcb_out(unsigned int port, unsigned long val, unsigned int size)
{
    ghcb_clear();
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_IOIO;
    *ghcb_at(GHCB_OFF_SW_EXITINFO1) = size_bit(size) |
        ((unsigned long)port << IOIO_PORT_SHIFT);
    *ghcb_at(GHCB_OFF_RAX) = val;
    ghcb_mark(GHCB_OFF_SW_EXITCODE);
    ghcb_mark(GHCB_OFF_SW_EXITINFO1);
    ghcb_mark(GHCB_OFF_RAX);
    vmgexit();
}

/* --- #VC handler: decode the faulting I/O instruction and service it ------ */

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
 * frame[0] error code, frame[1] RIP, and the saved RAX/RDX the trampoline
 * pushed, so an IN can hand its result back to the interrupted code.
 */
void vc_handle(unsigned long *frame, unsigned long *saved_rax,
               unsigned long *saved_rdx);
void vc_handle(unsigned long *frame, unsigned long *saved_rax,
               unsigned long *saved_rdx)
{
    const unsigned char *insn = (const unsigned char *)frame[1];
    unsigned int len = 0;
    unsigned int size = 4;
    unsigned int port;

    vc_count++;

    /*
     * Decode enough of the I/O encodings to service them: an optional operand
     * size prefix, then a port in an immediate or in DX.  Anything else is
     * stepped over, which is all a test can do without the full instruction.
     */
    if (insn[0] == 0x66) {
        size = 2;
        len = 1;
        insn++;
    }

    switch (insn[0]) {
    case 0xe4: case 0xe5:               /* in al/eax, imm8 */
        port = insn[1];
        len += 2;
        *saved_rax = ghcb_in(port, insn[0] == 0xe4 ? 1 : size);
        break;
    case 0xe6: case 0xe7:               /* out imm8, al/eax */
        port = insn[1];
        len += 2;
        ghcb_out(port, *saved_rax, insn[0] == 0xe6 ? 1 : size);
        break;
    case 0xec: case 0xed:               /* in al/eax, dx */
        port = *saved_rdx & 0xffff;
        len += 1;
        *saved_rax = ghcb_in(port, insn[0] == 0xec ? 1 : size);
        break;
    case 0xee: case 0xef:               /* out dx, al/eax */
        port = *saved_rdx & 0xffff;
        len += 1;
        ghcb_out(port, *saved_rax, insn[0] == 0xee ? 1 : size);
        break;
    default:
        len += (insn[0] == 0x0f) ? 2 : 1;
        break;
    }

    frame[1] += len;
}

__asm__(".globl vc_entry\n"
        "vc_entry:\n"
        "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n"
        "  push %rdi\n  push %r8\n   push %r9\n   push %r10\n"
        "  push %r11\n  sub $8, %rsp\n"
        "  lea 80(%rsp), %rdi\n"        /* interrupt frame  */
        "  lea 72(%rsp), %rsi\n"        /* saved rax        */
        "  lea 56(%rsp), %rdx\n"        /* saved rdx        */
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

/* Something the guest may legitimately claim; see its use below. */
static unsigned char arm_page[4096] __attribute__((aligned(4096)));

static unsigned int pvalidate(unsigned long gva)
{
    unsigned int status;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff"
                         : "=a"(status) : "a"(gva), "c"(0), "d"(1)
                         : "cc", "memory");
    return status;
}

int main(void)
{
    unsigned long resp;
    unsigned int a, b, c, d;

    ml_printf("Emulated SEV-SNP GHCB page / NAE test\n");

    idt_init();

    /* Own tables, so arm_page below can be mapped encrypted on its own. */
    snp_tables_init((unsigned long)arm_page);

    resp = 0;
    wrmsr(MSR_AMD64_SEV_ES_GHCB,
          GHCB_MSR_REG_GPA_REQ | (unsigned long)ghcb);
    vmgexit();
    resp = rdmsr(MSR_AMD64_SEV_ES_GHCB);
    check((resp & 0xfff) == GHCB_MSR_REG_GPA_RESP, "GHCB registration");

    /*
     * Leave the GHCB address in the register: the page protocol takes the
     * GHCB from the MSR at each VMGEXIT, so clearing it makes every exit below
     * arrive with no GHCB and do nothing at all.  A bare page-aligned address
     * carries no request code, so it cannot be read as an in-flight request
     * either, which is what the zero was for.
     */
    wrmsr(MSR_AMD64_SEV_ES_GHCB, (unsigned long)ghcb);

    /* NAE CPUID through the page, cross-checked against the instruction. */
    ghcb_clear();
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_CPUID;
    *ghcb_at(GHCB_OFF_RAX) = 1;
    *ghcb_at(GHCB_OFF_RCX) = 0;
    ghcb_mark(GHCB_OFF_SW_EXITCODE);
    ghcb_mark(GHCB_OFF_RAX);
    ghcb_mark(GHCB_OFF_RCX);
    vmgexit();
    check(*ghcb_at(GHCB_OFF_SW_EXITINFO2) == 0, "NAE CPUID reported an error");
    check(ghcb_valid(GHCB_OFF_RBX), "NAE CPUID did not set RBX valid");

    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(1), "c"(0));
    check((unsigned int)*ghcb_at(GHCB_OFF_RAX) == a, "NAE CPUID EAX != native");
    check((unsigned int)*ghcb_at(GHCB_OFF_RBX) == b, "NAE CPUID EBX != native");
    check((unsigned int)*ghcb_at(GHCB_OFF_RDX) == d, "NAE CPUID EDX != native");

    /* A request with no valid SW_EXITCODE must be refused. */
    ghcb_clear();
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_CPUID;
    vmgexit();
    check(*ghcb_at(GHCB_OFF_SW_EXITINFO2) != 0,
          "NAE without a valid SW_EXITCODE was accepted");

    /*
     * Arm reflection.  From here every ml_printf() faults and is serviced by
     * the handler above -- so the remaining output is itself the test.
     *
     * Not the GHCB: that page is shared by definition, since the hypervisor
     * has to read it, so it is mapped C=0 and PVALIDATE answers a C=0 mapping
     * with #PF rather than a status.  This test used to validate its own GHCB
     * and get away with it, which is the exact confusion the emulator's check
     * exists to surface.  Claim a page that may actually be claimed.
     */
    snp_map_private((unsigned long)arm_page);
    check(pvalidate((unsigned long)arm_page) == 0, "PVALIDATE status");

    ml_printf("output below this line travels over the GHCB\n");
    check(vc_count > 0, "no #VC was taken after arming");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP NAE checks passed (%d serviced)\n", (int)vc_count);
    return 0;
}
