/*
 * Emulated Intel TDX guest interface (TCG) regression test.
 *
 * Runs with -cpu ...,x-tdx-guest=on and checks the guest-visible surface:
 * the CPUID identification leaf, TDCALL and the TDG.* leaves, and the
 * TDVMCALL service routines a #VE handler depends on.
 *
 * Each service routine is cross-checked against the native instruction it
 * stands in for, so a routine that silently returns garbage fails here rather
 * than in a guest three layers up.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define TDG_VP_VMCALL           0
#define TDG_VP_INFO             1
#define TDG_VP_VEINFO_GET       3
#define TDG_MEM_PAGE_ACCEPT     6

#define TDVMCALL_INSTR_CPUID    10
#define TDVMCALL_INSTR_IO       30
#define TDVMCALL_INSTR_RDMSR    31
#define TDVMCALL_REQUEST_MMIO   48

#define TDX_SUCCESS             0
#define TDX_OPERAND_INVALID     0xC000010000000000ULL
#define TDX_NO_VE_INFO          0xC000070000000000ULL
#define TDVMCALL_SUCCESS        0
#define TDVMCALL_INVALID_OPERAND 0x8000000000000000ULL

/* Expose R10-R15 to the VMM, as a real TD guest does. */
#define EXPOSE_REGS             0xfc00

/* LAPIC version register: MMIO, always present, read-only. */
#define LAPIC_VER               0xfee00030UL

struct tdx_args {
    unsigned long rax, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
};

static void tdcall(struct tdx_args *a)
{
    register unsigned long rax __asm__("rax") = a->rax;
    register unsigned long rcx __asm__("rcx") = a->rcx;
    register unsigned long rdx __asm__("rdx") = a->rdx;
    register unsigned long r8  __asm__("r8")  = a->r8;
    register unsigned long r9  __asm__("r9")  = a->r9;
    register unsigned long r10 __asm__("r10") = a->r10;
    register unsigned long r11 __asm__("r11") = a->r11;
    register unsigned long r12 __asm__("r12") = a->r12;
    register unsigned long r13 __asm__("r13") = a->r13;
    register unsigned long r14 __asm__("r14") = a->r14;
    register unsigned long r15 __asm__("r15") = a->r15;

    /* TDCALL, 66 0F 01 CC -- spelled out so no assembler support is needed. */
    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "+r"(rax), "+r"(rcx), "+r"(rdx), "+r"(r8), "+r"(r9),
                           "+r"(r10), "+r"(r11), "+r"(r12), "+r"(r13),
                           "+r"(r14), "+r"(r15)
                         : : "memory");

    a->rax = rax; a->rcx = rcx; a->rdx = rdx; a->r8 = r8; a->r9 = r9;
    a->r10 = r10; a->r11 = r11; a->r12 = r12; a->r13 = r13; a->r14 = r14;
    a->r15 = r15;
}

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static void native_cpuid(unsigned int leaf, unsigned int subleaf,
                         unsigned int *a, unsigned int *b,
                         unsigned int *c, unsigned int *d)
{
    unsigned int ra = leaf, rb, rc = subleaf, rd;

    __asm__ __volatile__("cpuid"
                         : "+a"(ra), "=b"(rb), "+c"(rc), "=d"(rd));
    *a = ra; *b = rb; *c = rc; *d = rd;
}

static void test_cpuid_leaf(void)
{
    unsigned int a, b, c, d;

    native_cpuid(0x21, 0, &a, &b, &c, &d);
    /* "IntelTDX    " in EBX:EDX:ECX, exactly as the TDX module reports it. */
    check(b == 0x65746E49, "CPUID.0x21 EBX != \"Inte\"");
    check(d == 0x5844546C, "CPUID.0x21 EDX != \"lTDX\"");
    check(c == 0x20202020, "CPUID.0x21 ECX != \"    \"");
}

static void test_vp_info(void)
{
    struct tdx_args a = { .rax = TDG_VP_INFO };
    unsigned int gpaw;

    tdcall(&a);
    check(a.rax == TDX_SUCCESS, "TDG.VP.INFO status");

    gpaw = a.rcx & 0x3f;
    check(gpaw >= 32 && gpaw <= 63, "TDG.VP.INFO reported an out-of-range GPAW");

    /* A debuggable TD is not emulated, so ATTRIBUTES.DEBUG must be clear. */
    check((a.rdx & 1) == 0, "TDG.VP.INFO reported ATTRIBUTES.DEBUG set");
}

/*
 * An unknown leaf must report an invalid operand, not #UD: a guest may issue
 * its first TDCALL before installing an IDT, where a fault is a silent triple
 * fault.  Reaching the next line at all is most of what this checks.
 */
static void test_unknown_leaf(void)
{
    struct tdx_args a = { .rax = 0x999 };

    tdcall(&a);
    check(a.rax == TDX_OPERAND_INVALID, "unknown TDCALL leaf status");
}

static void test_veinfo_empty(void)
{
    struct tdx_args a = { .rax = TDG_VP_VEINFO_GET };

    tdcall(&a);
    check(a.rax == TDX_NO_VE_INFO, "TDG.VP.VEINFO.GET with no pending #VE");
}

static void test_page_accept(void)
{
    static char page[8192] __attribute__((aligned(4096)));
    struct tdx_args a = { .rax = TDG_MEM_PAGE_ACCEPT,
                          .rcx = (unsigned long)page };

    tdcall(&a);
    check((a.rax & (1ULL << 63)) == 0, "TDG.MEM.PAGE.ACCEPT reported an error");

    /* A page size other than 4KiB is not modelled and must be rejected. */
    a = (struct tdx_args){ .rax = TDG_MEM_PAGE_ACCEPT,
                           .rcx = (unsigned long)page | 1 };
    tdcall(&a);
    check((a.rax & (1ULL << 63)) != 0, "PAGE.ACCEPT accepted a 2MiB page");
}

/* The service routine must agree with the instruction it replaces. */
static void test_vmcall_cpuid(void)
{
    struct tdx_args a = { .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                          .r10 = 0, .r11 = TDVMCALL_INSTR_CPUID,
                          .r12 = 0x21, .r13 = 0 };
    unsigned int na, nb, nc, nd;

    tdcall(&a);
    check(a.r10 == TDVMCALL_SUCCESS, "TDVMCALL<Instruction.CPUID> status");

    native_cpuid(0x21, 0, &na, &nb, &nc, &nd);
    check((unsigned int)a.r11 == na, "TDVMCALL CPUID EAX != native");
    check((unsigned int)a.r12 == nb, "TDVMCALL CPUID EBX != native");
    check((unsigned int)a.r13 == nc, "TDVMCALL CPUID ECX != native");
    check((unsigned int)a.r14 == nd, "TDVMCALL CPUID EDX != native");
}

static void test_vmcall_io(void)
{
    struct tdx_args a;
    unsigned char native;

    /* Port 0x71 is CMOS data: readable, and reading it has no side effect
     * beyond the index register already selected. */
    __asm__ __volatile__("inb $0x71, %%al" : "=a"(native));

    a = (struct tdx_args){ .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                           .r10 = 0, .r11 = TDVMCALL_INSTR_IO,
                           .r12 = 1, .r13 = 1, .r14 = 0x71 };
    tdcall(&a);
    check(a.r10 == TDVMCALL_SUCCESS, "TDVMCALL<Instruction.IO> status");
    check((unsigned char)a.r11 == native, "TDVMCALL IO read != native inb");

    /* A size the architecture does not define must be refused. */
    a = (struct tdx_args){ .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                           .r10 = 0, .r11 = TDVMCALL_INSTR_IO,
                           .r12 = 3, .r13 = 1, .r14 = 0x71 };
    tdcall(&a);
    check(a.r10 == TDVMCALL_INVALID_OPERAND, "TDVMCALL IO accepted size 3");
}

static void test_vmcall_msr(void)
{
    struct tdx_args a = { .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                          .r10 = 0, .r11 = TDVMCALL_INSTR_RDMSR,
                          .r12 = 0xc0000080 /* IA32_EFER */ };
    unsigned int lo, hi;
    unsigned long native;

    tdcall(&a);
    check(a.r10 == TDVMCALL_SUCCESS, "TDVMCALL<Instruction.RDMSR> status");

    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xc0000080));
    native = ((unsigned long)hi << 32) | lo;
    check(a.r11 == native, "TDVMCALL RDMSR != native rdmsr");
}

static void test_vmcall_mmio(void)
{
    struct tdx_args a = { .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                          .r10 = 0, .r11 = TDVMCALL_REQUEST_MMIO,
                          .r12 = 4, .r13 = 1, .r14 = LAPIC_VER };
    volatile unsigned int *p = (volatile unsigned int *)LAPIC_VER;
    unsigned int native;

    tdcall(&a);
    check(a.r10 == TDVMCALL_SUCCESS, "TDVMCALL<#VE.RequestMMIO> status");

    /* Not reflected here, so the direct read is the reference value. */
    native = *p;
    check((unsigned int)a.r11 == native, "RequestMMIO read != direct MMIO read");

    a = (struct tdx_args){ .rax = TDG_VP_VMCALL, .rcx = EXPOSE_REGS,
                           .r10 = 0, .r11 = TDVMCALL_REQUEST_MMIO,
                           .r12 = 3, .r13 = 1, .r14 = LAPIC_VER };
    tdcall(&a);
    check(a.r10 == TDVMCALL_INVALID_OPERAND, "RequestMMIO accepted size 3");
}

int main(void)
{
    ml_printf("Emulated TDX guest interface test\n");

    test_cpuid_leaf();
    test_vp_info();
    test_unknown_leaf();
    test_veinfo_empty();
    test_page_accept();
    test_vmcall_cpuid();
    test_vmcall_io();
    test_vmcall_msr();
    test_vmcall_mmio();

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All TDX interface checks passed\n");
    return 0;
}
