/*
 * Emulated Intel TDX device DMA test.
 *
 * A TD's private memory is unreachable by the host, so a device may only DMA
 * to memory the TD has converted with TDVMCALL<MapGPA> -- and it addresses that
 * memory by its *plain* GPA.  Both halves are checked, because neither is the
 * answer on its own.
 *
 * The alias bit does not belong in a DMA address.  A TDVMCALL argument carries
 * it, because that is how the call names the alias to the TDX module; device
 * DMA is not relayed through the module at all.  A VMM resolves a DMA address
 * itself, against the ordinary guest memory map, where an address above RAM
 * resolves to nothing: the descriptors are written, the device is kicked, and
 * no data moves.  So an aliased DMA address is refused here whether or not the
 * page behind it was converted, which is the case a guest would otherwise
 * discover on hardware as a virtio device that negotiates and then hangs.
 *
 * The vehicle is the "edu" test device, whose DMA engine is programmable from
 * MMIO and calls pci_dma_read() on the guest's behalf -- the same path a virtio
 * ring fetch takes, with no driver needed.  Its dma_mask has to be widened past
 * the SHARED bit anyway, so that an aliased address reaches the filter and is
 * refused there rather than being quietly clamped before it arrives.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define TDX_SUCCESS                 0x0000000000000000UL
#define TDG_VP_INFO                 1UL
#define TDG_VP_VMCALL               0UL
#define TDVMCALL_MAP_GPA            0x10001UL

#define PCI_CFG_ADDR                0xcf8
#define PCI_CFG_DATA                0xcfc
#define PCI_VENDOR_EDU              0x1234
#define PCI_DEVICE_EDU              0x11e8
#define PCI_COMMAND                 0x04
#define PCI_COMMAND_MEM             0x02
#define PCI_COMMAND_MASTER          0x04
#define PCI_BAR0                    0x10

#define EDU_DMA_SRC                 0x80
#define EDU_DMA_DST                 0x88
#define EDU_DMA_CNT                 0x90
#define EDU_DMA_CMD                 0x98
#define EDU_DMA_RUN                 0x1
#define EDU_DMA_TO_PCI              0x2
#define EDU_DMA_BUF                 0x40000

#define PTE_FLAGS                   0x067
#define PDE_LARGE_FLAGS             0x0e7
#define PDE_TABLE_FLAGS             0x007
#define PAGE_SIZE                   4096UL
#define LARGE_PAGE_SIZE             (2UL * 1024 * 1024)

#define PATTERN_SHARED              0xa5a5a5a5a5a5a5a5UL
#define PATTERN_PRIVATE             0xbbbbbbbbbbbbbbbbUL

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static void outl(unsigned short port, unsigned int val)
{
    __asm__ __volatile__("outl %0, %w1" : : "a"(val), "d"(port));
}

static unsigned int inl(unsigned short port)
{
    unsigned int val;

    __asm__ __volatile__("inl %w1, %0" : "=a"(val) : "d"(port));
    return val;
}

static unsigned long shared_bit(void)
{
    unsigned long gpaw;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=c"(gpaw)
                         : "a"(TDG_VP_INFO)
                         : "rdx", "r8", "r9", "r10", "r11", "memory");
    return 1UL << ((gpaw & 0x3f) - 1);
}

static unsigned long map_gpa(unsigned long gpa_with_alias)
{
    register unsigned long r10 __asm__("r10") = 0;
    register unsigned long r11 __asm__("r11") = TDVMCALL_MAP_GPA;
    register unsigned long r12 __asm__("r12") = gpa_with_alias;
    register unsigned long r13 __asm__("r13") = PAGE_SIZE;
    unsigned long status;

    __asm__ __volatile__(".byte 0x66,0x0f,0x01,0xcc"
                         : "=a"(status), "+r"(r10), "+r"(r11), "+r"(r12),
                           "+r"(r13)
                         : "a"(TDG_VP_VMCALL), "c"(0xfc00)
                         : "memory");
    return status;
}

/* --- page tables, so the SHARED alias can be mapped ---------------------- */

static unsigned long pml4[512] __attribute__((aligned(4096)));
static unsigned long pdp[512] __attribute__((aligned(4096)));
static unsigned long pd[4][512] __attribute__((aligned(4096)));
static unsigned long pt[512] __attribute__((aligned(4096)));
static unsigned long split_base;

static unsigned long arena[4 * 512] __attribute__((aligned(4096)));

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

/*
 * MMIO is shared to a TD -- there is no private device memory -- so a BAR must
 * be mapped through the SHARED alias too, or the first register access is an
 * EPT violation.  The BAR is covered by a 2MiB identity entry, so the alias
 * goes on that.  Real TD firmware has the same obligation for every device.
 */
static void make_mmio_shared(unsigned long mmio, unsigned long bit)
{
    pd[mmio >> 30][(mmio >> 21) & 0x1ff] |= bit;
    __asm__ __volatile__("mov %%cr3, %%rax\n\tmov %%rax, %%cr3"
                         : : : "rax", "memory");
}

/* Convert a page to shared and map it through the SHARED alias. */
static void make_shared(unsigned long va, unsigned long bit)
{
    map_gpa(va | bit);
    pt[(va - split_base) / PAGE_SIZE] |= bit;
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

/* --- PCI and the device's DMA engine ------------------------------------- */

static unsigned int pci_cfg_read(unsigned int devfn, unsigned int off)
{
    outl(PCI_CFG_ADDR, 0x80000000 | (devfn << 8) | (off & 0xfc));
    return inl(PCI_CFG_DATA);
}

static void pci_cfg_write(unsigned int devfn, unsigned int off,
                          unsigned int val)
{
    outl(PCI_CFG_ADDR, 0x80000000 | (devfn << 8) | (off & 0xfc));
    outl(PCI_CFG_DATA, val);
}

static int find_edu(unsigned int *devfn_out)
{
    unsigned int devfn;

    for (devfn = 0; devfn < 256; devfn++) {
        unsigned int id = pci_cfg_read(devfn, 0);

        if ((id & 0xffff) == PCI_VENDOR_EDU &&
            ((id >> 16) & 0xffff) == PCI_DEVICE_EDU) {
            *devfn_out = devfn;
            return 1;
        }
    }
    return 0;
}

/* volatile: these are MMIO registers, and every access has to reach the bus. */
static volatile unsigned char *edu_bar;

static void edu_write64(unsigned int off, unsigned long val)
{
    *(volatile unsigned long *)(edu_bar + off) = val;
}

static unsigned long edu_read64(unsigned int off)
{
    return *(volatile unsigned long *)(edu_bar + off);
}

static int edu_dma(unsigned long src, unsigned long dst, unsigned long cnt,
                   unsigned long dir)
{
    unsigned long spins = 0;

    edu_write64(EDU_DMA_SRC, src);
    edu_write64(EDU_DMA_DST, dst);
    edu_write64(EDU_DMA_CNT, cnt);
    edu_write64(EDU_DMA_CMD, EDU_DMA_RUN | dir);

    while (edu_read64(EDU_DMA_CMD) & EDU_DMA_RUN) {
        if (++spins > 200000000UL) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    unsigned long shared = shared_bit();
    unsigned int devfn, bar, cmd;
    unsigned long src, res, zero, priv;
    volatile unsigned long *resp;

    ml_printf("Emulated TDX device DMA test (MapGPA, SHARED bit %d)\n",
              (int)__builtin_ctzl(shared));

    if (!find_edu(&devfn)) {
        ml_printf("FAIL: edu device not found\n");
        return 1;
    }
    bar = pci_cfg_read(devfn, PCI_BAR0) & ~0xfU;
    if (!bar) {
        ml_printf("FAIL: edu BAR0 is unassigned\n");
        return 1;
    }
    edu_bar = (volatile unsigned char *)(unsigned long)bar;
    cmd = pci_cfg_read(devfn, PCI_COMMAND);
    pci_cfg_write(devfn, PCI_COMMAND,
                  cmd | PCI_COMMAND_MEM | PCI_COMMAND_MASTER);

    build_tables((unsigned long)arena);
    make_mmio_shared((unsigned long)bar, shared);

    src  = (unsigned long)arena;
    res  = src + PAGE_SIZE;
    zero = src + 2 * PAGE_SIZE;
    priv = src + 3 * PAGE_SIZE;

    /* Fill while everything is still private and accepted. */
    *(volatile unsigned long *)src = PATTERN_SHARED;
    *(volatile unsigned long *)zero = 0;
    *(volatile unsigned long *)priv = PATTERN_PRIVATE;

    /* Convert the three pages the device is allowed to see. */
    make_shared(src, shared);
    make_shared(res, shared);
    make_shared(zero, shared);
    resp = (volatile unsigned long *)res;

    /* A converted page, addressed by its plain GPA, must work. */
    check(edu_dma(src, EDU_DMA_BUF, 8, 0),
          "DMA from a converted page did not complete");
    check(edu_dma(EDU_DMA_BUF, res, 8, EDU_DMA_TO_PCI),
          "DMA back to a converted page did not complete");
    check(*resp == PATTERN_SHARED,
          "device did not read a converted page correctly");

    /* Blank the device buffer so a leftover cannot be mistaken for success. */
    check(edu_dma(zero, EDU_DMA_BUF, 8, 0),
          "DMA of the zero page did not complete");
    *resp = PATTERN_SHARED;
    check(edu_dma(EDU_DMA_BUF, res, 8, EDU_DMA_TO_PCI),
          "DMA of the blanked buffer did not complete");
    check(*resp == 0, "device buffer was not blanked");

    /* Private memory, addressed privately: refused. */
    check(edu_dma(priv, EDU_DMA_BUF, 8, 0), "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, res, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*resp != PATTERN_PRIVATE, "device read TD-private memory");

    /*
     * A page that was never converted, addressed through the alias: refused.
     * Setting the bit is not the same as doing the work.
     */
    check(edu_dma(priv | shared, EDU_DMA_BUF, 8, 0),
          "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, res, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*resp != PATTERN_PRIVATE,
          "device read a page addressed through the SHARED alias");

    /*
     * And the case that distinguishes this model from one that keys off the
     * address bit: a page the TD really did convert, addressed through the
     * alias anyway.  The conversion is not what makes this wrong -- carrying
     * the alias into a DMA address is, because no VMM resolves one.  It must
     * be refused just as firmly as the unconverted page above.
     */
    *resp = PATTERN_PRIVATE;
    check(edu_dma(src | shared, EDU_DMA_BUF, 8, 0),
          "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, res, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*resp != PATTERN_SHARED,
          "device honoured a SHARED alias in a DMA address");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All TDX DMA checks passed (refused read gave 0x%lx)\n",
              *resp);
    return 0;
}
