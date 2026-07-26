/*
 * Emulated AMD SEV-SNP device DMA test.
 *
 * An SNP guest's private memory is unreachable by the host, so a device may
 * only DMA to pages the guest has shared.  There is no shared address bit to
 * check -- sharing is an RMP attribute -- so the filter has to consult page
 * state, and this test drives it from both sides.
 *
 * The vehicle is the "edu" test device, whose DMA engine is programmable
 * straight from MMIO: point it at a guest address, tell it to run, and it calls
 * pci_dma_read() on the guest's behalf.  That is exactly the path a virtio ring
 * fetch takes, without needing a virtio driver.
 *
 * Run in lazy mode, so pages are shared until claimed and the test's own memory
 * keeps working, with the one page under test explicitly moved to private.
 * Port I/O is relaxed: PCI configuration space is reached through 0xcf8/0xcfc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_PSC_REQ        0x014
#define PSC_OP_PRIVATE          1

#define PCI_CFG_ADDR            0xcf8
#define PCI_CFG_DATA            0xcfc
#define PCI_VENDOR_EDU          0x1234
#define PCI_DEVICE_EDU          0x11e8
#define PCI_COMMAND             0x04
#define PCI_COMMAND_MEM         0x02
#define PCI_COMMAND_MASTER      0x04
#define PCI_BAR0                0x10

/* edu registers, within BAR0. */
#define EDU_DMA_SRC             0x80
#define EDU_DMA_DST             0x88
#define EDU_DMA_CNT             0x90
#define EDU_DMA_CMD             0x98
#define EDU_DMA_RUN             0x1
#define EDU_DMA_TO_PCI          0x2     /* device buffer -> guest memory */
#define EDU_DMA_BUF             0x40000 /* device-buffer address space */

#define PATTERN_SHARED          0xa5a5a5a5a5a5a5a5UL
#define PATTERN_PRIVATE         0xbbbbbbbbbbbbbbbbUL

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

static unsigned int pvalidate(unsigned long gva, unsigned int validate)
{
    unsigned int status;

    __asm__ __volatile__(".byte 0xf2,0x0f,0x01,0xff"
                         : "=a"(status)
                         : "a"(gva), "c"(0), "d"(validate)
                         : "cc", "memory");
    return status;
}

static void psc_private(unsigned long gpa)
{
    wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_PSC_REQ |
          ((unsigned long)PSC_OP_PRIVATE << 56) | (gpa & ~0xfffUL));
    vmgexit();
    wrmsr(MSR_AMD64_SEV_ES_GHCB, 0);
}

/* --- PCI configuration space, through the legacy ports ------------------- */

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

/* --- the device's DMA engine --------------------------------------------- */

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

/*
 * The engine runs off a 100ms virtual-clock timer and clears RUN when done.
 * Virtual time advances while the guest executes, so a bounded poll is enough.
 */
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

static unsigned long page_shared[512] __attribute__((aligned(4096)));
static unsigned long page_private[512] __attribute__((aligned(4096)));
static unsigned long page_zero[512] __attribute__((aligned(4096)));
static unsigned long page_result[512] __attribute__((aligned(4096)));

int main(void)
{
    unsigned int devfn, bar, cmd;

    ml_printf("Emulated SEV-SNP device DMA test\n");

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

    /* Memory space and bus mastering, without which nothing DMAs at all. */
    cmd = pci_cfg_read(devfn, PCI_COMMAND);
    pci_cfg_write(devfn, PCI_COMMAND,
                  cmd | PCI_COMMAND_MEM | PCI_COMMAND_MASTER);

    page_shared[0] = PATTERN_SHARED;
    page_private[0] = PATTERN_PRIVATE;
    page_zero[0] = 0;
    page_result[0] = 0;

    /*
     * Claim the private page.  This is also what arms the filter, so every DMA
     * below is judged.  Nothing may touch page_private from the CPU after this:
     * the page tables say C=0 and the page is now private, which is a mismatch.
     */
    psc_private((unsigned long)page_private);
    check(pvalidate((unsigned long)page_private, 1) == 0,
          "PVALIDATE of the claimed page failed");

    /* A shared page must still be reachable by the device. */
    check(edu_dma((unsigned long)page_shared, EDU_DMA_BUF, 8, 0),
          "DMA from a shared page did not complete");
    check(edu_dma(EDU_DMA_BUF, (unsigned long)page_result, 8, EDU_DMA_TO_PCI),
          "DMA back to a shared page did not complete");
    check(page_result[0] == PATTERN_SHARED,
          "device did not read a shared page correctly");

    /* Blank the device buffer so the next result cannot be a leftover. */
    check(edu_dma((unsigned long)page_zero, EDU_DMA_BUF, 8, 0),
          "DMA of the zero page did not complete");
    page_result[0] = PATTERN_SHARED;
    check(edu_dma(EDU_DMA_BUF, (unsigned long)page_result, 8, EDU_DMA_TO_PCI),
          "DMA of the blanked buffer did not complete");
    check(page_result[0] == 0, "device buffer was not blanked");

    /*
     * And now the point of the whole exercise: the same device reading a page
     * the guest has kept private must come away with nothing.
     */
    check(edu_dma((unsigned long)page_private, EDU_DMA_BUF, 8, 0),
          "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, (unsigned long)page_result, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer after a denied read did not complete");
    check(page_result[0] != PATTERN_PRIVATE,
          "device read guest-private memory");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP DMA checks passed (private read returned 0x%lx)\n",
              page_result[0]);
    return 0;
}
