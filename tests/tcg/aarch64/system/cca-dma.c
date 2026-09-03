/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA device DMA test.
 *
 * A device may only reach memory the Realm has handed back with
 * RSI_IPA_STATE_SET, and it must be given the plain IPA of that memory rather
 * than the unprotected alias the Realm uses to reach it itself.  Both halves
 * are checked, because each has a way of looking like success: memory the
 * Realm still owns is readable to an emulator that does not care, and an
 * aliased descriptor address is accepted by a launcher that folds the bit away
 * in its own userspace before vhost ever sees it.
 *
 * The vehicle is the "edu" test device, whose DMA engine is programmable from
 * MMIO and does the transfer on the guest's behalf -- the same path a virtio
 * ring fetch takes, with no driver needed.  Its dma_mask has to be widened
 * past the alias bit, or an aliased address is clamped before the filter sees
 * it and the interesting case never arrives.
 *
 * Run with -cpu max,x-cca-guest=on,x-cca-ripas=1 -device edu,dma_mask=...
 */

#include <stdint.h>
#include <minilib.h>
#include "boot.h"

#define RSI_ABI_VERSION             0xc4000190UL
#define RSI_REALM_CONFIG            0xc4000196UL
#define RSI_IPA_STATE_SET           0xc4000197UL

#define RSI_SUCCESS                 0UL
#define RSI_ABI_VERSION_1_0         (1UL << 16)
#define RSI_RIPAS_EMPTY             0UL
#define RSI_NO_CHANGE_DESTROYED     1UL

/* virt's ECAM window and the first 32-bit MMIO window. */
#define ECAM_BASE                   0x3f000000UL
#define PCI_VENDOR_EDU              0x1234
#define PCI_DEVICE_EDU              0x11e8
#define PCI_COMMAND                 0x04
#define PCI_COMMAND_MEM             0x02
#define PCI_COMMAND_MASTER          0x04
#define PCI_BAR0                    0x10
#define PCI_MMIO_BASE               0x10000000UL

#define EDU_DMA_SRC                 0x80
#define EDU_DMA_DST                 0x88
#define EDU_DMA_CNT                 0x90
#define EDU_DMA_CMD                 0x98
#define EDU_DMA_RUN                 0x1
#define EDU_DMA_TO_PCI              0x2
#define EDU_DMA_BUF                 0x40000

#define PATTERN_SHARED              0x5cca5cca5cca5ccaUL
#define PATTERN_OWNED               0xbbbbbbbbbbbbbbbbUL

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

struct smc_res {
    uint64_t a0, a1, a2, a3;
};

static void rsi(struct smc_res *out, uint64_t f, uint64_t a1, uint64_t a2,
                uint64_t a3, uint64_t a4)
{
    register uint64_t x0 __asm__("x0") = f;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;

    __asm__ __volatile__("smc #0"
                         : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
                         : : "memory");
    out->a0 = x0;
    out->a1 = x1;
    out->a2 = x2;
    out->a3 = x3;
}

static void mmu_off(void)
{
    uint64_t sctlr;

    __asm__ __volatile__("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr &= ~1UL;                                  /* SCTLR_EL1.M */
    __asm__ __volatile__("msr sctlr_el1, %0\n\t"
                         "isb\n\t" : : "r"(sctlr) : "memory");
}

static volatile uint8_t *edu_bar;
static uint64_t shared_mask;

static uint32_t ecam_read(unsigned devfn, unsigned off)
{
    volatile uint32_t *p =
        (volatile uint32_t *)(ECAM_BASE + (devfn << 12) + (off & 0xfc));
    return *p;
}

static void ecam_write(unsigned devfn, unsigned off, uint32_t val)
{
    volatile uint32_t *p =
        (volatile uint32_t *)(ECAM_BASE + (devfn << 12) + (off & 0xfc));
    *p = val;
}

static void edu_put(unsigned off, uint64_t val)
{
    *(volatile uint64_t *)(edu_bar + off) = val;
}

static uint64_t edu_get(unsigned off)
{
    return *(volatile uint64_t *)(edu_bar + off);
}

/* Run one transfer and wait for the engine to drop the run bit. */
static int edu_dma(uint64_t src, uint64_t dst, uint64_t len, uint64_t dir)
{
    unsigned spins = 0;

    edu_put(EDU_DMA_SRC, src);
    edu_put(EDU_DMA_DST, dst);
    edu_put(EDU_DMA_CNT, len);
    edu_put(EDU_DMA_CMD, EDU_DMA_RUN | dir);

    while (edu_get(EDU_DMA_CMD) & EDU_DMA_RUN) {
        if (++spins > (1u << 24)) {
            return 0;
        }
    }
    return 1;
}

static int find_edu(unsigned *devfn_out)
{
    for (unsigned devfn = 0; devfn < 256; devfn++) {
        uint32_t id = ecam_read(devfn, 0);

        if ((id & 0xffff) == PCI_VENDOR_EDU &&
            (id >> 16) == PCI_DEVICE_EDU) {
            *devfn_out = devfn;
            return 1;
        }
    }
    return 0;
}

/*
 * The PL011's PeriphID0-3, at a fixed address on every virt board.  Each is a
 * 32-bit register holding one byte, so eight bytes read back as two of them:
 * 0x11 then 0x10.
 */
#define PL011_PERIPH_ID         0x09000fe0UL
#define PL011_PERIPH_ID_VALUE   0x0000001000000011UL

static uint8_t handed_back[4096] __attribute__((aligned(4096)));
static uint8_t still_ours[4096] __attribute__((aligned(4096)));
static uint8_t result[4096] __attribute__((aligned(4096)));

int main(void)
{
    struct smc_res r;
    uint64_t ipa_bits, base;
    unsigned devfn;
    uint32_t bar, cmd;
    volatile uint64_t *res;

    ml_printf("Emulated Arm CCA device DMA test\n");

    rsi(&r, RSI_ABI_VERSION, RSI_ABI_VERSION_1_0, 0, 0, 0);
    if (r.a0 != RSI_SUCCESS) {
        ml_printf("FAIL: no RSI here -- was x-cca-guest=on given?\n");
        return 1;
    }

    *(volatile uint64_t *)result = 0;
    rsi(&r, RSI_REALM_CONFIG, (uint64_t)result, 0, 0, 0);
    ipa_bits = *(volatile uint64_t *)result;
    shared_mask = 1UL << (ipa_bits - 1);

    /*
     * A Realm runs with stage-1 translation off, and so must this: the
     * harness maps only the block holding RAM, so ECAM and the device BAR
     * are not otherwise reachable.
     */
    mmu_off();

    if (!find_edu(&devfn)) {
        ml_printf("FAIL: edu device not found\n");
        return 1;
    }
    /*
     * Nothing has assigned BARs: booting with -kernel there is no firmware to
     * enumerate the bus, so place it ourselves in the 32-bit MMIO window.
     */
    ecam_write(devfn, PCI_BAR0, PCI_MMIO_BASE);
    bar = ecam_read(devfn, PCI_BAR0) & ~0xfU;
    if (bar != PCI_MMIO_BASE) {
        ml_printf("FAIL: edu BAR0 did not take the address we gave it\n");
        return 1;
    }
    edu_bar = (volatile uint8_t *)(uint64_t)bar;
    cmd = ecam_read(devfn, PCI_COMMAND);
    ecam_write(devfn, PCI_COMMAND, cmd | PCI_COMMAND_MEM | PCI_COMMAND_MASTER);

    /* Fill both pages while they are still ours to write. */
    *(volatile uint64_t *)handed_back = PATTERN_SHARED;
    *(volatile uint64_t *)still_ours = PATTERN_OWNED;
    *(volatile uint64_t *)result = 0;

    /* Hand one of them back, and the result page the device writes into. */
    base = (uint64_t)handed_back;
    rsi(&r, RSI_IPA_STATE_SET, base, base + sizeof(handed_back),
        RSI_RIPAS_EMPTY, RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET on the shared page");
    rsi(&r, RSI_IPA_STATE_SET, (uint64_t)result,
        (uint64_t)result + sizeof(result), RSI_RIPAS_EMPTY,
        RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET on the result page");

    res = (volatile uint64_t *)((uint64_t)result | shared_mask);

    /* A page the Realm handed back, addressed plainly: this must work. */
    check(edu_dma((uint64_t)handed_back, EDU_DMA_BUF, 8, 0),
          "DMA from a handed-back page did not complete");
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA back to a handed-back page did not complete");
    check(*res == PATTERN_SHARED, "the device did not read a handed-back page");

    /* Blank the device buffer so a leftover cannot be read as success. */
    *res = 0;
    check(edu_dma((uint64_t)result, EDU_DMA_BUF, 8, 0),
          "DMA of the blanking write did not complete");

    /* Memory the Realm still owns: the device must come away with nothing. */
    check(edu_dma((uint64_t)still_ours, EDU_DMA_BUF, 8, 0),
          "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*res != PATTERN_OWNED, "the device read memory the Realm still owns");

    /*
     * And the address the guest hands over: with x-cca-dma=plain the alias is
     * refused, because a launcher that registers Realm memory once at the
     * protected IPA resolves it to nothing and moves no data silently.
     */
    *res = 0;
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA of the blanking write did not complete");
    check(edu_dma(base | shared_mask, EDU_DMA_BUF, 8, 0),
          "denied DMA did not complete");
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*res != PATTERN_SHARED,
          "the device honoured an aliased descriptor address");

    /*
     * A device reaching another device is not the host reaching into Realm
     * memory, and only RAM has a page state at all.  Judging MMIO by the
     * page-state map denies every one of these, because a model that records
     * what a guest gave back calls everything else still the guest's -- and on
     * this board the first thing that would be denied is an MSI, which is a
     * write to the GIC.
     *
     * Read the PL011's peripheral identification registers, which every virt
     * board has at a fixed address and which read back a known value.  Nothing
     * relinquished them, so before this was distinguished the transfer moved
     * nothing at all.
     */
    *res = 0;
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA of the blanking write did not complete");
    check(edu_dma(PL011_PERIPH_ID, EDU_DMA_BUF, 8, 0),
          "DMA from device memory did not complete");
    check(edu_dma(EDU_DMA_BUF, (uint64_t)result, 8, EDU_DMA_TO_PCI),
          "DMA of the buffer did not complete");
    check(*res == PL011_PERIPH_ID_VALUE,
          "a device could not reach another device's registers");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA device DMA checks passed\n");
    return 0;
}
