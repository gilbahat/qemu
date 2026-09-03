/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA page-state test.
 *
 * A Realm's protected memory is RAM until the guest hands a range back with
 * RSI_IPA_STATE_SET(EMPTY), which is how it makes room to use the unprotected
 * alias of those pages for rings and buffers a device must also see.  Two
 * things have to be true afterwards, and they are the two halves of the same
 * promise:
 *
 *   - the alias reaches that memory;
 *   - the protected view no longer does.
 *
 * The second is what an emulation is prone to get wrong, because letting it
 * keep working costs nothing and looks like success.  Run with
 * -cpu max,x-cca-guest=on,x-cca-ripas=1.
 *
 * This test turns stage-1 translation off first.  That is not a trick to
 * reach the alias: it is how a Realm actually runs, and the harness maps
 * virtual onto physical one-to-one, so nothing moves when the MMU goes away.
 */

#include <stdint.h>
#include <minilib.h>
#include "boot.h"

#define RSI_ABI_VERSION             0xc4000190UL
#define RSI_REALM_CONFIG            0xc4000196UL
#define RSI_IPA_STATE_SET           0xc4000197UL
#define RSI_IPA_STATE_GET           0xc4000198UL

#define RSI_SUCCESS                 0UL
#define RSI_ERROR_INPUT             1UL
#define RSI_ABI_VERSION_1_0         (1UL << 16)
#define RSI_RIPAS_EMPTY             0UL
#define RSI_RIPAS_RAM               1UL
#define RSI_NO_CHANGE_DESTROYED     1UL

/* What the EL1 logging vector table records for a data abort. */
#define FAULT_DATA_ABORT            0x1001UL

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

/*
 * The results are stored through @out rather than returned by value.  A
 * 32-byte struct comes back through an indirect pointer, and at -O0 the
 * compiler is free to use one of the very registers the SMC returns in while
 * arranging that -- which silently loses x1.
 */
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

/* Did the last access fault, and at the address we expected? */
static int faulted_at(uint64_t addr)
{
    return exception_type_code == FAULT_DATA_ABORT &&
           exception_fault_address == addr;
}

static void clear_fault(void)
{
    exception_type_code = 0;
    exception_fault_address = 0;
}

static uint8_t given_back[4096] __attribute__((aligned(4096)));
static uint8_t kept[4096] __attribute__((aligned(4096)));
/* Two adjacent granules, so a query can be made to stop in the middle. */
static uint8_t window[8192] __attribute__((aligned(4096)));

int main(void)
{
    struct smc_res r;
    uint64_t ipa_bits, shared_mask, base, top;
    volatile uint64_t *p;

    ml_printf("Emulated Arm CCA page-state test\n");

    rsi(&r, RSI_ABI_VERSION, RSI_ABI_VERSION_1_0, 0, 0, 0);
    if (r.a0 != RSI_SUCCESS) {
        ml_printf("FAIL: no RSI here -- was x-cca-guest=on given?\n");
        return 1;
    }

    *(volatile uint64_t *)given_back = 0;
    rsi(&r, RSI_REALM_CONFIG, (uint64_t)given_back, 0, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_REALM_CONFIG status");
    ipa_bits = *(volatile uint64_t *)given_back;
    shared_mask = 1UL << (ipa_bits - 1);
    ml_printf("IPA width %d, shared bit 0x%lx\n", (int)ipa_bits, shared_mask);

    /* Write a marker while the page is still ours to touch. */
    *(volatile uint64_t *)given_back = 0x5cca5cca5cca5ccaUL;
    *(volatile uint64_t *)kept = 0x1234567812345678UL;

    mmu_off();
    ml_printf("running with stage-1 translation off\n");

    /* Still reachable: nothing has been handed back yet. */
    clear_fault();
    p = (volatile uint64_t *)given_back;
    check(*p == 0x5cca5cca5cca5ccaUL && !faulted_at((uint64_t)given_back),
          "a page that was never handed back is not reachable");

    /* Hand it back. */
    base = (uint64_t)given_back;
    top = base + sizeof(given_back);
    rsi(&r, RSI_IPA_STATE_SET, base, top, RSI_RIPAS_EMPTY,
            RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET status");
    check(r.a1 == top, "RSI_IPA_STATE_SET did not cover the range");

    /* The alias now reaches it, and it is the same memory. */
    clear_fault();
    p = (volatile uint64_t *)(base | shared_mask);
    check(*p == 0x5cca5cca5cca5ccaUL,
          "the unprotected alias is not the same memory");
    check(!faulted_at(base | shared_mask), "the alias faulted");
    *p = 0xa5a5a5a5a5a5a5a5UL;

    /* And the protected view no longer does. */
    clear_fault();
    p = (volatile uint64_t *)base;
    (void)*p;
    check(faulted_at(base),
          "the protected view still reaches a page that was handed back");

    /* A page never handed back is untouched by any of this. */
    clear_fault();
    p = (volatile uint64_t *)kept;
    check(*p == 0x1234567812345678UL && !faulted_at((uint64_t)kept),
          "handing one page back disturbed another");

    /*
     * RSI_IPA_STATE_GET reads the state back, which is how a guest discovers
     * what it was given rather than trusting what it asked for.
     */
    rsi(&r, RSI_IPA_STATE_GET, base, top, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_GET status");
    check(r.a2 == RSI_RIPAS_EMPTY,
          "RSI_IPA_STATE_GET did not report the page as handed back");
    check(r.a1 == top, "RSI_IPA_STATE_GET stopped short of the range");

    rsi(&r, RSI_IPA_STATE_GET, (uint64_t)kept, (uint64_t)kept + sizeof(kept),
        0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_GET status for an untouched page");
    check(r.a2 == RSI_RIPAS_RAM,
          "a page never handed back is not reported as RAM");

    /*
     * The reply is a run, not the whole range: hand back the first of two
     * adjacent granules and the answer must stop at the boundary rather than
     * describe the second one too.  A guest that read the top as "the range
     * you asked about" would mistake the second granule for relinquished.
     */
    rsi(&r, RSI_IPA_STATE_SET, (uint64_t)window, (uint64_t)window + 4096,
            RSI_RIPAS_EMPTY, RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET status for the window");

    rsi(&r, RSI_IPA_STATE_GET, (uint64_t)window, (uint64_t)window + 8192, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_GET status for the window");
    check(r.a2 == RSI_RIPAS_EMPTY, "the window's first granule is not EMPTY");
    check(r.a1 == (uint64_t)window + 4096,
          "RSI_IPA_STATE_GET ran past the change of state");

    rsi(&r, RSI_IPA_STATE_GET, (uint64_t)window + 4096,
        (uint64_t)window + 8192, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_GET status past the boundary");
    check(r.a2 == RSI_RIPAS_RAM, "the window's second granule is not RAM");

    /* Refused the same way the setter refuses them. */
    rsi(&r, RSI_IPA_STATE_GET, base + 1, top, 0, 0);
    check(r.a0 == RSI_ERROR_INPUT, "misaligned RSI_IPA_STATE_GET was accepted");
    rsi(&r, RSI_IPA_STATE_GET, top, base, 0, 0);
    check(r.a0 == RSI_ERROR_INPUT, "inverted RSI_IPA_STATE_GET was accepted");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA page-state checks passed\n");
    return 0;
}
