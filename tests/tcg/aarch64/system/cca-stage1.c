/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA page states, reached through stage-1 translation.
 *
 * cca-ripas.c turns the MMU off and reaches the unprotected alias by naming
 * it directly.  That is one of the two ways a Realm runs and it is the simpler
 * one to write, but it is not the interesting one for this emulation: with
 * translation off, the address the guest emits is the address the alias fold
 * and the page-state check see, so nothing sits between the guest and the code
 * under test.
 *
 * A Realm with page tables reaches shared memory the other way -- through an
 * entry whose *output* address carries the alias bit, at some input address
 * that does not.  The fold and the check live in get_phys_addr_gpc(), which
 * runs on the output of stage 1, so that is a different route into them and it
 * is the route a real guest takes: Solo5's cca binding turns translation on
 * before it does anything else.
 *
 * So this leaves the harness's MMU on and installs one block of its own,
 * mapping a spare input address onto the alias of a page it owns. Everything
 * else is the identity map the harness built.
 *
 * Run with -cpu max,x-cca-guest=on,x-cca-ripas=1.
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

#define BLOCK_2M                    (1UL << 21)
#define BLOCK_1G                    (1UL << 30)

/* A level-2 block: valid block, access flag, never executable. */
#define PTE_BLOCK_NX                ((3UL << 53) | 0x401UL)

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

/*
 * Install a level-2 block mapping @va onto @oa, in the harness's own table.
 *
 * Both have to sit in the 1GB region that table covers, which is the one this
 * code is running in -- for @va because that is the only table there is, and
 * for @oa because a block's output is 2MB-aligned and the page being aliased
 * is one of this image's own.
 */
static void map_block(uint64_t va, uint64_t oa)
{
    unsigned idx = (unsigned)((va >> 21) & 0x1ff);

    ttb_stage2[idx] = oa | PTE_BLOCK_NX;
    __asm__ __volatile__("dsb ishst\n"
                         "tlbi vmalle1\n"
                         "dsb ish\n"
                         "isb\n" : : : "memory");
}

/* Find a 2MB slot the harness left empty, so nothing already there moves. */
static int free_block_index(void)
{
    for (unsigned i = 0; i < 512; i++) {
        if (ttb_stage2[i] == 0) {
            return (int)i;
        }
    }
    return -1;
}

static uint8_t given_back[4096] __attribute__((aligned(4096)));
static uint8_t kept[4096] __attribute__((aligned(4096)));

int main(void)
{
    struct smc_res r;
    uint64_t ipa_bits, shared_mask, base, top, region, alias_va, alias_kept_va;
    /*
     * Volatile throughout: the loads and stores below are the thing under
     * test, not a means to a value. One that the compiler folded away, or
     * moved across the RSI call that changes the page's state, would test
     * nothing and still pass.
     */
    volatile uint64_t *p;
    int idx;

    ml_printf("Emulated Arm CCA stage-1 page-state test\n");

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
    check(ipa_bits >= 32 && ipa_bits <= 52, "IPA width is out of range");

    /*
     * The alias bit is above the harness's 39-bit input range, which is the
     * point: it can only appear in an output address here, which is where a
     * Realm with page tables puts it too.
     */
    region = (uint64_t)given_back & ~(BLOCK_1G - 1);

    idx = free_block_index();
    check(idx >= 0, "the harness left no spare 2MB block to map");
    if (idx < 0) {
        return 1;
    }
    alias_va = region + (uint64_t)idx * BLOCK_2M;
    map_block(alias_va, ((uint64_t)given_back & ~(BLOCK_2M - 1)) | shared_mask);
    alias_va += (uint64_t)given_back & (BLOCK_2M - 1);

    /* Write a marker while the page is still ours to touch, and check it. */
    *(volatile uint64_t *)given_back = 0x5cca5cca5cca5ccaUL;
    *(volatile uint64_t *)kept = 0x1234567812345678UL;

    /*
     * Hand the page back, and reach it through the mapping whose output
     * carries the alias. Same memory, so the fold happened on the output of
     * stage 1 rather than on what the guest wrote.
     */
    base = (uint64_t)given_back;
    top = base + sizeof(given_back);
    rsi(&r, RSI_IPA_STATE_SET, base, top, RSI_RIPAS_EMPTY,
            RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET status");

    clear_fault();
    p = (volatile uint64_t *)alias_va;
    check(*p == 0x5cca5cca5cca5ccaUL,
          "the alias of a translated address is not the same memory");
    check(!faulted_at(alias_va), "the alias faulted");

    /* And it is writable through that route. */
    *p = 0xa5a5a5a5a5a5a5a5UL;
    clear_fault();
    check(*p == 0xa5a5a5a5a5a5a5a5UL, "a write through the alias was lost");

    /*
     * The protected view is a different input address with no alias bit in its
     * output, and the Realm gave that granule up, so it must now fault. The
     * fault is reported at the input address, which is what the guest asked
     * for -- the output is not something it can see.
     */
    clear_fault();
    p = (volatile uint64_t *)base;
    (void)*p;
    check(faulted_at(base),
          "the protected view still reaches a page that was handed back");

    /* A page never handed back is reachable through both views. */
    clear_fault();
    p = (volatile uint64_t *)kept;
    check(*p == 0x1234567812345678UL && !faulted_at((uint64_t)kept),
          "handing one page back disturbed another");

    idx = free_block_index();
    check(idx >= 0, "no second spare block");
    if (idx >= 0) {
        alias_kept_va = region + (uint64_t)idx * BLOCK_2M;
        map_block(alias_kept_va, ((uint64_t)kept & ~(BLOCK_2M - 1)) |
                                 shared_mask);
        alias_kept_va += (uint64_t)kept & (BLOCK_2M - 1);

        /*
         * In lazy mode the alias of a page that was never handed back is
         * still folded to the same memory. That is deliberate -- a guest may
         * legitimately address the alias of a window it never owned -- and it
         * is what x-cca-ripas=2 exists to refuse.
         */
        clear_fault();
        p = (volatile uint64_t *)alias_kept_va;
        check(*p == 0x1234567812345678UL && !faulted_at(alias_kept_va),
              "the alias of a page that was never handed back did not fold");
    }

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA stage-1 page-state checks passed\n");
    return 0;
}
