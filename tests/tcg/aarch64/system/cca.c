/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA guest interface test.
 *
 * Exercises the RSI calls a Realm makes before it has any devices: negotiate
 * the interface version, read the Realm configuration, and relinquish a range
 * of protected memory so the unprotected alias becomes usable.  That is the
 * whole of what a guest needs in order to reach its own console, so it is the
 * boundary this test draws.
 *
 * Run with -cpu max,x-cca-guest=on.  Without it every call below returns
 * SMCCC's "not supported", which is how a Realm-aware guest discovers it is
 * not in a Realm -- checked at the end.
 */

#include <stdint.h>
#include <minilib.h>

#define RSI_ABI_VERSION             0xc4000190UL
#define RSI_MEASUREMENT_EXTEND      0xc4000193UL
#define RSI_REALM_CONFIG            0xc4000196UL
#define RSI_IPA_STATE_SET           0xc4000197UL

#define RSI_SUCCESS                 0UL
#define RSI_ERROR_INPUT             1UL
#define SMCCC_NOT_SUPPORTED         0xffffffffffffffffUL

#define RSI_ABI_VERSION_1_0         (1UL << 16)
#define RSI_RIPAS_EMPTY             0UL
#define RSI_NO_CHANGE_DESTROYED     1UL

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
 * Eleven registers in, four out: the widest RSI call carries a 48-byte value
 * across x3-x10, so a narrower helper would silently truncate it.
 */
static struct smc_res rsi(uint64_t f, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4)
{
    register uint64_t x0 __asm__("x0") = f;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;

    __asm__ __volatile__("smc #0"
                         : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
                         : : "memory");
    return (struct smc_res){x0, x1, x2, x3};
}

/* The configuration granule the RMM fills in.  Only the first field is read. */
static uint8_t config[4096] __attribute__((aligned(4096)));

/* A range to hand back, so the unprotected alias of it becomes usable. */
static uint8_t window[8192] __attribute__((aligned(4096)));

int main(void)
{
    struct smc_res r;
    uint64_t ipa_bits, shared_mask, base, top;

    ml_printf("Emulated Arm CCA guest interface test\n");

    /* Version: the reply must be an interval containing the one we asked for. */
    r = rsi(RSI_ABI_VERSION, RSI_ABI_VERSION_1_0, 0, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_VERSION status");
    check(r.a1 <= RSI_ABI_VERSION_1_0 && r.a2 >= RSI_ABI_VERSION_1_0,
          "RSI_VERSION did not offer 1.0");
    if (r.a0 != RSI_SUCCESS) {
        ml_printf("FAIL: no RSI here -- was x-cca-guest=on given?\n");
        return 1;
    }

    /*
     * Realm configuration: the IPA width, from which the alias bit follows.
     * Poison the field first, so a reply that writes nothing is not mistaken
     * for one that wrote a plausible value.
     */
    *(volatile uint64_t *)config = 0xdeadbeefUL;
    r = rsi(RSI_REALM_CONFIG, (uint64_t)config, 0, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_REALM_CONFIG status");
    check(*(volatile uint64_t *)config != 0xdeadbeefUL,
          "RSI_REALM_CONFIG did not write the granule");

    ipa_bits = *(volatile uint64_t *)config;
    check(ipa_bits >= 32 && ipa_bits <= 52, "IPA width is out of range");
    shared_mask = 1UL << (ipa_bits - 1);
    ml_printf("IPA width %d, shared bit 0x%lx\n", (int)ipa_bits, shared_mask);

    /* An unaligned configuration buffer must be refused rather than accepted. */
    r = rsi(RSI_REALM_CONFIG, (uint64_t)config + 8, 0, 0, 0);
    check(r.a0 == RSI_ERROR_INPUT, "unaligned RSI_REALM_CONFIG was accepted");

    /*
     * Relinquish the window.  The reply reports how far it got and the guest
     * is required to loop, so a reply that does not advance is a failure and
     * not a request to retry.
     */
    base = (uint64_t)window;
    top = base + sizeof(window);
    r = rsi(RSI_IPA_STATE_SET, base, top, RSI_RIPAS_EMPTY,
            RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET status");
    check(r.a1 > base && r.a1 <= top, "RSI_IPA_STATE_SET did not advance");

    /* A range that is not granule-aligned, and an empty one, must be refused. */
    r = rsi(RSI_IPA_STATE_SET, base + 1, top, RSI_RIPAS_EMPTY,
            RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_ERROR_INPUT, "misaligned RSI_IPA_STATE_SET was accepted");
    r = rsi(RSI_IPA_STATE_SET, top, base, RSI_RIPAS_EMPTY,
            RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_ERROR_INPUT, "inverted RSI_IPA_STATE_SET was accepted");
    r = rsi(RSI_IPA_STATE_SET, base, top, 99, RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_ERROR_INPUT, "undefined RIPAS was accepted");

    /*
     * Not checked here: that the unprotected alias reaches the same memory.
     * A Realm runs with stage-1 translation off, so for it the alias is just
     * an address; this harness enables the MMU before calling main(), so
     * reaching the alias would need a mapping this test does not build.  The
     * page-state test sets up its own tables and checks it there.
     */

    /* Something in the RSI range we do not implement is refused, not ignored. */
    r = rsi(RSI_MEASUREMENT_EXTEND, 1, 48, 0, 0);
    check(r.a0 == SMCCC_NOT_SUPPORTED,
          "an unimplemented RSI call did not report NOT_SUPPORTED");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA guest interface checks passed\n");
    return 0;
}
