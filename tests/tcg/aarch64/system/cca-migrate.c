/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA state across a migration.
 *
 * Everything the Realm interface remembers is Realm-scoped rather than
 * per-vCPU, so none of it lives in CPU state and none of it migrates for free:
 * the page-state map, the measurements, and a token part-way through being
 * handed over. A Realm that lost any of them across a snapshot would carry on
 * as though nothing had happened, which is the failure worth catching -- a REM
 * that quietly resets changes the attestation of a running Realm, and page
 * states that reset make the alias the guest has been using since start to
 * fault.
 *
 * So this sets all three, spins long enough for a migration to be started
 * underneath it, and only then checks. Run on its own it is a control: the
 * checks pass because nothing moved. Run with the VM migrated during the spin,
 * the checks run on the destination and are the actual test.
 *
 * Run with -cpu max,x-cca-guest=on,x-cca-ripas=1.
 */

#include <stdint.h>
#include <minilib.h>

#define RSI_ABI_VERSION             0xc4000190UL
#define RSI_MEASUREMENT_READ        0xc4000192UL
#define RSI_MEASUREMENT_EXTEND      0xc4000193UL
#define RSI_ATTESTATION_TOKEN_INIT  0xc4000194UL
#define RSI_ATTESTATION_TOKEN_CONT  0xc4000195UL
#define RSI_REALM_CONFIG            0xc4000196UL
#define RSI_IPA_STATE_SET           0xc4000197UL
#define RSI_IPA_STATE_GET           0xc4000198UL

#define RSI_SUCCESS                 0UL
#define RSI_INCOMPLETE              3UL
#define RSI_ABI_VERSION_1_0         (1UL << 16)
#define RSI_RIPAS_EMPTY             0UL
#define RSI_NO_CHANGE_DESTROYED     1UL

#define MEASUREMENT_LEN             64
#define HASH_LEN                    32
#define GRANULE                     4096

/*
 * Long enough that a migration started from outside lands inside it, short
 * enough to be an ordinary test when nothing does. The loop is over a volatile
 * counter so it cannot be optimised away.
 */
#define SPIN_ITERATIONS             600000000UL

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

struct smc_res {
    uint64_t a0, a1, a2, a3, a4, a5, a6, a7, a8;
};

static void rsi(struct smc_res *out, const uint64_t *in)
{
    register uint64_t x0 __asm__("x0") = in[0];
    register uint64_t x1 __asm__("x1") = in[1];
    register uint64_t x2 __asm__("x2") = in[2];
    register uint64_t x3 __asm__("x3") = in[3];
    register uint64_t x4 __asm__("x4") = in[4];
    register uint64_t x5 __asm__("x5") = in[5];
    register uint64_t x6 __asm__("x6") = in[6];
    register uint64_t x7 __asm__("x7") = in[7];
    register uint64_t x8 __asm__("x8") = in[8];
    register uint64_t x9 __asm__("x9") = in[9];
    register uint64_t x10 __asm__("x10") = in[10];

    __asm__ __volatile__("smc #0"
                         : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4),
                           "+r"(x5), "+r"(x6), "+r"(x7), "+r"(x8), "+r"(x9),
                           "+r"(x10)
                         : : "memory");
    out->a0 = x0;
    out->a1 = x1;
    out->a2 = x2;
    out->a3 = x3;
    out->a4 = x4;
    out->a5 = x5;
    out->a6 = x6;
    out->a7 = x7;
    out->a8 = x8;
}

/* The common shape: a function ID and up to four arguments. */
static void rsi_call(struct smc_res *out, uint64_t f, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4)
{
    uint64_t in[11] = { f, a1, a2, a3, a4 };

    rsi(out, in);
}

static int same(const void *a, const void *b, unsigned long n)
{
    const uint8_t *p = a, *q = b;

    while (n--) {
        if (*p++ != *q++) {
            return 0;
        }
    }
    return 1;
}

static int is_zero(const void *p, unsigned long n)
{
    const uint8_t *b = p;

    while (n--) {
        if (*b++) {
            return 0;
        }
    }
    return 1;
}

static void measurement_read(uint64_t index, uint8_t *out)
{
    uint64_t in[11] = { RSI_MEASUREMENT_READ, index };
    struct smc_res r;
    const uint64_t *words;

    rsi(&r, in);
    words = &r.a1;
    for (unsigned i = 0; i < MEASUREMENT_LEN / 8; i++) {
        for (unsigned b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(words[i] >> (b * 8));
        }
    }
}

static uint8_t window[GRANULE] __attribute__((aligned(GRANULE)));
static uint8_t token[GRANULE * 2] __attribute__((aligned(GRANULE)));
static uint8_t rem_before[MEASUREMENT_LEN], rem_after[MEASUREMENT_LEN];
static uint8_t rim_before[MEASUREMENT_LEN], rim_after[MEASUREMENT_LEN];
static uint8_t value[MEASUREMENT_LEN];

int main(void)
{
    struct smc_res r;
    uint64_t in[11];
    uint64_t base, top;
    unsigned long collected = 0;
    /* Volatile so the spin below is not optimised into nothing. */
    volatile unsigned long spin = 0;

    ml_printf("Emulated Arm CCA migration test\n");

    rsi_call(&r, RSI_ABI_VERSION, RSI_ABI_VERSION_1_0, 0, 0, 0);
    if (r.a0 != RSI_SUCCESS) {
        ml_printf("FAIL: no RSI here -- was x-cca-guest=on given?\n");
        return 1;
    }

    /* A page state that must still be there afterwards. */
    base = (uint64_t)window;
    top = base + sizeof(window);
    rsi_call(&r, RSI_IPA_STATE_SET, base, top, RSI_RIPAS_EMPTY,
             RSI_NO_CHANGE_DESTROYED);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_SET status");

    /* A measurement that must still be there afterwards. */
    for (unsigned i = 0; i < sizeof(value); i++) {
        value[i] = (uint8_t)(i * 11 + 3);
    }
    in[0] = RSI_MEASUREMENT_EXTEND;
    in[1] = 1;
    in[2] = HASH_LEN;
    for (unsigned i = 0; i < HASH_LEN / 8; i++) {
        uint64_t w = 0;

        for (unsigned b = 0; b < 8; b++) {
            w |= (uint64_t)value[i * 8 + b] << (b * 8);
        }
        in[3 + i] = w;
    }
    for (unsigned i = HASH_LEN / 8; i < 8; i++) {
        in[3 + i] = 0;
    }
    rsi(&r, in);
    check(r.a0 == RSI_SUCCESS, "RSI_MEASUREMENT_EXTEND status");

    measurement_read(0, rim_before);
    measurement_read(1, rem_before);
    check(!is_zero(rem_before, HASH_LEN), "REM 1 did not change when extended");

    /*
     * And a token part-way through being handed over. The first call after
     * INIT builds it and writes nothing, so this leaves a document that exists
     * and has been partly taken -- which is the state that has to survive, not
     * just the fact that a token was asked for.
     */
    for (unsigned i = 0; i < 11; i++) {
        in[i] = 0;
    }
    in[0] = RSI_ATTESTATION_TOKEN_INIT;
    for (unsigned i = 0; i < 8; i++) {
        in[1 + i] = 0x0101010101010101UL * (i + 1);
    }
    rsi(&r, in);
    check(r.a0 == RSI_SUCCESS, "RSI_ATTESTATION_TOKEN_INIT status");

    for (unsigned round = 0; round < 4 && collected == 0; round++) {
        rsi_call(&r, RSI_ATTESTATION_TOKEN_CONT, (uint64_t)token, 0, 64, 0);
        check(r.a0 == RSI_SUCCESS || r.a0 == RSI_INCOMPLETE,
              "RSI_ATTESTATION_TOKEN_CONTINUE status");
        collected += r.a1;
    }
    check(collected > 0, "no part of the token was collected");
    check(token[0] == 0xd9 && token[1] == 0x01 && token[2] == 0x8f,
          "the collected prefix is not a CCA token");

    /* The window a migration is started in. */
    ml_printf("state set, spinning\n");
    while (spin < SPIN_ITERATIONS) {
        spin = spin + 1;
    }
    ml_printf("spin done, checking\n");

    /* The measurements are the same Realm's. */
    measurement_read(0, rim_after);
    measurement_read(1, rem_after);
    check(same(rim_before, rim_after, MEASUREMENT_LEN), "the RIM changed");
    check(same(rem_before, rem_after, MEASUREMENT_LEN), "REM 1 changed");

    /* The page state is still what the Realm asked for. */
    rsi_call(&r, RSI_IPA_STATE_GET, base, top, 0, 0);
    check(r.a0 == RSI_SUCCESS, "RSI_IPA_STATE_GET status");
    check(r.a2 == RSI_RIPAS_EMPTY,
          "the page handed back is no longer reported as handed back");
    check(r.a1 == top, "RSI_IPA_STATE_GET stopped short of the range");

    /*
     * And the rest of the token is the rest of the same document: it finishes,
     * and it does not start over.
     */
    for (unsigned round = 0; round < 64 && collected < sizeof(token); round++) {
        uint64_t granule = collected & ~(uint64_t)(GRANULE - 1);
        uint64_t within = collected & (GRANULE - 1);
        uint64_t room = GRANULE - within;

        rsi_call(&r, RSI_ATTESTATION_TOKEN_CONT, (uint64_t)token + granule,
                 within, room, 0);
        if (r.a0 != RSI_SUCCESS && r.a0 != RSI_INCOMPLETE) {
            check(0, "the token could not be finished after the spin");
            break;
        }
        collected += r.a1;
        if (r.a0 == RSI_SUCCESS) {
            break;
        }
    }
    check(collected > 64, "the token did not continue past what was taken");
    check(token[0] == 0xd9 && token[1] == 0x01 && token[2] == 0x8f,
          "the finished token is not a CCA token");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA migration checks passed\n");
    return 0;
}
