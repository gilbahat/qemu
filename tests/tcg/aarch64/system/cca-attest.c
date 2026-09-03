/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Emulated Arm CCA measurement and attestation test.
 *
 * A Realm's measurements are the only thing in RSI it can check against
 * itself: the RIM is taken before it runs, the REMs are what it puts there,
 * and the token is supposed to carry both.  So this reads them, extends them,
 * and then looks inside the token for what it just did -- which is a stronger
 * claim than a length and a status, and is the claim an attestation flow
 * actually rests on.
 *
 * Run with -cpu max,x-cca-guest=on.
 */

#include <stdint.h>
#include <minilib.h>

#define RSI_MEASUREMENT_READ        0xc4000192UL
#define RSI_MEASUREMENT_EXTEND      0xc4000193UL
#define RSI_ATTESTATION_TOKEN_INIT  0xc4000194UL
#define RSI_ATTESTATION_TOKEN_CONT  0xc4000195UL

#define RSI_SUCCESS                 0UL
#define RSI_ERROR_INPUT             1UL
#define RSI_ERROR_STATE             2UL
#define RSI_INCOMPLETE              3UL

#define MEASUREMENT_LEN             64
#define HASH_LEN                    32
#define CHALLENGE_LEN               64
#define GRANULE                     4096

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

/*
 * Nine registers out rather than four: RSI_MEASUREMENT_READ returns the whole
 * 64-byte register in x1-x8.  As in the other CCA tests the results are stored
 * through a pointer instead of returned by value, because at -O0 the compiler
 * may use one of the registers the SMC returns in while arranging an indirect
 * return, and x1 is silently lost.
 */
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

static void zero(void *p, unsigned long n)
{
    uint8_t *d = p;

    while (n--) {
        *d++ = 0;
    }
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

/* Is @needle anywhere in @hay?  Used to find claims inside the token. */
static int contains(const uint8_t *hay, unsigned long haylen,
                    const uint8_t *needle, unsigned long len)
{
    if (haylen < len) {
        return 0;
    }
    for (unsigned long i = 0; i + len <= haylen; i++) {
        if (same(hay + i, needle, len)) {
            return 1;
        }
    }
    return 0;
}

/* Read one measurement register into @out, which is MEASUREMENT_LEN bytes. */
static uint64_t measurement_read(uint64_t index, uint8_t *out)
{
    uint64_t in[11] = { RSI_MEASUREMENT_READ, index };
    struct smc_res r;
    const uint64_t *words;

    rsi(&r, in);
    words = &r.a1;
    for (unsigned i = 0; i < MEASUREMENT_LEN / 8; i++) {
        uint64_t w = words[i];

        for (unsigned b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(w >> (b * 8));
        }
    }
    return r.a0;
}

static uint64_t measurement_extend(uint64_t index, const uint8_t *value,
                                   uint64_t len)
{
    uint64_t in[11] = { RSI_MEASUREMENT_EXTEND, index, len };
    struct smc_res r;

    for (unsigned i = 0; i * 8 < len; i++) {
        uint64_t w = 0;

        for (unsigned b = 0; b < 8 && i * 8 + b < len; b++) {
            w |= (uint64_t)value[i * 8 + b] << (b * 8);
        }
        in[3 + i] = w;
    }
    rsi(&r, in);
    return r.a0;
}

/* The token lands here, so it is granule-aligned as the RMM requires. */
static uint8_t token[GRANULE * 2] __attribute__((aligned(GRANULE)));
static uint8_t challenge[CHALLENGE_LEN];
static uint8_t rim[MEASUREMENT_LEN];
static uint8_t rem1[MEASUREMENT_LEN], rem1b[MEASUREMENT_LEN];
static uint8_t rem2[MEASUREMENT_LEN];
static uint8_t extend_value[MEASUREMENT_LEN];

/*
 * Collect the token, the way a Realm has to: bounded rounds, one granule at a
 * time, and a zero-length INCOMPLETE reply treated as progress rather than
 * failure.  Returns the length, or 0.
 */
static unsigned long collect_token(int *saw_empty_round)
{
    unsigned long off = 0;

    *saw_empty_round = 0;

    for (unsigned rounds = 0; rounds < 64 && off < sizeof(token); rounds++) {
        uint64_t granule = off & ~(uint64_t)(GRANULE - 1);
        uint64_t within = off & (GRANULE - 1);
        uint64_t room = GRANULE - within;
        uint64_t in[11] = { RSI_ATTESTATION_TOKEN_CONT,
                            (uint64_t)token + granule, within, room };
        struct smc_res r;

        if (room > sizeof(token) - off) {
            room = sizeof(token) - off;
            in[3] = room;
        }

        rsi(&r, in);
        if (r.a0 != RSI_SUCCESS && r.a0 != RSI_INCOMPLETE) {
            ml_printf("FAIL: token continue returned %d\n", (int)r.a0);
            return 0;
        }
        if (r.a1 > sizeof(token) - off) {
            ml_printf("FAIL: token continue wrote past the buffer\n");
            return 0;
        }
        if (r.a0 == RSI_INCOMPLETE && r.a1 == 0) {
            *saw_empty_round = 1;
        }
        off += r.a1;
        if (r.a0 == RSI_SUCCESS) {
            return off;
        }
    }
    ml_printf("FAIL: token never completed\n");
    return 0;
}

int main(void)
{
    struct smc_res r;
    uint64_t in[11];
    unsigned long len;
    int saw_empty_round;

    ml_printf("Emulated Arm CCA measurement and attestation test\n");

    /* The RIM is taken before the guest runs, so it is there already. */
    check(measurement_read(0, rim) == RSI_SUCCESS, "RSI_MEASUREMENT_READ(0)");
    check(!is_zero(rim, HASH_LEN), "the RIM is zero -- was anything measured?");
    check(is_zero(rim + HASH_LEN, MEASUREMENT_LEN - HASH_LEN),
          "the RIM register is not zero above the hash");
    ml_printf("RIM %x%x%x%x...\n", rim[0], rim[1], rim[2], rim[3]);

    /* The REMs start at zero and stay there until the guest extends them. */
    check(measurement_read(1, rem1) == RSI_SUCCESS, "RSI_MEASUREMENT_READ(1)");
    check(is_zero(rem1, MEASUREMENT_LEN), "REM 1 did not start at zero");

    /* Index 5 is past the last measurement. */
    check(measurement_read(5, rem1) == RSI_ERROR_INPUT,
          "RSI_MEASUREMENT_READ accepted an index past the last measurement");

    /*
     * The RIM is read-only: it is taken when the Realm is activated, and a
     * Realm extending its own initial measurement is the mistake this call is
     * most likely to be made with.
     */
    for (unsigned i = 0; i < sizeof(extend_value); i++) {
        extend_value[i] = (uint8_t)(i * 7 + 1);
    }
    check(measurement_extend(0, extend_value, HASH_LEN) == RSI_ERROR_INPUT,
          "RSI_MEASUREMENT_EXTEND accepted index 0, which is the RIM");
    check(measurement_extend(5, extend_value, HASH_LEN) == RSI_ERROR_INPUT,
          "RSI_MEASUREMENT_EXTEND accepted an index past the last REM");
    check(measurement_extend(1, extend_value, 0) == RSI_ERROR_INPUT,
          "RSI_MEASUREMENT_EXTEND accepted a zero-length value");
    check(measurement_extend(1, extend_value, 65) == RSI_ERROR_INPUT,
          "RSI_MEASUREMENT_EXTEND accepted a value wider than the register");

    /* A real extend moves the register, and not to the RIM. */
    check(measurement_extend(1, extend_value, HASH_LEN) == RSI_SUCCESS,
          "RSI_MEASUREMENT_EXTEND(1)");
    check(measurement_read(1, rem1) == RSI_SUCCESS, "read back REM 1");
    check(!is_zero(rem1, HASH_LEN), "REM 1 did not change when extended");
    check(!same(rem1, rim, HASH_LEN), "REM 1 came out equal to the RIM");

    /*
     * Two registers extended identically from zero must agree, and extending
     * one of them again must move it: the first says the measurement is a
     * function of what went in, the second that it chains rather than
     * replaces.  Together they are what a verifier replays.
     */
    check(measurement_extend(2, extend_value, HASH_LEN) == RSI_SUCCESS,
          "RSI_MEASUREMENT_EXTEND(2)");
    check(measurement_read(2, rem2) == RSI_SUCCESS, "read back REM 2");
    check(same(rem1, rem2, MEASUREMENT_LEN),
          "the same extend from zero gave two different measurements");

    check(measurement_extend(1, extend_value, HASH_LEN) == RSI_SUCCESS,
          "RSI_MEASUREMENT_EXTEND(1) again");
    check(measurement_read(1, rem1b) == RSI_SUCCESS, "read back REM 1 again");
    check(!same(rem1, rem1b, HASH_LEN),
          "extending twice left the measurement where it was");

    /* Now the token, over a challenge the guest can recognise afterwards. */
    for (unsigned i = 0; i < CHALLENGE_LEN; i++) {
        challenge[i] = (uint8_t)(i * 3 + 5);
    }
    zero(in, sizeof(in));
    in[0] = RSI_ATTESTATION_TOKEN_INIT;
    for (unsigned i = 0; i < CHALLENGE_LEN / 8; i++) {
        uint64_t w = 0;

        for (unsigned b = 0; b < 8; b++) {
            w |= (uint64_t)challenge[i * 8 + b] << (b * 8);
        }
        in[1 + i] = w;
    }
    rsi(&r, in);
    check(r.a0 == RSI_SUCCESS, "RSI_ATTESTATION_TOKEN_INIT");
    check(r.a1 > 0 && r.a1 <= sizeof(token),
          "the reported upper bound on the token size is not usable");

    zero(token, sizeof(token));
    len = collect_token(&saw_empty_round);
    check(len > 0, "no token was collected");
    ml_printf("token %d bytes\n", (int)len);

    /*
     * The RMM does bounded work per call and may answer INCOMPLETE having
     * written nothing.  A guest that treats that as failure works against this
     * emulation only if the emulation never does it, so it does.
     */
    check(saw_empty_round,
          "no INCOMPLETE round wrote zero bytes; the guest loop went untested");

    /*
     * The collection is CBOR tag 399 wrapping a two-entry map, and the first
     * key is 44234 -- which is 0xacca, and is how the bytes below read.
     */
    check(len > 7 && token[0] == 0xd9 && token[1] == 0x01 && token[2] == 0x8f,
          "the token does not begin with CBOR tag 399");
    check(len > 7 && token[3] == 0xa2 && token[4] == 0x19 &&
          token[5] == 0xac && token[6] == 0xca,
          "the token is not a two-entry map starting at the platform token");

    /* And it carries what this guest put in: its challenge and its RIM. */
    check(contains(token, len, challenge, CHALLENGE_LEN),
          "the token does not carry the challenge that was passed in");
    check(contains(token, len, rim, HASH_LEN),
          "the token does not carry the RIM");
    check(contains(token, len, rem1b, HASH_LEN),
          "the token does not carry the REM the guest extended");

    /* The token is done, so continuing without a new INIT is a state error. */
    zero(in, sizeof(in));
    in[0] = RSI_ATTESTATION_TOKEN_CONT;
    in[1] = (uint64_t)token;
    in[2] = 0;
    in[3] = GRANULE;
    rsi(&r, in);
    check(r.a0 == RSI_ERROR_STATE,
          "continuing a finished token was not a state error");

    /* A buffer that is not a granule, or a range leaving it, is refused. */
    zero(in, sizeof(in));
    in[0] = RSI_ATTESTATION_TOKEN_INIT;
    rsi(&r, in);
    check(r.a0 == RSI_SUCCESS, "RSI_ATTESTATION_TOKEN_INIT again");

    zero(in, sizeof(in));
    in[0] = RSI_ATTESTATION_TOKEN_CONT;
    in[1] = (uint64_t)token + 8;
    in[2] = 0;
    in[3] = 64;
    rsi(&r, in);
    check(r.a0 == RSI_ERROR_INPUT,
          "an unaligned token buffer was accepted");

    zero(in, sizeof(in));
    in[0] = RSI_ATTESTATION_TOKEN_CONT;
    in[1] = (uint64_t)token;
    in[2] = GRANULE - 8;
    in[3] = 64;
    rsi(&r, in);
    check(r.a0 == RSI_ERROR_INPUT,
          "a token write crossing out of the granule was accepted");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All CCA measurement and attestation checks passed\n");
    return 0;
}
