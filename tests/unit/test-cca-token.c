/*
 * Tests for the emulated Arm CCA attestation token.
 *
 * The token is what a Realm hands to a verifier, so the thing worth testing is
 * not that bytes come out but that they parse: definite-length CBOR with the
 * lengths right, a two-token collection, COSE_Sign1 around each half, and the
 * claim that binds them.  So this reads the token back with its own small
 * decoder rather than comparing against a golden blob, which would pass just
 * as happily on a malformed encoding.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "crypto/init.h"
#include "../../target/arm/tcg/cca-token.h"

#define CBOR_UINT   0
#define CBOR_NINT   1
#define CBOR_BSTR   2
#define CBOR_TSTR   3
#define CBOR_ARRAY  4
#define CBOR_MAP    5
#define CBOR_TAG    6

#define TAG_COSE_SIGN1              18
#define TAG_CCA_TOKEN               399
#define CCA_PLATFORM_TOKEN          44234
#define CCA_REALM_TOKEN             44241
#define CCA_PLATFORM_CHALLENGE      10
#define CCA_REALM_CHALLENGE         44235
#define CCA_REALM_PUB_KEY           44237
#define CCA_REALM_INITIAL_MEAS      44238
#define CCA_REALM_EXTENSIBLE_MEAS   44239

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} Cbor;

/* Read one CBOR head: the major type and its argument. */
static bool cbor_head(Cbor *c, uint8_t *major, uint64_t *val)
{
    uint8_t info;

    g_assert(c->p <= c->end);
    if (c->p == c->end) {
        return false;
    }
    *major = *c->p >> 5;
    info = *c->p & 0x1f;
    c->p++;

    if (info < 24) {
        *val = info;
        return true;
    }
    if (info > 27) {
        return false;
    }

    *val = 0;
    for (unsigned n = 1u << (info - 24); n; n--) {
        if (c->p == c->end) {
            return false;
        }
        *val = (*val << 8) | *c->p++;
    }
    return true;
}

/* Consume one complete item, whatever it is. */
static bool cbor_skip(Cbor *c)
{
    uint8_t major;
    uint64_t val;

    if (!cbor_head(c, &major, &val)) {
        return false;
    }

    switch (major) {
    case CBOR_UINT:
    case CBOR_NINT:
        return true;
    case CBOR_BSTR:
    case CBOR_TSTR:
        if (val > (uint64_t)(c->end - c->p)) {
            return false;
        }
        c->p += val;
        return true;
    case CBOR_ARRAY:
        for (uint64_t i = 0; i < val; i++) {
            if (!cbor_skip(c)) {
                return false;
            }
        }
        return true;
    case CBOR_MAP:
        for (uint64_t i = 0; i < val * 2; i++) {
            if (!cbor_skip(c)) {
                return false;
            }
        }
        return true;
    case CBOR_TAG:
        return cbor_skip(c);
    default:
        return false;
    }
}

static void cbor_expect(Cbor *c, uint8_t want_major, uint64_t want_val)
{
    uint8_t major;
    uint64_t val;

    g_assert_true(cbor_head(c, &major, &val));
    g_assert_cmpuint(major, ==, want_major);
    g_assert_cmpuint(val, ==, want_val);
}

/* Read a byte string, leaving @c positioned after it. */
static void cbor_bytes(Cbor *c, const uint8_t **data, size_t *len)
{
    uint8_t major;
    uint64_t val;

    g_assert_true(cbor_head(c, &major, &val));
    g_assert_cmpuint(major, ==, CBOR_BSTR);
    g_assert_cmpuint(val, <=, (uint64_t)(c->end - c->p));
    *data = c->p;
    *len = val;
    c->p += val;
}

/*
 * Find one claim in a map by its unsigned key.  Returns the cursor positioned
 * at the value, so the caller reads whatever type it expects.
 */
static Cbor cbor_find(Cbor map, uint64_t key)
{
    uint8_t major;
    uint64_t entries;

    g_assert_true(cbor_head(&map, &major, &entries));
    g_assert_cmpuint(major, ==, CBOR_MAP);

    for (uint64_t i = 0; i < entries; i++) {
        Cbor at_key = map;
        uint64_t k;

        g_assert_true(cbor_head(&map, &major, &k));
        if (major == CBOR_UINT && k == key) {
            return map;
        }
        (void)at_key;
        g_assert_true(cbor_skip(&map));         /* the value */
    }
    g_assert_not_reached();
}

/* Unwrap a COSE_Sign1 and hand back its payload. */
static Cbor cose_sign1_payload(const uint8_t *data, size_t len)
{
    Cbor c = { data, data + len };
    const uint8_t *payload, *sig, *prot;
    size_t payload_len, sig_len, prot_len;

    cbor_expect(&c, CBOR_TAG, TAG_COSE_SIGN1);
    cbor_expect(&c, CBOR_ARRAY, 4);

    /* The protected header is a byte string wrapping {1: -35}. */
    cbor_bytes(&c, &prot, &prot_len);
    Cbor hdr = { prot, prot + prot_len };
    cbor_expect(&hdr, CBOR_MAP, 1);
    cbor_expect(&hdr, CBOR_UINT, 1);
    cbor_expect(&hdr, CBOR_NINT, 34);           /* -35 */

    cbor_expect(&c, CBOR_MAP, 0);               /* unprotected header */
    cbor_bytes(&c, &payload, &payload_len);
    cbor_bytes(&c, &sig, &sig_len);
    g_assert_cmpuint(sig_len, ==, 96);          /* ES384 */

    /*
     * There is no signature here and the emulation says so in the field
     * itself.  Check that it does, because a token whose signature had become
     * plausible-looking random bytes would be the one genuinely dangerous
     * regression this file can have.
     */
    g_assert_nonnull(g_strstr_len((const char *)sig, sig_len,
                                 "NOT-A-SIGNATURE"));

    g_assert_true(c.p == c.end);
    return (Cbor){ payload, payload + payload_len };
}

static GByteArray *build(const uint8_t *challenge, const uint8_t *rim,
                         const uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN])
{
    GByteArray *token = cca_build_token(challenge, rim, rem);

    g_assert_nonnull(token);
    return token;
}

static void fill(uint8_t *p, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(i * 7 + seed);
    }
}

/* The whole token parses, and both halves are where the collection says. */
static void test_structure(void)
{
    uint8_t challenge[CCA_CHALLENGE_LEN], rim[CCA_HASH_LEN];
    uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN];
    const uint8_t *platform, *realm;
    size_t platform_len, realm_len;
    Cbor c;

    fill(challenge, sizeof(challenge), 1);
    fill(rim, sizeof(rim), 2);
    for (unsigned i = 0; i < CCA_REM_COUNT; i++) {
        fill(rem[i], CCA_HASH_LEN, 3 + i);
    }

    g_autoptr(GByteArray) token = build(challenge, rim, rem);

    c = (Cbor){ token->data, token->data + token->len };
    cbor_expect(&c, CBOR_TAG, TAG_CCA_TOKEN);

    Cbor collection = c;
    Cbor at = cbor_find(collection, CCA_PLATFORM_TOKEN);
    cbor_bytes(&at, &platform, &platform_len);
    at = cbor_find(collection, CCA_REALM_TOKEN);
    cbor_bytes(&at, &realm, &realm_len);

    g_assert_cmpuint(platform_len, >, 0);
    g_assert_cmpuint(realm_len, >, 0);

    /* Nothing trailing: the outer lengths have to add up. */
    g_assert_true(cbor_skip(&c));
    g_assert_true(c.p == c.end);
}

/* The realm token carries the challenge and the measurements it was given. */
static void test_realm_claims(void)
{
    uint8_t challenge[CCA_CHALLENGE_LEN], rim[CCA_HASH_LEN];
    uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN];
    const uint8_t *realm, *data;
    size_t realm_len, len;
    uint8_t major;
    uint64_t count;

    fill(challenge, sizeof(challenge), 11);
    fill(rim, sizeof(rim), 22);
    for (unsigned i = 0; i < CCA_REM_COUNT; i++) {
        fill(rem[i], CCA_HASH_LEN, 33 + i);
    }

    g_autoptr(GByteArray) token = build(challenge, rim, rem);
    Cbor c = { token->data, token->data + token->len };

    cbor_expect(&c, CBOR_TAG, TAG_CCA_TOKEN);
    Cbor at = cbor_find(c, CCA_REALM_TOKEN);
    cbor_bytes(&at, &realm, &realm_len);

    Cbor claims = cose_sign1_payload(realm, realm_len);

    at = cbor_find(claims, CCA_REALM_CHALLENGE);
    cbor_bytes(&at, &data, &len);
    g_assert_cmpuint(len, ==, CCA_CHALLENGE_LEN);
    g_assert_cmpmem(data, len, challenge, sizeof(challenge));

    at = cbor_find(claims, CCA_REALM_INITIAL_MEAS);
    cbor_bytes(&at, &data, &len);
    g_assert_cmpmem(data, len, rim, sizeof(rim));

    at = cbor_find(claims, CCA_REALM_EXTENSIBLE_MEAS);
    g_assert_true(cbor_head(&at, &major, &count));
    g_assert_cmpuint(major, ==, CBOR_ARRAY);
    g_assert_cmpuint(count, ==, CCA_REM_COUNT);
    for (unsigned i = 0; i < CCA_REM_COUNT; i++) {
        cbor_bytes(&at, &data, &len);
        g_assert_cmpmem(data, len, rem[i], CCA_HASH_LEN);
    }
}

/*
 * The binding between the two tokens: the platform token's challenge is the
 * hash of the realm token's public key.  This is the check a verifier must
 * make and must refuse on rather than downgrade, so it is the one structural
 * property of the token that would matter even if the signatures were real.
 */
static void test_platform_binding(void)
{
    uint8_t challenge[CCA_CHALLENGE_LEN], rim[CCA_HASH_LEN];
    uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN] = { 0 };
    const uint8_t *platform, *realm, *key, *nonce;
    size_t platform_len, realm_len, key_len, nonce_len;
    uint8_t digest[CCA_HASH_LEN];
    uint8_t *digestp = digest;
    size_t digestlen = sizeof(digest);
    struct iovec iov;

    fill(challenge, sizeof(challenge), 5);
    fill(rim, sizeof(rim), 6);

    g_autoptr(GByteArray) token = build(challenge, rim, rem);
    Cbor c = { token->data, token->data + token->len };

    cbor_expect(&c, CBOR_TAG, TAG_CCA_TOKEN);
    Cbor at = cbor_find(c, CCA_REALM_TOKEN);
    cbor_bytes(&at, &realm, &realm_len);
    at = cbor_find(c, CCA_PLATFORM_TOKEN);
    cbor_bytes(&at, &platform, &platform_len);

    Cbor realm_claims = cose_sign1_payload(realm, realm_len);
    at = cbor_find(realm_claims, CCA_REALM_PUB_KEY);
    cbor_bytes(&at, &key, &key_len);

    Cbor platform_claims = cose_sign1_payload(platform, platform_len);
    at = cbor_find(platform_claims, CCA_PLATFORM_CHALLENGE);
    cbor_bytes(&at, &nonce, &nonce_len);

    iov.iov_base = (void *)key;
    iov.iov_len = key_len;
    g_assert_cmpint(qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA256, &iov, 1,
                                        &digestp, &digestlen, NULL), ==, 0);
    g_assert_cmpmem(nonce, nonce_len, digest, sizeof(digest));
}

/*
 * The same inputs give the same token, and a different measurement gives a
 * different one.  Both halves matter: a token that moved on its own could not
 * be replayed by a verifier, and one that did not move when the Realm changed
 * would not be measuring anything.
 */
static void test_determinism(void)
{
    uint8_t challenge[CCA_CHALLENGE_LEN], rim[CCA_HASH_LEN];
    uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN] = { 0 };

    fill(challenge, sizeof(challenge), 9);
    fill(rim, sizeof(rim), 10);

    g_autoptr(GByteArray) a = build(challenge, rim, rem);
    g_autoptr(GByteArray) b = build(challenge, rim, rem);

    g_assert_cmpmem(a->data, a->len, b->data, b->len);

    rim[0] ^= 0xff;
    g_autoptr(GByteArray) c = build(challenge, rim, rem);
    g_assert_cmpint(memcmp(a->data, c->data, MIN(a->len, c->len)), !=, 0);

    rim[0] ^= 0xff;
    rem[2][0] ^= 0xff;
    g_autoptr(GByteArray) d = build(challenge, rim, rem);
    g_assert_cmpint(memcmp(a->data, d->data, MIN(a->len, d->len)), !=, 0);

    rem[2][0] ^= 0xff;
    challenge[0] ^= 0xff;
    g_autoptr(GByteArray) e = build(challenge, rim, rem);
    g_assert_cmpint(memcmp(a->data, e->data, MIN(a->len, e->len)), !=, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert_cmpint(qcrypto_init(NULL), ==, 0);

    g_test_add_func("/cca-token/structure", test_structure);
    g_test_add_func("/cca-token/realm-claims", test_realm_claims);
    g_test_add_func("/cca-token/platform-binding", test_platform_binding);
    g_test_add_func("/cca-token/determinism", test_determinism);

    return g_test_run();
}
