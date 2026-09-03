/*
 * The Arm CCA attestation token, for the emulated CCA guest interface.
 *
 * On hardware this is produced by the RMM and by the platform's root of trust:
 * the RMM signs a realm token with a key the Realm cannot reach, and the
 * platform signs a platform token whose challenge binds it to that key.  There
 * is no RMM here and no root of trust, so what this builds is the *structure*
 * of that token over the measurements the emulation really has.
 *
 * The structure is worth building faithfully, because it is what a guest and a
 * verifier parse: the CBOR shape, the two-token collection, the claim keys and
 * the key-to-platform binding are all real, and code that gets them wrong
 * fails here the same way it would fail on silicon.  The signatures are the
 * one thing that cannot be real, so they are not imitated -- every signature
 * and key coordinate is a repeated ASCII marker saying what it is, in the same
 * spirit as the emulated SEV-SNP report.  Anyone who hexdumps this token, or
 * ships one to a relying party by accident, is told immediately.
 *
 * The CBOR is written out here rather than through libcbor and the qemu_cbor
 * helpers, which the Nitro NSM device uses for the same job.  The reason is
 * that CONFIG_LIBCBOR is optional: routing a *guest-visible ABI* through it
 * would make RSI_ATTESTATION_TOKEN_CONTINUE succeed or fail depending on which
 * libraries the host had when QEMU was built, which is not a difference a
 * Realm should be able to observe.  The encoder below is definite-length
 * serialization only, over data this file produces itself.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "crypto/hash.h"
#include "cca-token.h"

/* CBOR major types, in the top three bits of the initial byte. */
#define CBOR_UINT       0
#define CBOR_NINT       1
#define CBOR_BSTR       2
#define CBOR_TSTR       3
#define CBOR_ARRAY      4
#define CBOR_MAP        5
#define CBOR_TAG        6

/* CBOR tags: 18 is COSE_Sign1, 399 is the CCA token collection. */
#define CBOR_TAG_COSE_SIGN1     18
#define CBOR_TAG_CCA_TOKEN      399

/* Collection members. */
#define CCA_PLATFORM_TOKEN      44234
#define CCA_REALM_TOKEN         44241

/* Realm token claims. */
#define CCA_REALM_CHALLENGE             44235
#define CCA_REALM_PERSONALIZATION       44236
#define CCA_REALM_PUB_KEY               44237
#define CCA_REALM_INITIAL_MEASUREMENT   44238
#define CCA_REALM_EXTENSIBLE_MEAS       44239
#define CCA_REALM_HASH_ALGO_ID          44240
#define CCA_REALM_PUB_KEY_HASH_ALGO_ID  44242

/* Platform token claims, which are PSA's. */
#define CCA_PLATFORM_CHALLENGE          10
#define CCA_PLATFORM_INSTANCE_ID        256
#define CCA_PLATFORM_PROFILE            265
#define CCA_PLATFORM_LIFECYCLE          2395
#define CCA_PLATFORM_IMPLEMENTATION_ID  2396
#define CCA_PLATFORM_SW_COMPONENTS      2399
#define CCA_PLATFORM_VERIFICATION_SVC   2400
#define CCA_PLATFORM_CONFIG             2401

/* PSA software-component map keys. */
#define PSA_SW_MEASUREMENT_TYPE         1
#define PSA_SW_MEASUREMENT_VALUE        2
#define PSA_SW_SIGNER_ID                5

/* COSE: algorithm sits at header key 1, and ES384 is -35. */
#define COSE_HEADER_ALG                 1
#define COSE_ALG_ES384                  (-35)

/* COSE_Key: EC2 over P-384, with the coordinates at -2 and -3. */
#define COSE_KEY_KTY                    1
#define COSE_KEY_ALG                    3
#define COSE_KEY_KTY_EC2                2
#define COSE_KEY_CRV                    (-1)
#define COSE_KEY_CRV_P384               2
#define COSE_KEY_X                      (-2)
#define COSE_KEY_Y                      (-3)

/* ES384 is two 48-byte halves. */
#define CCA_SIGNATURE_LEN               96
#define CCA_P384_COORD_LEN              48

/*
 * PSA lifecycle.  0x1000 is ASSEMBLY_AND_TEST, which is what this is: a
 * platform that has not been provisioned and is not claiming to be secured.
 */
#define PSA_LIFECYCLE_ASSEMBLY_AND_TEST 0x1000

/*
 * Markers.  These fill every field that would hold a secret-derived value on
 * hardware.  They are deliberately long enough that a truncated hexdump still
 * shows the words rather than a plausible-looking prefix of random bytes.
 */
#define CCA_NOT_A_SIGNATURE  "NOT-A-SIGNATURE-QEMU-TCG-CCA-EMULATION-"
#define CCA_NOT_A_KEY_X      "NOT-A-KEY-X-QEMU-TCG-CCA-EMULATION-"
#define CCA_NOT_A_KEY_Y      "NOT-A-KEY-Y-QEMU-TCG-CCA-EMULATION-"
#define CCA_NOT_A_SIGNER_ID  "NOT-A-SIGNER-ID-QEMU-TCG-CCA-EMULATION-"
#define CCA_IMPLEMENTATION   "QEMU TCG emulated CCA -- not a platform"
#define CCA_PLATFORM_CFG     "QEMU TCG emulated CCA -- no configuration"

/*
 * There is nowhere to send this token.  The claim is defined as a URL a
 * verifier can be pointed at, so name the absence rather than leaving it out:
 * a token that quietly omits the claim looks like one whose verification
 * service simply was not provisioned.
 */
#define CCA_VERIFICATION_SVC "urn:qemu:cca-tcg:there-is-no-verification-service"

/* The token names its own format; SHA-256 is what RSI_REALM_CONFIG says. */
#define CCA_PLATFORM_PROFILE_STR    "http://arm.com/CCA-SSD/1.0.0"
#define CCA_HASH_ALGO_STR           "sha-256"

static void cbor_head(GByteArray *b, uint8_t major, uint64_t val)
{
    uint8_t hdr[9];
    size_t n;

    if (val < 24) {
        hdr[0] = (major << 5) | val;
        n = 1;
    } else if (val <= UINT8_MAX) {
        hdr[0] = (major << 5) | 24;
        hdr[1] = val;
        n = 2;
    } else if (val <= UINT16_MAX) {
        hdr[0] = (major << 5) | 25;
        stw_be_p(hdr + 1, val);
        n = 3;
    } else if (val <= UINT32_MAX) {
        hdr[0] = (major << 5) | 26;
        stl_be_p(hdr + 1, val);
        n = 5;
    } else {
        hdr[0] = (major << 5) | 27;
        stq_be_p(hdr + 1, val);
        n = 9;
    }
    g_byte_array_append(b, hdr, n);
}

static void cbor_uint(GByteArray *b, uint64_t val)
{
    cbor_head(b, CBOR_UINT, val);
}

static void cbor_int(GByteArray *b, int64_t val)
{
    if (val < 0) {
        cbor_head(b, CBOR_NINT, (uint64_t)(-1 - val));
    } else {
        cbor_head(b, CBOR_UINT, (uint64_t)val);
    }
}

static void cbor_bytes(GByteArray *b, const void *data, size_t len)
{
    cbor_head(b, CBOR_BSTR, len);
    g_byte_array_append(b, data, len);
}

static void cbor_text(GByteArray *b, const char *s)
{
    size_t len = strlen(s);

    cbor_head(b, CBOR_TSTR, len);
    g_byte_array_append(b, (const uint8_t *)s, len);
}

static void cbor_array(GByteArray *b, size_t n)
{
    cbor_head(b, CBOR_ARRAY, n);
}

static void cbor_map(GByteArray *b, size_t n)
{
    cbor_head(b, CBOR_MAP, n);
}

static void cbor_tag(GByteArray *b, uint64_t tag)
{
    cbor_head(b, CBOR_TAG, tag);
}

/* Fill @len bytes with @marker, repeated and truncated rather than padded. */
static void cca_marker(uint8_t *out, size_t len, const char *marker)
{
    size_t mlen = strlen(marker);

    for (size_t i = 0; i < len; i += mlen) {
        memcpy(out + i, marker, MIN(mlen, len - i));
    }
}

static bool cca_sha256(const void *data, size_t len, uint8_t *out)
{
    size_t outlen = CCA_HASH_LEN;
    struct iovec iov = { .iov_base = (void *)data, .iov_len = len };

    return qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA256, &iov, 1,
                               &out, &outlen, NULL) == 0;
}

/*
 * The realm's public key, as a COSE_Key.  Its bytes are what the platform
 * token's challenge is the hash of, so this is built once and used twice --
 * which is the whole point of the claim and the reason it is not inlined.
 */
static void cca_realm_pub_key(GByteArray *key)
{
    uint8_t coord[CCA_P384_COORD_LEN];

    cbor_map(key, 5);
    cbor_uint(key, COSE_KEY_KTY);
    cbor_uint(key, COSE_KEY_KTY_EC2);
    cbor_uint(key, COSE_KEY_ALG);
    cbor_int(key, COSE_ALG_ES384);
    cbor_int(key, COSE_KEY_CRV);
    cbor_uint(key, COSE_KEY_CRV_P384);
    cbor_int(key, COSE_KEY_X);
    cca_marker(coord, sizeof(coord), CCA_NOT_A_KEY_X);
    cbor_bytes(key, coord, sizeof(coord));
    cbor_int(key, COSE_KEY_Y);
    cca_marker(coord, sizeof(coord), CCA_NOT_A_KEY_Y);
    cbor_bytes(key, coord, sizeof(coord));
}

/*
 * Wrap a claims map as a COSE_Sign1.  A verifier reconstructs the Sig_structure
 * from the protected header and the payload and checks the signature over it;
 * everything up to that last step is real here, so a verifier gets as far as
 * the check and then refuses, which is the correct outcome.
 */
static void cca_cose_sign1(GByteArray *out, const GByteArray *claims)
{
    g_autoptr(GByteArray) protected_hdr = g_byte_array_new();
    uint8_t sig[CCA_SIGNATURE_LEN];

    cbor_map(protected_hdr, 1);
    cbor_uint(protected_hdr, COSE_HEADER_ALG);
    cbor_int(protected_hdr, COSE_ALG_ES384);

    cbor_tag(out, CBOR_TAG_COSE_SIGN1);
    cbor_array(out, 4);
    cbor_bytes(out, protected_hdr->data, protected_hdr->len);
    cbor_map(out, 0);                           /* no unprotected header */
    cbor_bytes(out, claims->data, claims->len);
    cca_marker(sig, sizeof(sig), CCA_NOT_A_SIGNATURE);
    cbor_bytes(out, sig, sizeof(sig));
}

/*
 * The platform token.  On hardware this describes the firmware that booted the
 * machine, measured by a root of trust.  None of that happened, and rather
 * than fill the claims with plausible values this says so in each of them: the
 * implementation ID is ASCII, the lifecycle is the un-provisioned one, and the
 * single software component is the emulation naming itself.
 *
 * @key_hash is the one claim that is not decorative.  It is the hash of the
 * realm public key, and checking it against that key is what binds the two
 * halves of the collection together -- the check a verifier must make and must
 * refuse on rather than skip.  It holds here.
 */
static void cca_platform_claims(GByteArray *claims, const uint8_t *key_hash)
{
    uint8_t buf[CCA_HASH_LEN + 1];

    cbor_map(claims, 8);

    cbor_uint(claims, CCA_PLATFORM_CHALLENGE);
    cbor_bytes(claims, key_hash, CCA_HASH_LEN);

    /* An instance ID is a type byte followed by a unique value. */
    cbor_uint(claims, CCA_PLATFORM_INSTANCE_ID);
    buf[0] = 0x01;
    cca_marker(buf + 1, CCA_HASH_LEN, CCA_IMPLEMENTATION);
    cbor_bytes(claims, buf, sizeof(buf));

    cbor_uint(claims, CCA_PLATFORM_PROFILE);
    cbor_text(claims, CCA_PLATFORM_PROFILE_STR);

    cbor_uint(claims, CCA_PLATFORM_LIFECYCLE);
    cbor_uint(claims, PSA_LIFECYCLE_ASSEMBLY_AND_TEST);

    cbor_uint(claims, CCA_PLATFORM_IMPLEMENTATION_ID);
    cca_marker(buf, CCA_HASH_LEN, CCA_IMPLEMENTATION);
    cbor_bytes(claims, buf, CCA_HASH_LEN);

    cbor_uint(claims, CCA_PLATFORM_SW_COMPONENTS);
    cbor_array(claims, 1);
    cbor_map(claims, 3);
    cbor_uint(claims, PSA_SW_MEASUREMENT_TYPE);
    cbor_text(claims, "QEMU_TCG_CCA");
    cbor_uint(claims, PSA_SW_MEASUREMENT_VALUE);
    cca_marker(buf, CCA_HASH_LEN, CCA_IMPLEMENTATION);
    cbor_bytes(claims, buf, CCA_HASH_LEN);
    cbor_uint(claims, PSA_SW_SIGNER_ID);
    cca_marker(buf, CCA_HASH_LEN, CCA_NOT_A_SIGNER_ID);
    cbor_bytes(claims, buf, CCA_HASH_LEN);

    cbor_uint(claims, CCA_PLATFORM_VERIFICATION_SVC);
    cbor_text(claims, CCA_VERIFICATION_SVC);

    cbor_uint(claims, CCA_PLATFORM_CONFIG);
    cca_marker(buf, CCA_HASH_LEN, CCA_PLATFORM_CFG);
    cbor_bytes(claims, buf, CCA_HASH_LEN);
}

/*
 * The realm token.  Everything here except the key is a measurement or a
 * challenge the emulation genuinely holds, so this half of the token says
 * something true: the RIM changes when the image changes, the REMs change when
 * the guest extends them, and the challenge is the one the guest passed in.
 */
static void cca_realm_claims(GByteArray *claims, const uint8_t *challenge,
                             const uint8_t *rim,
                             const uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN],
                             const GByteArray *key)
{
    uint8_t rpv[CCA_CHALLENGE_LEN] = { 0 };

    cbor_map(claims, 7);

    cbor_uint(claims, CCA_REALM_CHALLENGE);
    cbor_bytes(claims, challenge, CCA_CHALLENGE_LEN);

    /*
     * The personalization value is set by whoever creates the Realm, and
     * nothing here creates one.  Zero is what a Realm created without one gets.
     */
    cbor_uint(claims, CCA_REALM_PERSONALIZATION);
    cbor_bytes(claims, rpv, sizeof(rpv));

    cbor_uint(claims, CCA_REALM_PUB_KEY);
    cbor_bytes(claims, key->data, key->len);

    cbor_uint(claims, CCA_REALM_INITIAL_MEASUREMENT);
    cbor_bytes(claims, rim, CCA_HASH_LEN);

    cbor_uint(claims, CCA_REALM_EXTENSIBLE_MEAS);
    cbor_array(claims, CCA_REM_COUNT);
    for (unsigned i = 0; i < CCA_REM_COUNT; i++) {
        cbor_bytes(claims, rem[i], CCA_HASH_LEN);
    }

    cbor_uint(claims, CCA_REALM_HASH_ALGO_ID);
    cbor_text(claims, CCA_HASH_ALGO_STR);

    cbor_uint(claims, CCA_REALM_PUB_KEY_HASH_ALGO_ID);
    cbor_text(claims, CCA_HASH_ALGO_STR);
}

GByteArray *cca_build_token(const uint8_t *challenge, const uint8_t *rim,
                            const uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN])
{
    g_autoptr(GByteArray) key = g_byte_array_new();
    g_autoptr(GByteArray) platform_claims = g_byte_array_new();
    g_autoptr(GByteArray) realm_claims = g_byte_array_new();
    g_autoptr(GByteArray) platform = g_byte_array_new();
    g_autoptr(GByteArray) realm = g_byte_array_new();
    GByteArray *token = g_byte_array_new();
    uint8_t key_hash[CCA_HASH_LEN];

    cca_realm_pub_key(key);
    if (!cca_sha256(key->data, key->len, key_hash)) {
        g_byte_array_free(token, TRUE);
        return NULL;
    }

    cca_platform_claims(platform_claims, key_hash);
    cca_cose_sign1(platform, platform_claims);

    cca_realm_claims(realm_claims, challenge, rim, rem, key);
    cca_cose_sign1(realm, realm_claims);

    cbor_tag(token, CBOR_TAG_CCA_TOKEN);
    cbor_map(token, 2);
    cbor_uint(token, CCA_PLATFORM_TOKEN);
    cbor_bytes(token, platform->data, platform->len);
    cbor_uint(token, CCA_REALM_TOKEN);
    cbor_bytes(token, realm->data, realm->len);

    return token;
}
