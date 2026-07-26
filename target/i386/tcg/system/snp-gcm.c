/*
 * AES-256-GCM, for the emulated AMD SEV-SNP guest-message protocol.
 *
 * SNP_GUEST_REQUEST carries its payload encrypted under a VMPCK with
 * AES-256-GCM, so an emulation that wants a guest to exercise the real
 * attestation path has to speak it.  QEMU's crypto API offers no AEAD mode and
 * this is its only user, so the construction is assembled here from the AES
 * block cipher the API does provide.
 *
 * The field multiply is the textbook shift-and-xor from NIST SP 800-38D rather
 * than anything clever.  Messages here are a few kilobytes and this runs once
 * per attestation request, so there is nothing to gain from a table-driven or
 * carry-less-multiply version and plenty to lose: the value of this file is
 * that it is obviously correct and checked against known answers.
 *
 * See tests/unit/test-snp-gcm.c.  A wrong implementation here would not be a
 * security problem -- nothing is protecting anything -- but it would silently
 * fail to interoperate with a guest that does GCM correctly, which is exactly
 * the class of bug this emulation exists to catch rather than to cause.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "crypto/cipher.h"
#include "snp-gcm.h"

#define GCM_BLOCK 16

static void xor_bytes(uint8_t *dst, const uint8_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

/*
 * Multiply X by H in GF(2^128), per NIST SP 800-38D section 6.3.  The field
 * convention is the awkward part: bit 0 of byte 0 is the most significant
 * coefficient, so the reduction polynomial shows up as 0xe1 in byte 0.
 */
static void ghash_mul(uint8_t *x, const uint8_t *h)
{
    uint8_t z[GCM_BLOCK] = { 0 };
    uint8_t v[GCM_BLOCK];
    int i, j;

    memcpy(v, h, GCM_BLOCK);

    for (i = 0; i < 128; i++) {
        bool lsb;

        if (x[i / 8] & (0x80 >> (i % 8))) {
            xor_bytes(z, v, GCM_BLOCK);
        }

        /* v >>= 1 across the whole block, then reduce if a bit fell off. */
        lsb = v[GCM_BLOCK - 1] & 1;
        for (j = GCM_BLOCK - 1; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1;
        }
    }

    memcpy(x, z, GCM_BLOCK);
}

/* Fold @len bytes of @data into @y, zero-padding the final partial block. */
static void ghash_update(uint8_t *y, const uint8_t *h, const uint8_t *data,
                         size_t len)
{
    while (len) {
        uint8_t block[GCM_BLOCK] = { 0 };
        size_t n = MIN(len, (size_t)GCM_BLOCK);

        memcpy(block, data, n);
        xor_bytes(y, block, GCM_BLOCK);
        ghash_mul(y, h);
        data += n;
        len -= n;
    }
}

static void be64_store(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = v & 0xff;
        v >>= 8;
    }
}

/* The GCM counter increments only the low 32 bits of the block. */
static void inc32(uint8_t *ctr)
{
    int i;

    for (i = GCM_BLOCK - 1; i >= GCM_BLOCK - 4; i--) {
        if (++ctr[i]) {
            break;
        }
    }
}

typedef struct SnpGcmCtx {
    QCryptoCipher *aes;
    uint8_t h[GCM_BLOCK];       /* AES_K(0) */
    uint8_t j0[GCM_BLOCK];      /* IV || 0^31 || 1 */
} SnpGcmCtx;

static bool aes_block(SnpGcmCtx *c, const uint8_t *in, uint8_t *out)
{
    return qcrypto_cipher_encrypt(c->aes, in, out, GCM_BLOCK, NULL) == 0;
}

static bool gcm_init(SnpGcmCtx *c, const uint8_t *key, const uint8_t *iv,
                     size_t ivlen)
{
    static const uint8_t zero[GCM_BLOCK] = { 0 };

    if (ivlen != SNP_GCM_IV_LEN) {
        /* Only the 96-bit IV form appears in the guest-message protocol. */
        return false;
    }

    /*
     * ECB, not CTR: GCM's counter wraps within its low 32 bits only, while the
     * generic CTR mode carries across the whole block. Driving the counter
     * here keeps the two from ever disagreeing.
     */
    c->aes = qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_256,
                                QCRYPTO_CIPHER_MODE_ECB,
                                key, SNP_GCM_KEY_LEN, NULL);
    if (!c->aes) {
        return false;
    }
    if (!aes_block(c, zero, c->h)) {
        qcrypto_cipher_free(c->aes);
        c->aes = NULL;
        return false;
    }

    memset(c->j0, 0, GCM_BLOCK);
    memcpy(c->j0, iv, SNP_GCM_IV_LEN);
    c->j0[GCM_BLOCK - 1] = 1;
    return true;
}

/* CTR keystream over @len bytes, starting from inc32(J0). */
static bool gcm_crypt(SnpGcmCtx *c, const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ctr[GCM_BLOCK];
    uint8_t stream[GCM_BLOCK];
    size_t done = 0;

    memcpy(ctr, c->j0, GCM_BLOCK);
    while (done < len) {
        size_t n = MIN(len - done, (size_t)GCM_BLOCK);
        size_t i;

        inc32(ctr);
        if (!aes_block(c, ctr, stream)) {
            return false;
        }
        for (i = 0; i < n; i++) {
            out[done + i] = in[done + i] ^ stream[i];
        }
        done += n;
    }
    return true;
}

/* S = GHASH(A | pad | C | pad | len(A) | len(C)); T = S ^ AES(J0). */
static bool gcm_tag(SnpGcmCtx *c, const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen, uint8_t *tag)
{
    uint8_t y[GCM_BLOCK] = { 0 };
    uint8_t lens[GCM_BLOCK];
    uint8_t ej0[GCM_BLOCK];

    ghash_update(y, c->h, aad, aadlen);
    ghash_update(y, c->h, ct, ctlen);

    be64_store(lens, (uint64_t)aadlen * 8);
    be64_store(lens + 8, (uint64_t)ctlen * 8);
    xor_bytes(y, lens, GCM_BLOCK);
    ghash_mul(y, c->h);

    if (!aes_block(c, c->j0, ej0)) {
        return false;
    }
    xor_bytes(y, ej0, GCM_BLOCK);
    memcpy(tag, y, SNP_GCM_TAG_LEN);
    return true;
}

bool snp_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *plain, uint8_t *cipher, size_t len,
                     uint8_t *tag)
{
    SnpGcmCtx c;
    bool ok;

    if (!gcm_init(&c, key, iv, ivlen)) {
        return false;
    }
    ok = gcm_crypt(&c, plain, cipher, len) &&
         gcm_tag(&c, aad, aadlen, cipher, len, tag);
    qcrypto_cipher_free(c.aes);
    return ok;
}

bool snp_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *cipher, uint8_t *plain, size_t len,
                     const uint8_t *tag)
{
    SnpGcmCtx c;
    uint8_t want[SNP_GCM_TAG_LEN];
    bool ok;

    if (!gcm_init(&c, key, iv, ivlen)) {
        return false;
    }

    /*
     * Tag first, over the ciphertext, compared without an early exit.  Not
     * because there is a secret worth protecting -- there is not -- but because
     * a guest developed against an emulation that accepts a bad tag will fail
     * on hardware, and that is the failure this exists to prevent.
     */
    ok = gcm_tag(&c, aad, aadlen, cipher, len, want);
    if (ok) {
        uint8_t diff = 0;
        size_t i;

        for (i = 0; i < SNP_GCM_TAG_LEN; i++) {
            diff |= want[i] ^ tag[i];
        }
        ok = (diff == 0);
    }
    if (ok) {
        ok = gcm_crypt(&c, cipher, plain, len);
    }
    qcrypto_cipher_free(c.aes);
    return ok;
}
