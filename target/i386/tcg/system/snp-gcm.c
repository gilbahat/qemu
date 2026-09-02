/*
 * AES-256-GCM, for the emulated AMD SEV-SNP guest-message protocol.
 *
 * SNP_GUEST_REQUEST carries its payload encrypted under a VMPCK with
 * AES-256-GCM, so an emulation that wants a guest to exercise the real
 * attestation path has to speak it.
 *
 * This is a thin adapter over QEMU's crypto API.  It used to be a hand-written
 * GHASH and counter mode, because the API offered no AEAD mode and this was its
 * only user; the API has since grown GCM along with the setaad/gettag calls, so
 * the construction is no longer ours to carry.  Keeping our own field multiply
 * beside an audited one would only be a way to disagree with it later.
 *
 * What remains here is the one thing the API does not offer: snp_gcm_decrypt()
 * verifies the tag before it produces any plaintext.  The API computes the tag
 * as it decrypts and exposes it only afterwards, so the plaintext goes to a
 * scratch buffer and is handed back only once the tag has been checked.
 *
 * See tests/unit/test-snp-gcm.c, which holds the known-answer vectors and is
 * what makes this swap checkable rather than hopeful.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "crypto/cipher.h"
#include "snp-gcm.h"

/*
 * A GCM cipher with the IV and AAD already fed in, ready for the message.
 * Returns NULL on a bad parameter or a cipher failure; the caller frees.
 */
static QCryptoCipher *snp_gcm_begin(const uint8_t *key,
                                    const uint8_t *iv, size_t ivlen,
                                    const uint8_t *aad, size_t aadlen)
{
    QCryptoCipher *c;

    if (ivlen != SNP_GCM_IV_LEN) {
        /* Only the 96-bit IV form appears in the guest-message protocol. */
        return NULL;
    }

    c = qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_256,
                           QCRYPTO_CIPHER_MODE_GCM,
                           key, SNP_GCM_KEY_LEN, NULL);
    if (!c) {
        return NULL;
    }
    if (qcrypto_cipher_setiv(c, iv, ivlen, NULL) < 0 ||
        (aadlen && qcrypto_cipher_setaad(c, aad, aadlen, NULL) < 0)) {
        qcrypto_cipher_free(c);
        return NULL;
    }
    return c;
}

bool snp_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *plain, uint8_t *cipher, size_t len,
                     uint8_t *tag)
{
    QCryptoCipher *c = snp_gcm_begin(key, iv, ivlen, aad, aadlen);
    bool ok;

    if (!c) {
        return false;
    }

    /* An AAD-only message is legal here, and must not become a zero-byte
     * encrypt: the tag still has to come out. */
    ok = (!len || qcrypto_cipher_encrypt(c, plain, cipher, len, NULL) == 0) &&
         qcrypto_cipher_gettag(c, tag, SNP_GCM_TAG_LEN, NULL) == 0;

    qcrypto_cipher_free(c);
    return ok;
}

bool snp_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *cipher, uint8_t *plain, size_t len,
                     const uint8_t *tag)
{
    QCryptoCipher *c = snp_gcm_begin(key, iv, ivlen, aad, aadlen);
    g_autofree uint8_t *scratch = NULL;
    uint8_t want[SNP_GCM_TAG_LEN];
    bool ok;

    if (!c) {
        return false;
    }

    /*
     * Into scratch, not into @plain: the caller is promised that a message
     * with a bad tag yields no plaintext at all.  Not because there is a
     * secret worth protecting -- there is not -- but because a guest developed
     * against an emulation that hands back plaintext anyway will fail on
     * hardware, and that is the failure this exists to prevent.
     */
    scratch = len ? g_malloc(len) : NULL;
    ok = (!len || qcrypto_cipher_decrypt(c, cipher, scratch, len, NULL) == 0) &&
         qcrypto_cipher_gettag(c, want, SNP_GCM_TAG_LEN, NULL) == 0;

    if (ok) {
        uint8_t diff = 0;
        size_t i;

        /* Compared without an early exit, for the same reason. */
        for (i = 0; i < SNP_GCM_TAG_LEN; i++) {
            diff |= want[i] ^ tag[i];
        }
        ok = (diff == 0);
    }
    if (ok && len) {
        memcpy(plain, scratch, len);
    }

    qcrypto_cipher_free(c);
    return ok;
}
