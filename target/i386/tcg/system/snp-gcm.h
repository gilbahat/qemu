/*
 * AES-256-GCM for the emulated AMD SEV-SNP guest-message protocol.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef I386_TCG_SYSTEM_SNP_GCM_H
#define I386_TCG_SYSTEM_SNP_GCM_H

#define SNP_GCM_KEY_LEN     32
#define SNP_GCM_IV_LEN      12
#define SNP_GCM_TAG_LEN     16

/**
 * snp_gcm_encrypt: AES-256-GCM seal.
 * @key: 32-byte key.
 * @iv: 12-byte IV; only the 96-bit form is used by the protocol.
 * @aad: additional authenticated data, not encrypted.
 * @plain: input, @len bytes.
 * @cipher: output, @len bytes; may alias @plain.
 * @tag: 16-byte tag out.
 *
 * Returns false only on a bad parameter or a cipher failure.
 */
bool snp_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *plain, uint8_t *cipher, size_t len,
                     uint8_t *tag);

/**
 * snp_gcm_decrypt: AES-256-GCM open.
 *
 * Verifies @tag before producing any plaintext, and returns false if it does
 * not match.  Same argument conventions as snp_gcm_encrypt().
 */
bool snp_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *cipher, uint8_t *plain, size_t len,
                     const uint8_t *tag);

#endif /* I386_TCG_SYSTEM_SNP_GCM_H */
