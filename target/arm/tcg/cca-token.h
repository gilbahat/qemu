/*
 * The Arm CCA attestation token, for the emulated CCA guest interface.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_ARM_CCA_TOKEN_H
#define TARGET_ARM_CCA_TOKEN_H

/* The challenge a guest passes to RSI_ATTESTATION_TOKEN_INIT, in x1-x8. */
#define CCA_CHALLENGE_LEN       64

/*
 * A measurement register is 64 bytes wide whatever the hash is; SHA-256 fills
 * the first 32 and the rest stays zero.  RSI_MEASUREMENT_READ returns the
 * whole width, the token carries only the hash.
 */
#define CCA_MEASUREMENT_LEN     64
#define CCA_HASH_LEN            32

/* RSI numbers measurements 0..4: 0 is the RIM, 1..4 are the REMs. */
#define CCA_REM_COUNT           4

/**
 * cca_build_token: build a CCA attestation token collection.
 * @challenge: CCA_CHALLENGE_LEN bytes the guest asked to be bound in.
 * @rim: the Realm Initial Measurement, CCA_HASH_LEN bytes.
 * @rem: the four Realm Extensible Measurements.
 *
 * Returns a newly allocated array holding the serialized token.  The structure
 * is the real one; the signatures are not.  See the file comment.
 */
GByteArray *cca_build_token(const uint8_t *challenge, const uint8_t *rim,
                            const uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN]);

#endif /* TARGET_ARM_CCA_TOKEN_H */
