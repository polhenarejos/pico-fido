/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _ARKG_H_
#define _ARKG_H_

#ifdef ENABLE_PREVIEW_SIGN

#include <stdint.h>
#include <stddef.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

/* ARKG Algorithm IDs (Yubico experimental COSE assignments) */
#define ARKG_COSE_ALG_ESP256_SPLIT_ARKG  (-65539)  /* ESP256-split using ARKG-P256 */
#define ARKG_COSE_ALG_ARKG_P256          (-65700)  /* ARKG-P256 seed key type */
#define ARKG_COSE_KTY_ARKG               (-65537)  /* ARKG key type */
#define ARKG_COSE_ALG_ESP256             (-9)      /* ESP256 (derived signing key algorithm) */

/* previewSign v4 supported algorithms */
#define PS_ALG_ES256   (-7)   /* Standard ECDSA P-256 */
#define PS_ALG_ESP256  (-9)   /* ECDSA P-256 (two-party compatible) */

/* Key handle structure: [16-byte HMAC tag] [65-byte uncompressed EC point] */
#define ARKG_KH_TAG_LEN     16
#define ARKG_KH_POINT_LEN   65
#define ARKG_KH_LEN         (ARKG_KH_TAG_LEN + ARKG_KH_POINT_LEN)  /* 81 */

/* Key derivation path prefixes (distinct from FIDO's 10022) */
#define PS_PATH_SIGN   10025u  /* Non-ARKG signing key path prefix */

/* DST constants for ARKG-P256 */
#define ARKG_DST_EXT_BL      "ARKG-P256"
#define ARKG_DST_EXT_KEM     "ARKG-ECDH.ARKG-P256"

/*
 * Check if an algorithm ID is supported by previewSign.
 */
static inline int ps_algorithm_supported(int64_t alg) {
    return (alg == PS_ALG_ES256 || alg == PS_ALG_ESP256 ||
            alg == ARKG_COSE_ALG_ESP256_SPLIT_ARKG);
}

/*
 * Check if an algorithm ID is an ARKG algorithm (requires additional_args).
 */
static inline int ps_algorithm_is_arkg(int64_t alg) {
    return (alg == ARKG_COSE_ALG_ESP256_SPLIT_ARKG);
}

/* Non-ARKG signing key functions */

/*
 * Derive a non-ARKG signing keypair deterministically from credential key material.
 * Uses path prefix PS_PATH_SIGN (10025) to derive a key distinct from the FIDO key.
 *
 */
int ps_load_signing_key(const uint8_t *key_seed, mbedtls_ecp_keypair *key);

/*
 * Build an inner AttestationObject for a non-ARKG signing credential.
 * The inner attestation contains a plain ES256 or ESP256 COSE public key.
 *
 */
int ps_build_inner_attestation_object(const uint8_t *rp_id_hash, uint8_t ps_flags,
                                      int64_t ps_algorithm,
                                      const uint8_t *inner_cred_id, size_t inner_cred_id_len,
                                      const mbedtls_ecp_point *pk,
                                      const mbedtls_ecp_group *grp,
                                      uint8_t *buf, size_t buf_len, size_t *out_len);

/* ARKG functions (unchanged) */

/*
 * Derive ARKG seed key pairs deterministically from credential key material.
 * Generates (sk_bl, pk_bl) and (sk_kem, pk_kem) for ARKG-P256.
 *
 */
int arkg_derive_seed_keys(const uint8_t *key_seed, size_t key_seed_len,
                          mbedtls_mpi *sk_bl, mbedtls_ecp_point *pk_bl,
                          mbedtls_mpi *sk_kem, mbedtls_ecp_point *pk_kem);

/*
 * ARKG-Derive-Private-Key: Derive a child private key from the ARKG seed
 * and a key handle produced by the server's ARKG-Derive-Public-Key.
 *
 * Implements: sk' = (sk_bl + tau) mod N
 *   where tau = BL-PRF(KEM-Decaps(sk_kem, kh, ctx_kem), ctx_bl)
 *
 */
int arkg_derive_private_key(const mbedtls_mpi *sk_bl, const mbedtls_mpi *sk_kem,
                            const uint8_t *kh, size_t kh_len,
                            const uint8_t *ctx, size_t ctx_len,
                            mbedtls_ecp_keypair *sk_out);

/*
 * Encode the ARKG public seed as a CBOR COSE key.
 *
 * Output format:
 *   {1: -65537, 3: -65700,
 *    -1: {1:2, 3:-7,  -1:1, -2:<x>, -3:<y>},   // pk_bl
 *    -2: {1:2, 3:-25, -1:1, -2:<x>, -3:<y>},   // pk_kem
 *    -3: -9}                                     // derived key alg
 *
 */
int arkg_encode_cose_public_seed(const mbedtls_ecp_point *pk_bl,
                                 const mbedtls_ecp_point *pk_kem,
                                 const mbedtls_ecp_group *grp,
                                 uint8_t *buf, size_t buf_len, size_t *out_len);

/*
 * Build a complete inner AttestationObject for the ARKG seed credential.
 * Used as the unsigned extension output at key 7 in MakeCredential.
 *
 */
int arkg_build_inner_attestation_object(const uint8_t *rp_id_hash, uint8_t arkg_flags,
                                        const uint8_t *inner_cred_id, size_t inner_cred_id_len,
                                        const mbedtls_ecp_point *pk_bl,
                                        const mbedtls_ecp_point *pk_kem,
                                        const mbedtls_ecp_group *grp,
                                        uint8_t *buf, size_t buf_len, size_t *out_len);

#endif /* ENABLE_PREVIEW_SIGN */
#endif /* _ARKG_H_ */
