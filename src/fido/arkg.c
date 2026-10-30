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

#ifdef ENABLE_PREVIEW_SIGN

#include "picokeys.h"
#include "arkg.h"
#include "fido.h"
#include "ctap2_cbor.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "random.h"
#include "cbor.h"
#include <string.h>

/* Constants */

/* P-256 curve order N (big-endian, 32 bytes) */
static const uint8_t P256_ORDER_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

/* SHA-256 parameters */
#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

/* ARKG hash_to_field L parameter for P-256: ceil((256 + 128) / 8) = 48 */
#define ARKG_HTF_L  48

/* Key derivation path prefixes (distinct from FIDO's 10022) */
#define ARKG_PATH_BL   10023u
#define ARKG_PATH_KEM  10024u

/* RFC 9380: expand_message_xmd */

/*
 * RFC 9380 Section 5.3.1 — expand_message_xmd with SHA-256.
 * Expands msg+DST into len_in_bytes of pseudo-random output.
 */
static int expand_message_xmd(const uint8_t *msg, size_t msg_len,
                               const uint8_t *DST, size_t DST_len,
                               uint8_t *out, size_t len_in_bytes)
{
    size_t ell = (len_in_bytes + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    if (ell > 255 || len_in_bytes > 65535 || DST_len > 255) {
        return -1;
    }

    uint8_t DST_len_byte = (uint8_t)DST_len;
    uint8_t l_i_b_str[2] = {
        (uint8_t)(len_in_bytes >> 8),
        (uint8_t)(len_in_bytes & 0xFF)
    };

    /* Step 7: b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime) */
    uint8_t b_0[SHA256_DIGEST_SIZE];
    {
        uint8_t z_pad[SHA256_BLOCK_SIZE];
        memset(z_pad, 0, sizeof(z_pad));
        uint8_t zero = 0;

        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, z_pad, sizeof(z_pad));
        mbedtls_sha256_update(&ctx, msg, msg_len);
        mbedtls_sha256_update(&ctx, l_i_b_str, 2);
        mbedtls_sha256_update(&ctx, &zero, 1);
        mbedtls_sha256_update(&ctx, DST, DST_len);
        mbedtls_sha256_update(&ctx, &DST_len_byte, 1);
        mbedtls_sha256_finish(&ctx, b_0);
        mbedtls_sha256_free(&ctx);
    }

    /* Steps 8-10: iteratively compute b_1 .. b_ell */
    uint8_t b_prev[SHA256_DIGEST_SIZE];
    uint8_t b_xor[SHA256_DIGEST_SIZE];
    memcpy(b_xor, b_0, SHA256_DIGEST_SIZE);
    size_t written = 0;

    for (size_t i = 1; i <= ell; i++) {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, b_xor, SHA256_DIGEST_SIZE);
        uint8_t i_byte = (uint8_t)i;
        mbedtls_sha256_update(&ctx, &i_byte, 1);
        mbedtls_sha256_update(&ctx, DST, DST_len);
        mbedtls_sha256_update(&ctx, &DST_len_byte, 1);
        mbedtls_sha256_finish(&ctx, b_prev);
        mbedtls_sha256_free(&ctx);

        /* Copy to output */
        size_t to_copy = len_in_bytes - written;
        if (to_copy > SHA256_DIGEST_SIZE) {
            to_copy = SHA256_DIGEST_SIZE;
        }
        memcpy(out + written, b_prev, to_copy);
        written += to_copy;

        /* b_xor = XOR(b_0, b_i) for next iteration */
        for (size_t j = 0; j < SHA256_DIGEST_SIZE; j++) {
            b_xor[j] = b_0[j] ^ b_prev[j];
        }
    }

    return 0;
}

/* RFC 9380: hash_to_field */

/*
 * RFC 9380 Section 5.2 — hash_to_field(msg, count=1).
 * Returns a single field element as an MPI reduced mod p.
 */
static int hash_to_field(const uint8_t *msg, size_t msg_len,
                          const uint8_t *DST, size_t DST_len,
                          const mbedtls_mpi *p,
                          mbedtls_mpi *result)
{
    uint8_t uniform_bytes[ARKG_HTF_L];
    int ret = expand_message_xmd(msg, msg_len, DST, DST_len,
                                  uniform_bytes, ARKG_HTF_L);
    if (ret != 0) {
        return ret;
    }

    /* result = OS2IP(uniform_bytes) mod p */
    mbedtls_mpi tv;
    mbedtls_mpi_init(&tv);
    ret = mbedtls_mpi_read_binary(&tv, uniform_bytes, ARKG_HTF_L);
    if (ret == 0) {
        ret = mbedtls_mpi_mod_mpi(result, &tv, p);
    }
    mbedtls_mpi_free(&tv);
    mbedtls_platform_zeroize(uniform_bytes, sizeof(uniform_bytes));
    return ret;
}

/* ARKG KEM-Decaps */

/*
 * KEM-Decaps: Decapsulate a key handle to recover the ARKG shared secret.
 *
 * kh = [16-byte HMAC tag t] [65-byte uncompressed EC point c']
 *
 * Steps:
 *   1. ECDH(pk_eph=c', sk_kem) → k'
 *   2. prk = HKDF-Extract(SHA256, salt=NULL, IKM=k')
 *   3. mk  = HKDF-Expand(SHA256, prk, "ARKG-KEM-HMAC-mac."||DST||ctx, 32)
 *   4. Verify HMAC-SHA256(mk, c')[:16] == t
 *   5. k   = HKDF-Expand(SHA256, prk, "ARKG-KEM-HMAC-shared."||DST||ctx, 32)
 */
static int kem_decaps(const mbedtls_mpi *sk_kem,
                       const uint8_t *kh, size_t kh_len,
                       const uint8_t *ctx_kem, size_t ctx_kem_len,
                       uint8_t *k_out)
{
    if (kh_len != ARKG_KH_LEN) {
        return -1;
    }

    const uint8_t *t = kh;
    const uint8_t *c_prime = kh + ARKG_KH_TAG_LEN;

    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pk_eph;
    mbedtls_mpi z;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pk_eph);
    mbedtls_mpi_init(&z);

    uint8_t k_prime[SHA256_DIGEST_SIZE] = {0};
    uint8_t prk[SHA256_DIGEST_SIZE] = {0};
    uint8_t mk[SHA256_DIGEST_SIZE] = {0};
    uint8_t hmac_full[SHA256_DIGEST_SIZE] = {0};

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    /* Parse and validate ephemeral public key from c' */
    ret = mbedtls_ecp_point_read_binary(&grp, &pk_eph, c_prime, ARKG_KH_POINT_LEN);
    if (ret != 0) goto cleanup;
    ret = mbedtls_ecp_check_pubkey(&grp, &pk_eph);
    if (ret != 0) goto cleanup;

    /* ECDH: z = X-coordinate of sk_kem * pk_eph */
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &pk_eph, sk_kem,
                                       random_fill_iterator, NULL);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_write_binary(&z, k_prime, SHA256_DIGEST_SIZE);
    if (ret != 0) goto cleanup;

    /*
     * Build HKDF info strings.
     * Base = "ARKG-ECDH.ARKG-P256" (19 bytes) = ARKG_DST_EXT_KEM
     * info_mac    = "ARKG-KEM-HMAC-mac."    (18) || base (19) || ctx_kem
     * info_shared = "ARKG-KEM-HMAC-shared." (21) || base (19) || ctx_kem
     */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const size_t dst_kem_len = strlen(ARKG_DST_EXT_KEM); /* 19 */

    /* prk = HKDF-Extract(SHA256, salt=NULL, IKM=k') */
    ret = mbedtls_hkdf_extract(md, NULL, 0, k_prime, SHA256_DIGEST_SIZE, prk);
    if (ret != 0) goto cleanup;

    /* mk = HKDF-Expand(SHA256, prk, info_mac, 32) */
    {
        uint8_t info[256];
        size_t info_len = 0;
        memcpy(info, "ARKG-KEM-HMAC-mac.", 18);                 info_len = 18;
        memcpy(info + info_len, ARKG_DST_EXT_KEM, dst_kem_len); info_len += dst_kem_len;
        memcpy(info + info_len, ctx_kem, ctx_kem_len);           info_len += ctx_kem_len;
        ret = mbedtls_hkdf_expand(md, prk, SHA256_DIGEST_SIZE,
                                   info, info_len, mk, SHA256_DIGEST_SIZE);
    }
    if (ret != 0) goto cleanup;

    /* t' = HMAC-SHA256(mk, c')[:16] */
    ret = mbedtls_md_hmac(md, mk, SHA256_DIGEST_SIZE,
                           c_prime, ARKG_KH_POINT_LEN, hmac_full);
    if (ret != 0) goto cleanup;

    /* Constant-time tag comparison */
    {
        uint8_t diff = 0;
        for (int i = 0; i < ARKG_KH_TAG_LEN; i++) {
            diff |= t[i] ^ hmac_full[i];
        }
        if (diff != 0) {
            ret = -1; /* HMAC tag mismatch — invalid key handle */
            goto cleanup;
        }
    }

    /* k = HKDF-Expand(SHA256, prk, info_shared, 32) */
    {
        uint8_t info[256];
        size_t info_len = 0;
        memcpy(info, "ARKG-KEM-HMAC-shared.", 21);               info_len = 21;
        memcpy(info + info_len, ARKG_DST_EXT_KEM, dst_kem_len);  info_len += dst_kem_len;
        memcpy(info + info_len, ctx_kem, ctx_kem_len);            info_len += ctx_kem_len;
        ret = mbedtls_hkdf_expand(md, prk, SHA256_DIGEST_SIZE,
                                   info, info_len, k_out, SHA256_DIGEST_SIZE);
    }

cleanup:
    mbedtls_platform_zeroize(k_prime, sizeof(k_prime));
    mbedtls_platform_zeroize(prk, sizeof(prk));
    mbedtls_platform_zeroize(mk, sizeof(mk));
    mbedtls_platform_zeroize(hmac_full, sizeof(hmac_full));
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pk_eph);
    mbedtls_mpi_free(&z);
    return ret;
}

/* ARKG BL-PRF */

/*
 * BL-PRF: Derive the blinding factor tau from the KEM shared secret.
 *
 *   DST_tau = "ARKG-BL-EC." || "ARKG-P256" || ctx_bl
 *   tau = hash_to_field(ikm_tau, 1) with DST=DST_tau, p=N, L=48
 */
static int bl_prf(const uint8_t *ikm_tau, size_t ikm_tau_len,
                   const uint8_t *ctx_bl, size_t ctx_bl_len,
                   mbedtls_mpi *tau)
{
    const size_t dst_bl_len = strlen(ARKG_DST_EXT_BL); /* 9 */

    /* DST_tau = "ARKG-BL-EC." (11) || "ARKG-P256" (9) || ctx_bl */
    uint8_t DST_tau[256];
    size_t DST_tau_len = 0;
    memcpy(DST_tau, "ARKG-BL-EC.", 11);                      DST_tau_len = 11;
    memcpy(DST_tau + DST_tau_len, ARKG_DST_EXT_BL, dst_bl_len); DST_tau_len += dst_bl_len;
    memcpy(DST_tau + DST_tau_len, ctx_bl, ctx_bl_len);        DST_tau_len += ctx_bl_len;

    /* N = P-256 curve order */
    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    int ret = mbedtls_mpi_read_binary(&N, P256_ORDER_N, sizeof(P256_ORDER_N));
    if (ret != 0) {
        mbedtls_mpi_free(&N);
        return ret;
    }

    ret = hash_to_field(ikm_tau, ikm_tau_len,
                         DST_tau, DST_tau_len, &N, tau);

    mbedtls_mpi_free(&N);
    return ret;
}

/* ARKG-Derive-Private-Key */

int arkg_derive_private_key(const mbedtls_mpi *sk_bl, const mbedtls_mpi *sk_kem,
                            const uint8_t *kh, size_t kh_len,
                            const uint8_t *ctx, size_t ctx_len,
                            mbedtls_ecp_keypair *sk_out)
{
    if (kh_len != ARKG_KH_LEN || ctx_len > 64) {
        return -1;
    }

    int ret = 0;

    /*
     * ctx' = I2OSP(LEN(ctx), 1) || ctx
     * ctx_bl  = "ARKG-Derive-Key-BL."  (19) || ctx'
     * ctx_kem = "ARKG-Derive-Key-KEM." (20) || ctx'
     */
    uint8_t ctx_prime[65]; /* 1 + max 64 */
    ctx_prime[0] = (uint8_t)ctx_len;
    if (ctx_len > 0) {
        memcpy(ctx_prime + 1, ctx, ctx_len);
    }
    size_t ctx_prime_len = 1 + ctx_len;

    uint8_t ctx_bl[128];
    size_t ctx_bl_len = 0;
    memcpy(ctx_bl, "ARKG-Derive-Key-BL.", 19);       ctx_bl_len = 19;
    memcpy(ctx_bl + ctx_bl_len, ctx_prime, ctx_prime_len); ctx_bl_len += ctx_prime_len;

    uint8_t ctx_kem[128];
    size_t ctx_kem_len = 0;
    memcpy(ctx_kem, "ARKG-Derive-Key-KEM.", 20);      ctx_kem_len = 20;
    memcpy(ctx_kem + ctx_kem_len, ctx_prime, ctx_prime_len); ctx_kem_len += ctx_prime_len;

    /* Step 1: ikm_tau = KEM-Decaps(sk_kem, kh, ctx_kem) */
    uint8_t ikm_tau[SHA256_DIGEST_SIZE] = {0};
    ret = kem_decaps(sk_kem, kh, kh_len, ctx_kem, ctx_kem_len, ikm_tau);
    if (ret != 0) goto cleanup;

    /* Step 2: tau = BL-PRF(ikm_tau, ctx_bl) */
    mbedtls_mpi tau;
    mbedtls_mpi_init(&tau);
    ret = bl_prf(ikm_tau, SHA256_DIGEST_SIZE, ctx_bl, ctx_bl_len, &tau);
    if (ret != 0) {
        mbedtls_mpi_free(&tau);
        goto cleanup;
    }

    /* Step 3: sk' = (sk_bl + tau) mod N */
    {
        mbedtls_mpi N, sk_derived;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&sk_derived);

        ret = mbedtls_mpi_read_binary(&N, P256_ORDER_N, sizeof(P256_ORDER_N));
        if (ret != 0) goto step3_cleanup;

        ret = mbedtls_mpi_add_mpi(&sk_derived, sk_bl, &tau);
        if (ret != 0) goto step3_cleanup;

        ret = mbedtls_mpi_mod_mpi(&sk_derived, &sk_derived, &N);
        if (ret != 0) goto step3_cleanup;

        /* Load into keypair */
        ret = mbedtls_ecp_group_load(&sk_out->grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) goto step3_cleanup;

        uint8_t sk_bytes[32];
        ret = mbedtls_mpi_write_binary(&sk_derived, sk_bytes, 32);
        if (ret == 0) {
            ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, sk_out, sk_bytes, 32);
        }
        if (ret == 0) {
            ret = mbedtls_ecp_keypair_calc_public(sk_out, random_fill_iterator, NULL);
        }
        mbedtls_platform_zeroize(sk_bytes, sizeof(sk_bytes));

step3_cleanup:
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&sk_derived);
    }
    mbedtls_mpi_free(&tau);

cleanup:
    mbedtls_platform_zeroize(ikm_tau, sizeof(ikm_tau));
    return ret;
}

/* ARKG Seed Key Derivation */

/*
 * Derive one P-256 keypair deterministically using the same HKDF-chain
 * scheme as fido_load_key(), but with a different path prefix constant.
 */
static int arkg_load_key(uint32_t path_id, const uint8_t *cred_id,
                          mbedtls_ecp_keypair *key)
{
    uint8_t key_path[KEY_PATH_LEN];
    memcpy(key_path, cred_id, KEY_PATH_LEN);
    uint32_t key_path_first = 0x80000000u | path_id;
    memcpy(key_path, &key_path_first, sizeof(key_path_first));
    for (size_t i = 1; i < KEY_PATH_ENTRIES; i++) {
        uint32_t part = 0;
        memcpy(&part, key_path + i * sizeof(uint32_t), sizeof(part));
        part |= 0x80000000u;
        memcpy(key_path + i * sizeof(uint32_t), &part, sizeof(part));
    }
    return derive_key(NULL, false, key_path, MBEDTLS_ECP_DP_SECP256R1, key);
}

int arkg_derive_seed_keys(const uint8_t *key_seed, size_t key_seed_len,
                          mbedtls_mpi *sk_bl, mbedtls_ecp_point *pk_bl,
                          mbedtls_mpi *sk_kem, mbedtls_ecp_point *pk_kem)
{
    (void)key_seed_len; /* key_seed is used as KEY_PATH_LEN-sized buffer */

    int ret = 0;
    mbedtls_ecp_keypair bl_key, kem_key;
    mbedtls_ecp_keypair_init(&bl_key);
    mbedtls_ecp_keypair_init(&kem_key);

    /* Derive BL keypair (path prefix 10023) */
    ret = arkg_load_key(ARKG_PATH_BL, key_seed, &bl_key);
    if (ret != 0) goto cleanup;

    /* Derive KEM keypair (path prefix 10024) */
    ret = arkg_load_key(ARKG_PATH_KEM, key_seed, &kem_key);
    if (ret != 0) goto cleanup;

    /* Extract sk and pk from keypairs */
    ret = mbedtls_mpi_copy(sk_bl, &bl_key.d);
    if (ret != 0) goto cleanup;
    ret = mbedtls_ecp_copy(pk_bl, &bl_key.Q);
    if (ret != 0) goto cleanup;
    ret = mbedtls_mpi_copy(sk_kem, &kem_key.d);
    if (ret != 0) goto cleanup;
    ret = mbedtls_ecp_copy(pk_kem, &kem_key.Q);

cleanup:
    mbedtls_ecp_keypair_free(&bl_key);
    mbedtls_ecp_keypair_free(&kem_key);
    return ret;
}

/* COSE Encoding */

/*
 * Encode one EC P-256 public key as a COSE key sub-map.
 * {1: 2 (EC2), 3: alg, -1: 1 (P-256), -2: x, -3: y}
 */
static int encode_ec_cose_subkey(CborEncoder *parent,
                                  const mbedtls_ecp_point *pk,
                                  const mbedtls_ecp_group *grp,
                                  int64_t alg)
{
    uint8_t x[32], y[32];
    int ret = mbedtls_mpi_write_binary(&pk->X, x, 32);
    if (ret != 0) return ret;
    ret = mbedtls_mpi_write_binary(&pk->Y, y, 32);
    if (ret != 0) return ret;
    (void)grp;

    CborEncoder submap;
    CborError err;
    err = cbor_encoder_create_map(parent, &submap, 5);
    if (err) { ret = (int)err; return ret; }

    err = cbor_encode_int(&submap, 1);      if (err) { ret = (int)err; return ret; }
    err = cbor_encode_int(&submap, 2);      if (err) { ret = (int)err; return ret; } /* kty: EC2 */

    err = cbor_encode_int(&submap, 3);      if (err) { ret = (int)err; return ret; }
    err = cbor_encode_int(&submap, alg);    if (err) { ret = (int)err; return ret; } /* alg */

    err = cbor_encode_int(&submap, -1);     if (err) { ret = (int)err; return ret; }
    err = cbor_encode_int(&submap, 1);      if (err) { ret = (int)err; return ret; } /* crv: P-256 */

    err = cbor_encode_int(&submap, -2);     if (err) { ret = (int)err; return ret; }
    err = cbor_encode_byte_string(&submap, x, 32); if (err) { ret = (int)err; return ret; } /* x */

    err = cbor_encode_int(&submap, -3);     if (err) { ret = (int)err; return ret; }
    err = cbor_encode_byte_string(&submap, y, 32); if (err) { ret = (int)err; return ret; } /* y */

    err = cbor_encoder_close_container(parent, &submap);
    ret = (int)err;
    return ret;
}

int arkg_encode_cose_public_seed(const mbedtls_ecp_point *pk_bl,
                                 const mbedtls_ecp_point *pk_kem,
                                 const mbedtls_ecp_group *grp,
                                 uint8_t *buf, size_t buf_len, size_t *out_len)
{
    CborEncoder encoder, mapEnc;
    cbor_encoder_init(&encoder, buf, buf_len, 0);

    CborError err;
    err = cbor_encoder_create_map(&encoder, &mapEnc, 5);
    if (err) return (int)err;

    /* 1: kty = -65537 (ARKG placeholder) */
    err = cbor_encode_int(&mapEnc, 1);                   if (err) return (int)err;
    err = cbor_encode_int(&mapEnc, ARKG_COSE_KTY_ARKG);  if (err) return (int)err;

    /* 3: alg = -65700 (ARKG-P256 placeholder) */
    err = cbor_encode_int(&mapEnc, 3);                       if (err) return (int)err;
    err = cbor_encode_int(&mapEnc, ARKG_COSE_ALG_ARKG_P256); if (err) return (int)err;

    /* -1: pk_bl (ES256 COSE key sub-map, alg=-7) */
    err = cbor_encode_int(&mapEnc, -1);                  if (err) return (int)err;
    {
        int ret = encode_ec_cose_subkey(&mapEnc, pk_bl, grp, FIDO2_ALG_ES256);
        if (ret != 0) return ret;
    }

    /* -2: pk_kem (ECDH-ES COSE key sub-map, alg=-25) */
    err = cbor_encode_int(&mapEnc, -2);                  if (err) return (int)err;
    {
        int ret = encode_ec_cose_subkey(&mapEnc, pk_kem, grp, FIDO2_ALG_ECDH_ES_HKDF_256);
        if (ret != 0) return ret;
    }

    /* -3: derived key algorithm = -9 (ESP256) */
    err = cbor_encode_int(&mapEnc, -3);                  if (err) return (int)err;
    err = cbor_encode_int(&mapEnc, ARKG_COSE_ALG_ESP256); if (err) return (int)err;

    err = cbor_encoder_close_container(&encoder, &mapEnc);
    if (err) return (int)err;

    *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
    return 0;
}

/* Inner Attestation Object Builder */

/*
 * Build the inner attestation object shared by both ARKG and non-ARKG paths.
 * Takes a pre-encoded COSE key and assembles the full attestation structure.
 */
static int ps_build_inner_att_obj_common(const uint8_t *rp_id_hash, uint8_t flags,
                                          const uint8_t *inner_cred_id, size_t inner_cred_id_len,
                                          const uint8_t *cose_key, size_t cose_key_len,
                                          uint8_t *buf, size_t buf_len, size_t *out_len)
{
    /* 1) Encode inner extensions: {"previewSign": {4: flags}} */
    uint8_t inner_ext[64];
    CborEncoder ext_enc, ext_map, ext_ps_map;
    cbor_encoder_init(&ext_enc, inner_ext, sizeof(inner_ext), 0);
    cbor_encoder_create_map(&ext_enc, &ext_map, 1);
    cbor_encode_text_stringz(&ext_map, "previewSign");
    cbor_encoder_create_map(&ext_map, &ext_ps_map, 1);
    cbor_encode_uint(&ext_ps_map, 4);
    cbor_encode_uint(&ext_ps_map, flags);
    cbor_encoder_close_container(&ext_map, &ext_ps_map);
    cbor_encoder_close_container(&ext_enc, &ext_map);
    size_t inner_ext_len = cbor_encoder_get_buffer_size(&ext_enc, inner_ext);

    /* 2) Build inner auth_data bytes */
    uint8_t auth_flags = FIDO2_AUT_FLAG_AT | FIDO2_AUT_FLAG_ED | FIDO2_AUT_FLAG_UP;
    size_t auth_data_len = RP_ID_HASH_LEN       /* rpIdHash */
                         + 1                      /* flags */
                         + 4                      /* counter (0) */
                         + 16                     /* aaguid */
                         + 2                      /* credIdLen */
                         + inner_cred_id_len      /* credId */
                         + cose_key_len           /* publicKey */
                         + inner_ext_len;         /* extensions */

    uint8_t *auth_data = (uint8_t *)calloc(1, auth_data_len);
    if (!auth_data) return -1;

    uint8_t *pa = auth_data;
    memcpy(pa, rp_id_hash, RP_ID_HASH_LEN);              pa += RP_ID_HASH_LEN;
    *pa++ = auth_flags;
    /* counter = 0 (4 bytes big-endian) */
    *pa++ = 0; *pa++ = 0; *pa++ = 0; *pa++ = 0;
    memcpy(pa, aaguid, 16);                               pa += 16;
    /* credId length (big-endian) */
    *pa++ = (uint8_t)(inner_cred_id_len >> 8);
    *pa++ = (uint8_t)(inner_cred_id_len & 0xFF);
    memcpy(pa, inner_cred_id, inner_cred_id_len);         pa += inner_cred_id_len;
    memcpy(pa, cose_key, cose_key_len);                   pa += cose_key_len;
    memcpy(pa, inner_ext, inner_ext_len);                  pa += inner_ext_len;

    /* 3) Build attestation object CBOR: {1: "none", 2: auth_data, 3: {}} */
    CborEncoder att_enc, att_map, empty_map;
    cbor_encoder_init(&att_enc, buf, buf_len, 0);
    CborError err;
    err = cbor_encoder_create_map(&att_enc, &att_map, 3);
    if (err) { free(auth_data); return (int)err; }

    err = cbor_encode_uint(&att_map, 1);
    if (!err) err = cbor_encode_text_stringz(&att_map, "none");
    if (!err) err = cbor_encode_uint(&att_map, 2);
    if (!err) err = cbor_encode_byte_string(&att_map, auth_data, auth_data_len);
    if (!err) err = cbor_encode_uint(&att_map, 3);
    if (!err) err = cbor_encoder_create_map(&att_map, &empty_map, 0);
    if (!err) err = cbor_encoder_close_container(&att_map, &empty_map);
    if (!err) err = cbor_encoder_close_container(&att_enc, &att_map);

    free(auth_data);

    if (err) return (int)err;

    *out_len = cbor_encoder_get_buffer_size(&att_enc, buf);
    return 0;
}

int arkg_build_inner_attestation_object(const uint8_t *rp_id_hash, uint8_t arkg_flags,
                                        const uint8_t *inner_cred_id, size_t inner_cred_id_len,
                                        const mbedtls_ecp_point *pk_bl,
                                        const mbedtls_ecp_point *pk_kem,
                                        const mbedtls_ecp_group *grp,
                                        uint8_t *buf, size_t buf_len, size_t *out_len)
{
    /* Encode ARKG COSE public key */
    uint8_t cose_key[256];
    size_t cose_key_len = 0;
    int ret = arkg_encode_cose_public_seed(pk_bl, pk_kem, grp, cose_key, sizeof(cose_key), &cose_key_len);
    if (ret != 0) return ret;

    return ps_build_inner_att_obj_common(rp_id_hash, arkg_flags,
                                          inner_cred_id, inner_cred_id_len,
                                          cose_key, cose_key_len,
                                          buf, buf_len, out_len);
}

/* Non-ARKG Signing Key Functions */

/* Non-ARKG Signing Key Functions */

int ps_load_signing_key(const uint8_t *key_seed, mbedtls_ecp_keypair *key)
{
    return arkg_load_key(PS_PATH_SIGN, key_seed, key);
}

/*
 * Build an inner AttestationObject for a non-ARKG signing credential.
 * The inner attestation contains a plain ES256 or ESP256 COSE public key.
 */
int ps_build_inner_attestation_object(const uint8_t *rp_id_hash, uint8_t ps_flags,
                                      int64_t ps_algorithm,
                                      const uint8_t *inner_cred_id, size_t inner_cred_id_len,
                                      const mbedtls_ecp_point *pk,
                                      const mbedtls_ecp_group *grp,
                                      uint8_t *buf, size_t buf_len, size_t *out_len)
{
    (void)grp; /* Curve parameters are implicit; we write x/y directly */

    /* Encode the COSE public key: {1:2 (EC2), 3:alg, -1:1 (P-256), -2:x, -3:y} */
    uint8_t x_buf[32], y_buf[32];
    int ret = mbedtls_mpi_write_binary(&pk->X, x_buf, sizeof(x_buf));
    if (ret != 0) return ret;
    ret = mbedtls_mpi_write_binary(&pk->Y, y_buf, sizeof(y_buf));
    if (ret != 0) return ret;

    uint8_t cose_key[128];
    CborEncoder ck_enc, ck_map;
    cbor_encoder_init(&ck_enc, cose_key, sizeof(cose_key), 0);
    CborError err;
    err = cbor_encoder_create_map(&ck_enc, &ck_map, 5);
    if (err) return (int)err;
    err = cbor_encode_int(&ck_map, 1);
    if (!err) err = cbor_encode_int(&ck_map, 2);
    if (!err) err = cbor_encode_int(&ck_map, 3);
    if (!err) err = cbor_encode_int(&ck_map, ps_algorithm);
    if (!err) err = cbor_encode_int(&ck_map, -1);
    if (!err) err = cbor_encode_int(&ck_map, 1);
    if (!err) err = cbor_encode_int(&ck_map, -2);
    if (!err) err = cbor_encode_byte_string(&ck_map, x_buf, sizeof(x_buf));
    if (!err) err = cbor_encode_int(&ck_map, -3);
    if (!err) err = cbor_encode_byte_string(&ck_map, y_buf, sizeof(y_buf));
    if (!err) err = cbor_encoder_close_container(&ck_enc, &ck_map);
    if (err) return (int)err;
    size_t cose_key_len = cbor_encoder_get_buffer_size(&ck_enc, cose_key);

    return ps_build_inner_att_obj_common(rp_id_hash, ps_flags,
                                          inner_cred_id, inner_cred_id_len,
                                          cose_key, cose_key_len,
                                          buf, buf_len, out_len);
}

#endif /* ENABLE_PREVIEW_SIGN */
