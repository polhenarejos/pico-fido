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

#include "picokeys.h"
#include "serial.h"
#include "ctap2_cbor.h"
#include "fido.h"
#include "ctap.h"
#include "hid/ctap_hid.h"
#include "files.h"
#include "credential.h"
#include "apdu.h"
#include "random.h"
#include "button.h"
#include "led/led.h"
#include "compat/board.h"
#include "crypto_utils.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"

#include "vault.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

static const uint8_t vault_id_domain[] = "PicoKeys Vault ID v1";
static const uint8_t vault_enroll_info[] = "PicoKeys Vault enrollment v1";
static const uint8_t vault_blob_magic[] = { 'P', 'K', 'V', 1 };
uint8_t vault_enroll_private[VAULT_X448_BYTES];
uint8_t vault_enroll_public[VAULT_X448_BYTES];
uint8_t vault_enroll_challenge[VAULT_ENROLL_CHALLENGE_BYTES];
bool vault_enroll_active = false;
bool vault_enrollment_button_accepted = false;

static const uint8_t picokeys_vault_ca_der[] = {
    0x30, 0x82, 0x01, 0xEB, 0x30, 0x82, 0x01, 0x6B, 0xA0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x2B, 0x37, 0x6A, 0xC8, 0x98, 0x74, 0xE5, 0x0E, 0x80,
    0x1F, 0xB9, 0x61, 0xCD, 0x25, 0x80, 0x48, 0x17, 0xD6, 0x33, 0xA1, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30,
    0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F,
    0x4B, 0x65, 0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20,
    0x56, 0x61, 0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D,
    0x32, 0x36, 0x30, 0x38, 0x30, 0x35, 0x31, 0x36, 0x34, 0x34, 0x35, 0x36,
    0x5A, 0x17, 0x0D, 0x33, 0x36, 0x30, 0x38, 0x30, 0x32, 0x31, 0x36, 0x34,
    0x34, 0x35, 0x36, 0x5A, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30, 0x0F, 0x06,
    0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65,
    0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20, 0x56, 0x61,
    0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x43, 0x30, 0x05, 0x06, 0x03,
    0x2B, 0x65, 0x71, 0x03, 0x3A, 0x00, 0xE4, 0x0E, 0x8C, 0x62, 0xC6, 0xD3,
    0x6B, 0x06, 0xC4, 0x0A, 0x54, 0x40, 0x7C, 0x82, 0x1F, 0xDD, 0xAE, 0x93,
    0xF2, 0x88, 0x00, 0x9F, 0xDB, 0x10, 0x67, 0x9A, 0x32, 0x47, 0x62, 0xCE,
    0x92, 0x2A, 0xE2, 0x94, 0x2F, 0x40, 0xF4, 0xEC, 0x0A, 0xFE, 0x72, 0xA4,
    0x18, 0x5D, 0x20, 0x4D, 0x55, 0x97, 0x46, 0xE5, 0x94, 0x7D, 0x11, 0xF0,
    0x5C, 0xE6, 0x00, 0xA3, 0x66, 0x30, 0x64, 0x30, 0x1F, 0x06, 0x03, 0x55,
    0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xAE, 0xFB, 0xD5, 0x12,
    0x05, 0xBA, 0x61, 0xD7, 0x67, 0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22,
    0xFA, 0xC7, 0xDC, 0x26, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01,
    0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00,
    0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x06, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04,
    0x16, 0x04, 0x14, 0xAE, 0xFB, 0xD5, 0x12, 0x05, 0xBA, 0x61, 0xD7, 0x67,
    0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22, 0xFA, 0xC7, 0xDC, 0x26, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x03, 0x73, 0x00, 0x0B, 0xB4, 0x4F,
    0x45, 0x1C, 0x36, 0x77, 0xC1, 0x58, 0xDE, 0x39, 0xC0, 0x29, 0xA0, 0x7C,
    0x9F, 0x8F, 0x75, 0xC2, 0x9E, 0xAE, 0x12, 0x41, 0x00, 0xC8, 0xC9, 0x45,
    0xD1, 0xC0, 0xA6, 0x9A, 0x1D, 0xFA, 0x75, 0xE9, 0xB8, 0x82, 0x00, 0xE3,
    0x81, 0xCF, 0x74, 0x35, 0x59, 0x7F, 0x70, 0x06, 0x3A, 0xEC, 0xDF, 0x52,
    0x42, 0x53, 0x0D, 0xC3, 0x3B, 0x80, 0xF1, 0x1E, 0x3F, 0xC4, 0xAD, 0xC8,
    0xCA, 0x07, 0x4E, 0xBD, 0x5E, 0x35, 0xB7, 0x54, 0x63, 0x08, 0x43, 0x4B,
    0xB1, 0xCC, 0x7F, 0x1A, 0x45, 0x4C, 0xE1, 0x34, 0x57, 0x89, 0x57, 0xAA,
    0x08, 0xD5, 0xF6, 0x54, 0xC5, 0xE7, 0x49, 0xC7, 0xBA, 0xD7, 0x79, 0xAE,
    0xD6, 0x11, 0x05, 0x7A, 0xEF, 0x38, 0x97, 0x05, 0x96, 0x13, 0xC6, 0x95,
    0x01, 0x3A, 0x00,
};

uint8_t vault_channel_key[VAULT_CHANNEL_KEY_BYTES];
bool vault_channel_init = false;

int vault_pin_auth(uint8_t protocol, const CborByteString *auth, const uint8_t *raw_params, size_t raw_params_len, uint64_t subcommand) {
    if (!auth->present) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if ((protocol != 1 && protocol != 2) || auth->len != (protocol == 1 ? 16u : 32u)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (raw_params_len > CTAP_MAX_CBOR_PAYLOAD - 34u) {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    uint8_t *payload = calloc(1, 34u + raw_params_len);
    if (!payload) {
        return CTAP2_ERR_PROCESSING;
    }
    memset(payload, 0xff, 32);
    payload[32] = 0x0d;
    payload[33] = (uint8_t)subcommand;
    if (raw_params_len) {
        memcpy(payload + 34, raw_params, raw_params_len);
    }
    int ret = verify(protocol, paut.data, payload, (uint16_t)(34u + raw_params_len), auth->data);
    free(payload);
    if (ret != 0 || !(paut.permissions & CTAP_PERMISSION_ACFG)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

int vault_x448_generate(uint8_t private_key[VAULT_X448_BYTES], uint8_t public_key[VAULT_X448_BYTES]) {
    mbedtls_ecp_keypair key;
    size_t private_len = 0;
    size_t public_len = 0;
    mbedtls_ecp_keypair_init(&key);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE448, &key, random_fill_iterator, NULL);
    if (ret == 0) {
        ret = mbedtls_ecp_write_key_ext(&key, &private_len, private_key, VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&key.grp, &key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, VAULT_X448_BYTES);
    }
    mbedtls_ecp_keypair_free(&key);
    if (ret != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return private_len == VAULT_X448_BYTES && public_len == VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_LENGTH;
}

int vault_x448_shared(const uint8_t private_key[VAULT_X448_BYTES], const uint8_t peer_public[VAULT_X448_BYTES], uint8_t shared[VAULT_X448_BYTES]) {
    mbedtls_ecdh_context ecdh;
    mbedtls_ecp_keypair ours;
    mbedtls_ecp_keypair theirs;
    size_t shared_len = 0;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ecp_keypair_init(&ours);
    mbedtls_ecp_keypair_init(&theirs);
    int ret = mbedtls_ecp_group_load(&ours.grp, MBEDTLS_ECP_DP_CURVE448);
    if (ret == 0) {
        ret = mbedtls_ecp_group_load(&theirs.grp, MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE448, &ours, private_key, VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&theirs.grp, &theirs.Q, peer_public, VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &ours, MBEDTLS_ECDH_OURS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &theirs, MBEDTLS_ECDH_THEIRS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_calc_secret(&ecdh, &shared_len, shared, VAULT_X448_BYTES, random_fill_iterator, NULL);
    }
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ecp_keypair_free(&ours);
    mbedtls_ecp_keypair_free(&theirs);
    if (ret != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return shared_len == VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_LENGTH;
}

int vault_validate_certificate(mbedtls_x509_crt *certificate) {
    if (!certificate) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    mbedtls_x509_crt ca;
    uint32_t flags = 0;
    mbedtls_x509_crt_init(&ca);
    int ret = mbedtls_x509_crt_parse(&ca, picokeys_vault_ca_der, sizeof(picokeys_vault_ca_der));
    if (ret == 0) {
        ret = mbedtls_x509_crt_verify(certificate, &ca, NULL, NULL, &flags, NULL, NULL);
    }
    mbedtls_x509_crt_free(&ca);
    return ret != 0 ? PICOKEYS_EXEC_ERROR : (flags == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED);
}

static int vault_validate_certificate_serial(mbedtls_x509_crt *certificate) {
    if (!certificate || !certificate->subject_alt_names.next) {
        return PICOKEYS_VERIFICATION_FAILED;
    }
    size_t serial_len = strlen(pico_serial_str);
    for (mbedtls_x509_sequence *entry = certificate->subject_alt_names.next; entry; entry = entry->next) {
        mbedtls_x509_subject_alternative_name san = {0};
        int ret = mbedtls_x509_parse_subject_alt_name(&entry->buf, &san);
        if (ret == 0 && (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) && san.san.unstructured_name.len == serial_len && memcmp(san.san.unstructured_name.p, pico_serial_str, serial_len) == 0) {
            mbedtls_x509_free_subject_alt_name(&san);
            return PICOKEYS_OK;
        }
        mbedtls_x509_free_subject_alt_name(&san);
    }
    return PICOKEYS_VERIFICATION_FAILED;
}

static int vault_certificate_x448_public(mbedtls_x509_crt *certificate, uint8_t public_key[VAULT_X448_BYTES]) {
    if (!certificate || !public_key || (mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY && mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY_DH)) {
        return PICOKEYS_WRONG_DATA;
    }
    mbedtls_ecp_keypair *key = mbedtls_pk_ec(certificate->pk);
    if (!key || key->grp.id != MBEDTLS_ECP_DP_CURVE448) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t public_len = 0;
    int ret = mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, VAULT_X448_BYTES);
    return ret == 0 && public_len == VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

int vault_hash_key(const uint8_t key[VAULT_KEY_BYTES], uint8_t digest[VAULT_ID_BYTES]) {
    uint8_t input[sizeof(vault_id_domain) - 1 + VAULT_KEY_BYTES];
    memcpy(input, vault_id_domain, sizeof(vault_id_domain) - 1);
    memcpy(input + sizeof(vault_id_domain) - 1, key, VAULT_KEY_BYTES);
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), input, sizeof(input), digest);
    mbedtls_platform_zeroize(input, sizeof(input));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int vault_layer_key(const uint8_t key[VAULT_KEY_BYTES], const uint8_t vault_id[VAULT_ID_BYTES], const uint8_t credential_hash[VAULT_ID_BYTES], uint8_t algorithm, uint8_t layer, uint8_t out[VAULT_KEY_BYTES]) {
    uint8_t info[sizeof(vault_enroll_info) - 1 + VAULT_ID_BYTES + 2];
    memcpy(info, vault_enroll_info, sizeof(vault_enroll_info) - 1);
    memcpy(info + sizeof(vault_enroll_info) - 1, credential_hash, VAULT_ID_BYTES);
    info[sizeof(vault_enroll_info) - 1 + VAULT_ID_BYTES] = algorithm;
    info[sizeof(vault_enroll_info) - 1 + VAULT_ID_BYTES + 1] = layer;
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), vault_id, VAULT_ID_BYTES, key, VAULT_KEY_BYTES, info, sizeof(info), out, VAULT_KEY_BYTES);
    mbedtls_platform_zeroize(info, sizeof(info));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

bool vault_algorithm_valid(uint8_t algorithm) {
    return algorithm >= VAULT_ALGORITHM_CHACHAPOLY && algorithm <= VAULT_ALGORITHM_AESGCM_CHACHAPOLY;
}

static size_t vault_algorithm_layers(uint8_t algorithm) {
    return algorithm >= VAULT_ALGORITHM_CHACHAPOLY_AESGCM ? 2u : 1u;
}

static uint8_t vault_algorithm_layer(uint8_t algorithm, size_t index) {
    if (algorithm == VAULT_ALGORITHM_CHACHAPOLY_AESGCM) {
        return index == 0 ? VAULT_ALGORITHM_CHACHAPOLY : VAULT_ALGORITHM_AESGCM;
    }
    if (algorithm == VAULT_ALGORITHM_AESGCM_CHACHAPOLY) {
        return index == 0 ? VAULT_ALGORITHM_AESGCM : VAULT_ALGORITHM_CHACHAPOLY;
    }
    return algorithm;
}

static int vault_encrypt_layer(uint8_t algorithm, const uint8_t key[VAULT_KEY_BYTES], const uint8_t nonce[VAULT_BLOB_NONCE_BYTES], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, uint8_t *output, uint8_t tag[16]) {
    int ret = -1;
    if (algorithm == VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, input_len, nonce, aad, aad_len, input, output, tag);
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, nonce, VAULT_BLOB_NONCE_BYTES, aad, aad_len, input, output, 16, tag);
        }
        mbedtls_gcm_free(&gcm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int vault_decrypt_layer(uint8_t algorithm, const uint8_t key[VAULT_KEY_BYTES], const uint8_t nonce[VAULT_BLOB_NONCE_BYTES], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, const uint8_t tag[16], uint8_t *output) {
    int ret = -1;
    if (algorithm == VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, input_len, nonce, aad, aad_len, tag, input, output);
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, input_len, nonce, VAULT_BLOB_NONCE_BYTES, aad, aad_len, tag, 16, input, output);
        }
        mbedtls_gcm_free(&gcm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

int vault_load_key(uint8_t key[VAULT_KEY_BYTES]) {
    if (!key || !ef_vault_key || !file_has_data(ef_vault_key) || file_get_size(ef_vault_key) != VAULT_STORE_LEN) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t keydev[32] = {0};
    int ret = load_keydev(keydev);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(keydev, sizeof(keydev));
        return ret;
    }
    const uint8_t *record = file_get_data(ef_vault_key);
    if (record[0] != PIN_KDF_V2) {
        mbedtls_platform_zeroize(keydev, sizeof(keydev));
        return PICOKEYS_WRONG_DATA;
    }
    ret = decrypt_with_aad(keydev, CONST_BYTE_ARRAY(record + 1, VAULT_STORE_LEN - 1), PIN_KDF_V2, key);
    mbedtls_platform_zeroize(keydev, sizeof(keydev));
    return ret == PICOKEYS_OK ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

static int vault_store_key(const uint8_t key[VAULT_KEY_BYTES]) {
    if (!key || !ef_vault_key) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t keydev[32] = {0};
    uint8_t record[VAULT_STORE_LEN] = {0};
    record[0] = PIN_KDF_V2;
    int ret = load_keydev(keydev);
    if (ret == PICOKEYS_OK) {
        ret = encrypt_with_aad(keydev, CONST_BYTE_ARRAY(key, VAULT_KEY_BYTES), PIN_KDF_V2, record + 1);
    }
    mbedtls_platform_zeroize(keydev, sizeof(keydev));
    if (ret != 0) {
        mbedtls_platform_zeroize(record, sizeof(record));
        return ret == PICOKEYS_OK ? PICOKEYS_EXEC_ERROR : ret;
    }
    ret = file_put_data(ef_vault_key, CONST_BYTE_ARRAY(record, sizeof(record)));
    mbedtls_platform_zeroize(record, sizeof(record));
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    return flash_commit_sync(5000) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

#ifndef ENABLE_EMULATION
static bool vault_enrollment_window_open(void) {
    return board_millis() < (uint32_t)VAULT_ENROLL_WINDOW_MS;
}
#endif

bool vault_enrollment_button_ready(void) {
#ifdef ENABLE_EMULATION
    vault_enrollment_button_accepted = true;
    return true;
#else
    if (!vault_enrollment_window_open() && !vault_enroll_active) {
        vault_enrollment_button_accepted = false;
        button_pressed_duration = 0;
        led_set_mode(MODE_MOUNTED);
        return false;
    }
    if (button_pressed_duration >= VAULT_ENROLL_HOLD_MS) {
        if (!vault_enrollment_button_accepted) {
            led_set_mode(MODE_BUTTON);
        }
        vault_enrollment_button_accepted = true;
    }
    return vault_enrollment_button_accepted;
#endif
}

void vault_enrollment_clear(void) {
    mbedtls_platform_zeroize(vault_enroll_private, sizeof(vault_enroll_private));
    mbedtls_platform_zeroize(vault_enroll_public, sizeof(vault_enroll_public));
    mbedtls_platform_zeroize(vault_enroll_challenge, sizeof(vault_enroll_challenge));
    vault_enroll_active = false;
}

void vault_enrollment_reset(void) {
    vault_enrollment_clear();
    vault_enrollment_button_accepted = false;
#ifndef ENABLE_EMULATION
    button_pressed_duration = 0;
    led_set_mode(MODE_MOUNTED);
#endif
}

static int vault_clear_file(file_t *file) {
    if (!file) {
        return PICOKEYS_OK;
    }
    meta_delete_no_commit(file->fid);
    return flash_clear_file(file);
}

int vault_unenroll(void) {
    int ret = PICOKEYS_OK;
    vault_enrollment_reset();
    mbedtls_platform_zeroize(vault_channel_key, sizeof(vault_channel_key));
    vault_channel_init = false;
    if (ret == PICOKEYS_OK) {
        ret = vault_clear_file(ef_vault_cert);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_clear_file(ef_vault_key);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_clear_file(ef_vault_label);
    }
    if (ret == PICOKEYS_OK && !flash_commit_sync(5000)) {
        ret = PICOKEYS_ERR_MEMORY_FATAL;
    }
    return ret;
}

int vault_enrollment_finish(const uint8_t *packet, size_t packet_len) {
    if (!vault_enroll_active || !packet || packet_len < VAULT_ENROLL_MIN_PACKET_LEN) {
        vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }
    uint16_t certificate_len = ((uint16_t)packet[0] << 8) | packet[1];
    size_t encrypted_len = packet_len - 2 - certificate_len - 12;
    if (certificate_len == 0 || certificate_len > VAULT_ENROLL_CERT_MAX || encrypted_len < VAULT_KEY_BYTES + 16 || encrypted_len > VAULT_ENROLL_PLAIN_MAX + 16) {
        vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }
    mbedtls_x509_crt certificate;
    mbedtls_x509_crt_init(&certificate);
    int ret = mbedtls_x509_crt_parse(&certificate, packet + 2, certificate_len);
    if (ret == 0) {
        ret = vault_validate_certificate(&certificate);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_validate_certificate_serial(&certificate);
    }
    uint8_t certificate_public[VAULT_X448_BYTES] = {0};
    if (ret == PICOKEYS_OK) {
        ret = vault_certificate_x448_public(&certificate, certificate_public);
    }
    mbedtls_x509_crt_free(&certificate);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
        vault_enrollment_reset();
        return PICOKEYS_VERIFICATION_FAILED;
    }
    uint8_t shared[VAULT_X448_BYTES] = {0};
    uint8_t session_key[VAULT_KEY_BYTES] = {0};
    uint8_t info[sizeof(vault_enroll_info) - 1 + VAULT_ENROLL_CHALLENGE_BYTES + VAULT_X448_BYTES * 2] = {0};
    memcpy(info, vault_enroll_info, sizeof(vault_enroll_info) - 1);
    memcpy(info + sizeof(vault_enroll_info) - 1, vault_enroll_challenge, VAULT_ENROLL_CHALLENGE_BYTES);
    memcpy(info + sizeof(vault_enroll_info) - 1 + VAULT_ENROLL_CHALLENGE_BYTES, certificate_public, VAULT_X448_BYTES);
    memcpy(info + sizeof(vault_enroll_info) - 1 + VAULT_ENROLL_CHALLENGE_BYTES + VAULT_X448_BYTES, vault_enroll_public, VAULT_X448_BYTES);
    ret = vault_x448_shared(vault_enroll_private, certificate_public, shared);
    if (ret == PICOKEYS_OK) {
        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, shared, sizeof(shared), info, sizeof(info), session_key, sizeof(session_key));
    }
    uint8_t kvault[VAULT_KEY_BYTES] = {0};
    uint8_t enrollment_plain[VAULT_ENROLL_PLAIN_MAX] = {0};
    size_t label_len = 0;
    if (ret == PICOKEYS_OK) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, encrypted_len - 16, packet + 2 + certificate_len, 12, info, sizeof(info), packet + 2 + certificate_len + 12 + encrypted_len - 16, 16, packet + 2 + certificate_len + 12, enrollment_plain);
        }
        mbedtls_gcm_free(&gcm);
    }
    if (ret == 0 && encrypted_len - 16 == VAULT_KEY_BYTES) {
        memcpy(kvault, enrollment_plain, VAULT_KEY_BYTES);
    }
    else if (ret == 0 && encrypted_len - 16 >= VAULT_KEY_BYTES + 1 && enrollment_plain[VAULT_KEY_BYTES] <= VAULT_LABEL_MAX && encrypted_len - 16 == (size_t)VAULT_KEY_BYTES + 1u + enrollment_plain[VAULT_KEY_BYTES]) {
        memcpy(kvault, enrollment_plain, VAULT_KEY_BYTES);
        label_len = enrollment_plain[VAULT_KEY_BYTES];
    }
    else if (ret == 0) {
        ret = PICOKEYS_WRONG_LENGTH;
    }
    if (ret == 0) {
        ret = vault_store_key(kvault);
    }
    if (ret == 0 && ef_vault_label) {
        if (label_len > 0) {
            ret = file_put_data(ef_vault_label, CONST_BYTE_ARRAY(enrollment_plain + VAULT_KEY_BYTES + 1, label_len));
        }
        else {
            ret = vault_clear_file(ef_vault_label);
        }
        if (ret == PICOKEYS_OK && !flash_commit_sync(5000)) {
            ret = PICOKEYS_ERR_MEMORY_FATAL;
        }
    }
    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_platform_zeroize(session_key, sizeof(session_key));
    mbedtls_platform_zeroize(info, sizeof(info));
    mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(enrollment_plain, sizeof(enrollment_plain));
    vault_enrollment_reset();
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

static int vault_sha256(const uint8_t *data, size_t data_len, uint8_t digest[VAULT_ID_BYTES]) {
    if (!data || !digest) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, data_len, digest) == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int vault_export_blob(const uint8_t *requested_id, size_t requested_id_len, uint8_t algorithm, uint8_t *blob, size_t blob_capacity, size_t *blob_len, uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len) {
    if (!requested_id || requested_id_len == 0 || requested_id_len > MAX_CRED_ID_LENGTH || !blob || !blob_len || !metadata || !metadata_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!vault_algorithm_valid(algorithm)) {
        return PICOKEYS_WRONG_DATA;
    }
    Credential credential = {0};
    file_t *found = NULL;
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = {0};
    int ret = PICOKEYS_ERR_FILE_NOT_FOUND;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS && !found; i++) {
        file_t *ef = file_search((uint16_t)(EF_CRED + i));
        if (!file_has_data(ef) || credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
            continue;
        }
        Credential current = {0};
        if (credential_load_resident(ef, rp_id_hash, &current) == 0) {
            if ((current.id.len == requested_id_len && mbedtls_ct_memcmp(current.id.data, requested_id, requested_id_len) == 0) || credential_resident_matches_id(ef, requested_id, requested_id_len)) {
                credential = current;
                found = ef;
            }
            else {
                credential_free(&current);
            }
        }
    }
    if (!found) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    const uint8_t *key_seed = credential.id.data;
    if (credential.residentId.present && credential_resident_id_uses_stable_keys(credential.residentId.data, credential.residentId.len)) {
        key_seed = credential.residentId.data;
    }
    mbedtls_ecp_keypair credential_key;
    mbedtls_ecp_keypair_init(&credential_key);
    uint8_t private_key[80] = {0};
    size_t private_len = 0;
    ret = PICOKEYS_OK;
    if (credential.privateKey.present) {
        private_len = credential.privateKey.len;
        if (private_len <= sizeof(private_key)) {
            memcpy(private_key, credential.privateKey.data, private_len);
        }
        else ret = PICOKEYS_WRONG_LENGTH;
    }
    else {
        ret = fido_load_key((int)credential.curve, key_seed, &credential_key);
        if (ret == 0) {
            ret = mbedtls_ecp_write_key_ext(&credential_key, &private_len, private_key, sizeof(private_key));
        }
    }
    mbedtls_ecp_keypair_free(&credential_key);
    if (ret != 0 || private_len == 0) {
        credential_free(&credential);
        mbedtls_platform_zeroize(private_key, sizeof(private_key));
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t embedded_metadata[VAULT_CREDENTIAL_METADATA_MAX] = {0};
    if (vault_encode_credential_metadata(&credential, rp_id_hash, embedded_metadata, sizeof(embedded_metadata), metadata_len) != PICOKEYS_OK || *metadata_len > metadata_capacity) {
        credential_free(&credential);
        mbedtls_platform_zeroize(private_key, sizeof(private_key));
        return PICOKEYS_ERR_NO_MEMORY;
    }
    memcpy(metadata, embedded_metadata, *metadata_len);
    uint8_t plain[VAULT_PLAIN_MAX] = {0};
    CborEncoder plain_encoder, plain_map;
    CborError error = CborNoError;
    cbor_encoder_init(&plain_encoder, plain, sizeof(plain), 0);
    if ((error = cbor_encoder_create_map(&plain_encoder, &plain_map, 6)) == CborNoError) {
        error = cbor_encode_uint(&plain_map, 1);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 1);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 2);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, credential.id.data, credential.id.len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 3);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, private_key, private_len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 4);
    }
    if (error == CborNoError) {
        error = cbor_encode_text_string(&plain_map, credential.rpId.data, credential.rpId.len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 5);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, embedded_metadata, *metadata_len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 6);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, requested_id, requested_id_len);
    }
    if (error == CborNoError) {
        error = cbor_encoder_close_container(&plain_encoder, &plain_map);
    }
    size_t plain_len = cbor_encoder_get_buffer_size(&plain_encoder, plain);
    uint8_t kvault[VAULT_KEY_BYTES] = {0};
    uint8_t vault_id[VAULT_ID_BYTES] = {0};
    uint8_t credential_hash[VAULT_ID_BYTES] = {0};
    uint8_t blob_keys[2][VAULT_KEY_BYTES] = {0};
    size_t layer_count = vault_algorithm_layers(algorithm);
    size_t nonce_len = layer_count * VAULT_BLOB_NONCE_BYTES;
    size_t total_len = VAULT_BLOB_HEADER_LEN + nonce_len + plain_len + layer_count * 16;
    if (error == CborNoError && vault_load_key(kvault) != PICOKEYS_OK) {
        error = CborErrorImproperValue;
    }
    if (error == CborNoError && (vault_hash_key(kvault, vault_id) != PICOKEYS_OK || vault_sha256(requested_id, requested_id_len, credential_hash) != PICOKEYS_OK)) {
        error = CborErrorImproperValue;
    }
    if (error == CborNoError) {
        for (size_t layer = 0; layer < layer_count; layer++) {
            if (vault_layer_key(kvault, vault_id, credential_hash, algorithm, (uint8_t)layer, blob_keys[layer]) != PICOKEYS_OK) {
                error = CborErrorImproperValue;
                break;
            }
        }
    }
    if (error == CborNoError && (total_len > blob_capacity || plain_len == 0)) {
        error = CborErrorOutOfMemory;
    }
    if (error == CborNoError) {
        memcpy(blob, vault_blob_magic, sizeof(vault_blob_magic));
        memcpy(blob + 4, vault_id, VAULT_ID_BYTES);
        memcpy(blob + 4 + VAULT_ID_BYTES, credential_hash, VAULT_ID_BYTES);
        blob[VAULT_BLOB_SERIAL_LEN_OFFSET] = sizeof(pico_serial.id);
        memcpy(blob + VAULT_BLOB_SERIAL_OFFSET, pico_serial.id, sizeof(pico_serial.id));
        blob[VAULT_BLOB_ALGORITHM_OFFSET] = algorithm;
        random_fill_buffer(BYTE_ARRAY(blob + VAULT_BLOB_HEADER_LEN, nonce_len));
        if (layer_count == 1) {
            uint8_t algorithm_layer = vault_algorithm_layer(algorithm, 0);
            error = vault_encrypt_layer(algorithm_layer, blob_keys[0], blob + VAULT_BLOB_HEADER_LEN, blob, VAULT_BLOB_HEADER_LEN, plain, plain_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len + plain_len) == PICOKEYS_OK ? CborNoError : CborErrorImproperValue;
        }
        else {
            uint8_t intermediate[VAULT_PLAIN_MAX + 16] = {0};
            uint8_t first_algorithm = vault_algorithm_layer(algorithm, 0);
            uint8_t second_algorithm = vault_algorithm_layer(algorithm, 1);
            if (vault_encrypt_layer(first_algorithm, blob_keys[0], blob + VAULT_BLOB_HEADER_LEN, blob, VAULT_BLOB_HEADER_LEN, plain, plain_len, intermediate, intermediate + plain_len) != PICOKEYS_OK || vault_encrypt_layer(second_algorithm, blob_keys[1], blob + VAULT_BLOB_HEADER_LEN + VAULT_BLOB_NONCE_BYTES, blob, VAULT_BLOB_HEADER_LEN, intermediate, plain_len + 16, blob + VAULT_BLOB_HEADER_LEN + nonce_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len + plain_len + 16) != PICOKEYS_OK) {
                error = CborErrorImproperValue;
            }
            mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
        }
        *blob_len = total_len;
    }
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(blob_keys, sizeof(blob_keys));
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    mbedtls_platform_zeroize(embedded_metadata, sizeof(embedded_metadata));
    credential_free(&credential);
    return error == CborNoError ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int vault_import_blob(const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len < VAULT_BLOB_HEADER_LEN + VAULT_BLOB_NONCE_BYTES + 16) {
        return PICOKEYS_WRONG_DATA;
    }
    if (memcmp(blob, vault_blob_magic, sizeof(vault_blob_magic)) != 0) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t header_len = VAULT_BLOB_HEADER_LEN;
    uint8_t algorithm = blob[VAULT_BLOB_ALGORITHM_OFFSET];
    if (!vault_algorithm_valid(algorithm)) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t layer_count = vault_algorithm_layers(algorithm);
    size_t nonce_len = layer_count * VAULT_BLOB_NONCE_BYTES;
    if (blob_len < header_len + nonce_len + layer_count * 16) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t kvault[VAULT_KEY_BYTES] = {0};
    uint8_t vault_id[VAULT_ID_BYTES] = {0};
    uint8_t blob_keys[2][VAULT_KEY_BYTES] = {0};
    uint8_t plain[VAULT_PLAIN_MAX] = {0};
    uint8_t intermediate[VAULT_PLAIN_MAX + 16] = {0};
    int ret = vault_load_key(kvault);
    if (ret == PICOKEYS_OK) {
        ret = vault_hash_key(kvault, vault_id);
    }
    if (ret == PICOKEYS_OK && mbedtls_ct_memcmp(vault_id, blob + 4, VAULT_ID_BYTES) != 0) {
        ret = PICOKEYS_VERIFICATION_FAILED;
    }
    if (ret == PICOKEYS_OK) {
        for (size_t layer = 0; layer < layer_count; layer++) {
            ret = vault_layer_key(kvault, vault_id, blob + 4 + VAULT_ID_BYTES, algorithm, (uint8_t)layer, blob_keys[layer]);
            if (ret != PICOKEYS_OK) {
                break;
            }
        }
    }
    size_t encrypted_len = blob_len - header_len - nonce_len;
    size_t plain_len = encrypted_len - layer_count * 16;
    if (ret == PICOKEYS_OK && plain_len > sizeof(plain)) {
        ret = PICOKEYS_WRONG_LENGTH;
    }
    if (ret == PICOKEYS_OK) {
        if (layer_count == 1) {
            uint8_t algorithm_layer = vault_algorithm_layer(algorithm, 0);
            ret = vault_decrypt_layer(algorithm_layer, blob_keys[0], blob + header_len, blob, header_len, blob + header_len + nonce_len, plain_len, blob + blob_len - 16, plain);
        }
        else {
            uint8_t first_algorithm = vault_algorithm_layer(algorithm, 0);
            uint8_t second_algorithm = vault_algorithm_layer(algorithm, 1);
            ret = vault_decrypt_layer(second_algorithm, blob_keys[1], blob + header_len + VAULT_BLOB_NONCE_BYTES, blob, header_len, blob + header_len + nonce_len, plain_len + 16, blob + blob_len - 16, intermediate);
            if (ret == PICOKEYS_OK) {
                ret = vault_decrypt_layer(first_algorithm, blob_keys[0], blob + header_len, blob, header_len, intermediate, plain_len, intermediate + plain_len, plain);
            }
        }
    }
    CborByteString credential_id = {0}, private_key = {0}, metadata = {0}, rp_id_hash = {0};
    CborParser parser, metadata_parser;
    CborValue map, metadata_map;
    CborError error = CborNoError;
    if (ret == PICOKEYS_OK) {
        CBOR_CHECK(cbor_parser_init(plain, plain_len, 0, &parser, &map));
        CBOR_PARSE_MAP_START(map, 1)
        {
            uint64_t key = 0;
            CBOR_FIELD_GET_UINT(key, 1);
            if (key == 0x02) { CBOR_FIELD_GET_BYTES(credential_id, 1); }
            else if (key == 0x03) { CBOR_FIELD_GET_BYTES(private_key, 1); }
            else if (key == 0x05) { CBOR_FIELD_GET_BYTES(metadata, 1); }
            else { CBOR_ADVANCE(1); }
        }
        CBOR_PARSE_MAP_END(map, 1);
        CBOR_CHECK(cbor_parser_init(metadata.data, metadata.len, 0, &metadata_parser, &metadata_map));
        CBOR_PARSE_MAP_START(metadata_map, 2)
        {
            uint64_t key = 0;
            CBOR_FIELD_GET_UINT(key, 2);
            if (key == 0x02) { CBOR_FIELD_GET_BYTES(rp_id_hash, 2); }
            else { CBOR_ADVANCE(2); }
        }
        CBOR_PARSE_MAP_END(metadata_map, 2);
        if (!credential_id.present || !private_key.present || !metadata.present || !rp_id_hash.present || rp_id_hash.len != RP_ID_HASH_LEN) {
            error = CborErrorImproperValue;
        }
    }
    if (ret == PICOKEYS_OK && error == CborNoError) {
        ret = credential_import(credential_id.data, credential_id.len, rp_id_hash.data, metadata.data, metadata.len, private_key.data, private_key.len);
    }
err:
    CBOR_FREE_BYTE_STRING(credential_id);
    CBOR_FREE_BYTE_STRING(private_key);
    CBOR_FREE_BYTE_STRING(metadata);
    CBOR_FREE_BYTE_STRING(rp_id_hash);
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(blob_keys, sizeof(blob_keys));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
    if (error != CborNoError) {
        return PICOKEYS_WRONG_DATA;
    }
    return ret == 0 ? PICOKEYS_OK : ret;
}

int vault_encode_credential_metadata(const Credential *credential, const uint8_t rp_id_hash[RP_ID_HASH_LEN], uint8_t *buffer, size_t buffer_len, size_t *metadata_len) {
    if (!credential || !rp_id_hash || !buffer || !metadata_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    cbor_encoder_init(&encoder, buffer, buffer_len, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, CborIndefiniteLength));
    if (credential->rpId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->rpId.data, credential->rpId.len));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, RP_ID_HASH_LEN));
    if (credential->userId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, credential->userId.data, credential->userId.len));
    }
    if (credential->userName.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->userName.data, credential->userName.len));
    }
    if (credential->userDisplayName.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->userDisplayName.data, credential->userDisplayName.len));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, credential->board_creation));
    if (credential->extensions.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, CborIndefiniteLength));
        if (credential->extensions.credBlob.present) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, credential->extensions.credBlob.data, credential->extensions.credBlob.len));
        }
        if (credential->extensions.credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, credential->extensions.credProtect));
        }
        if (credential->extensions.hmac_secret != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, *credential->extensions.hmac_secret));
        }
        if (credential->extensions.largeBlobKey == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        if (credential->extensions.thirdPartyPayment == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, credential->use_sign_count == ptrue));
    if (credential->alg != FIDO2_ALG_ES256 || credential->curve != FIDO2_CURVE_P256) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
        CBOR_CHECK(cbor_encode_int(&mapEncoder, credential->alg));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
        CBOR_CHECK(cbor_encode_int(&mapEncoder, credential->curve));
    }
    if (credential->opts.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, CborIndefiniteLength));
        if (credential->opts.rk != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, credential->opts.rk == ptrue));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (credential->rtc_creation != 0) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, credential->rtc_creation));
    }
    if (credential->residentId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0D));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, credential->residentId.data, credential->residentId.len));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    *metadata_len = cbor_encoder_get_buffer_size(&encoder, buffer);
    return PICOKEYS_OK;
err:
    return PICOKEYS_ERR_NO_MEMORY;
}

CborError vault_vendor_command(uint64_t vendorCmd, CborByteString vendorParam, CborByteString pinUvAuthParam, uint64_t pinUvAuthProtocol, const uint8_t *raw_vendor_params, size_t raw_vendor_params_len, uint64_t vault_algorithm, bool vault_algorithm_present, CborByteString *requested_id, CborEncoder encoder, size_t *resp_size, bool *response_handled, int *ctap_error) {
    CborError error = CborNoError;
    CborEncoder mapEncoder;
    int ret = 0;
    bool response_started = false;
    *resp_size = 0;
    *response_handled = false;
    *ctap_error = 0;
#define VAULT_CBOR_ERROR(e) do { *ctap_error = (e); goto err; } while (0)
    if (vendorCmd == 0x05) {
        uint8_t kvault[VAULT_KEY_BYTES] = {0};
        uint8_t vault_id[VAULT_ID_BYTES] = {0};
        bool stored = ef_vault_key && file_has_data(ef_vault_key) && file_get_size(ef_vault_key) == VAULT_STORE_LEN && file_get_data(ef_vault_key)[0] == PIN_KDF_V2;
        bool enrolled = vault_load_key(kvault) == PICOKEYS_OK;
        if (enrolled && vault_hash_key(kvault, vault_id) != PICOKEYS_OK) {
            mbedtls_platform_zeroize(kvault, sizeof(kvault));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        const uint8_t *label_data = NULL;
        size_t label_len = 0;
        if (ef_vault_label && file_has_data(ef_vault_label) && file_get_size(ef_vault_label) <= VAULT_LABEL_MAX) {
            label_data = file_get_data(ef_vault_label);
            label_len = file_get_size(ef_vault_label);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 5));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_id, enrolled ? sizeof(vault_id) : 0));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, vault_enrollment_button_ready()));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, board_millis()));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, stored));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, label_data ? (const char *)label_data : "", label_len));
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
    }
    else if (vendorCmd == 0x06) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (!vault_enrollment_button_ready()) {
            VAULT_CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        vault_enrollment_clear();
        if (vault_x448_generate(vault_enroll_private, vault_enroll_public) != PICOKEYS_OK) {
            vault_enrollment_reset();
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        random_fill_buffer(BYTE_ARRAY(vault_enroll_challenge, sizeof(vault_enroll_challenge)));
        vault_enroll_active = true;
#ifndef ENABLE_EMULATION
        led_set_mode(MODE_BUTTON);
#endif
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_enroll_public, sizeof(vault_enroll_public)));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_enroll_challenge, sizeof(vault_enroll_challenge)));
    }
    else if (vendorCmd == 0x07) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (!vendorParam.present || vault_enrollment_finish(vendorParam.data, vendorParam.len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        uint8_t kvault[VAULT_KEY_BYTES] = {0};
        uint8_t vault_id[VAULT_ID_BYTES] = {0};
        if (vault_load_key(kvault) != PICOKEYS_OK || vault_hash_key(kvault, vault_id) != PICOKEYS_OK) {
            mbedtls_platform_zeroize(kvault, sizeof(kvault));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_id, sizeof(vault_id)));
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
    }
    else if (vendorCmd == 0x0A) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (vault_unenroll() != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        goto err;
    }
    else if (vendorCmd == 0x08) {
        if (!vendorParam.present || vendorParam.len == 0) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        uint8_t blob[VAULT_BLOB_MAX] = {0};
        uint8_t metadata[VAULT_CREDENTIAL_METADATA_MAX] = {0};
        size_t blob_len = 0;
        size_t metadata_len = 0;
        uint8_t algorithm = VAULT_ALGORITHM_CHACHAPOLY;
        if (vault_algorithm_present) {
            if (vault_algorithm > UINT8_MAX || !vault_algorithm_valid((uint8_t)vault_algorithm)) {
                VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            algorithm = (uint8_t)vault_algorithm;
        }
        if (vault_export_blob(vendorParam.data, vendorParam.len, algorithm, blob, sizeof(blob), &blob_len, metadata, sizeof(metadata), &metadata_len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, blob, blob_len));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, metadata, metadata_len));
        mbedtls_platform_zeroize(blob, sizeof(blob));
        mbedtls_platform_zeroize(metadata, sizeof(metadata));
    }
    else if (vendorCmd == 0x09) {
        if (!vendorParam.present || vendorParam.len == 0) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (vault_import_blob(vendorParam.data, vendorParam.len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 0));
        response_started = true;
    }
    else if (vendorCmd == 0x01) {
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        if (ef_vault_cert && file_has_data(ef_vault_cert)) {
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_vault_cert), file_get_size(ef_vault_cert)));
        }
        else {
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, NULL, 0));
        }
    }
    else if (vendorCmd == 0x02) {
        if (!ef_vault_cert || !vendorParam.present || vendorParam.len == 0 || vendorParam.len > 1900) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);
            ret = mbedtls_x509_crt_parse(&cert, vendorParam.data, vendorParam.len);
        if (ret == PICOKEYS_OK) {
            ret = vault_validate_certificate(&cert);
        }
        mbedtls_x509_crt_free(&cert);
        if (ret != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        file_put_data(ef_vault_cert, CONST_BYTE_ARRAY(vendorParam.data, vendorParam.len));
        flash_commit();
        goto err;
    }
    else if (vendorCmd == 0x03) {
        if (!ef_vault_cert || !file_has_data(ef_vault_cert) || !vendorParam.present ||
            vendorParam.len == 0 || vendorParam.len > 1900 ||
            vendorParam.len != file_get_size(ef_vault_cert) ||
            memcmp(vendorParam.data, file_get_data(ef_vault_cert), vendorParam.len) != 0) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }

        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);
            ret = mbedtls_x509_crt_parse(&cert, vendorParam.data, vendorParam.len);
        if (ret == PICOKEYS_OK) {
            ret = vault_validate_certificate(&cert);
        }
        uint8_t vault_public[VAULT_X448_BYTES] = {0};
        size_t vault_public_len = 0;
        if (ret == PICOKEYS_OK && (mbedtls_pk_get_type(&cert.pk) == MBEDTLS_PK_ECKEY || mbedtls_pk_get_type(&cert.pk) == MBEDTLS_PK_ECKEY_DH)) {
            mbedtls_ecp_keypair *key = mbedtls_pk_ec(cert.pk);
            if (key && key->grp.id == MBEDTLS_ECP_DP_CURVE448) {
                ret = mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &vault_public_len, vault_public, sizeof(vault_public));
            }
            else {
                ret = PICOKEYS_WRONG_DATA;
            }
        }
        else {
            ret = PICOKEYS_WRONG_DATA;
        }
        mbedtls_x509_crt_free(&cert);
        if (ret != PICOKEYS_OK || vault_public_len != VAULT_X448_BYTES) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }

        uint8_t ephemeral_private[VAULT_X448_BYTES] = {0};
        uint8_t ephemeral_public[VAULT_X448_BYTES] = {0};
        uint8_t shared[VAULT_X448_BYTES] = {0};
        if (vault_x448_generate(ephemeral_private, ephemeral_public) != PICOKEYS_OK ||
            vault_x448_shared(ephemeral_private, vault_public, shared) != PICOKEYS_OK) {
            mbedtls_platform_zeroize(ephemeral_private, sizeof(ephemeral_private));
            mbedtls_platform_zeroize(shared, sizeof(shared));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t info[sizeof(VAULT_CHANNEL_INFO) - 1 + VAULT_X448_BYTES * 2] = {0};
        memcpy(info, VAULT_CHANNEL_INFO, sizeof(VAULT_CHANNEL_INFO) - 1);
        memcpy(info + sizeof(VAULT_CHANNEL_INFO) - 1, vault_public, VAULT_X448_BYTES);
        memcpy(info + sizeof(VAULT_CHANNEL_INFO) - 1 + VAULT_X448_BYTES, ephemeral_public, VAULT_X448_BYTES);
        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, shared, sizeof(shared), info, sizeof(info), vault_channel_key, sizeof(vault_channel_key));
        mbedtls_platform_zeroize(ephemeral_private, sizeof(ephemeral_private));
        mbedtls_platform_zeroize(shared, sizeof(shared));
        mbedtls_platform_zeroize(info, sizeof(info));
        if (ret != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        vault_channel_init = true;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, ephemeral_public, sizeof(ephemeral_public)));
    }
    else if (vendorCmd == 0x04) {
        if (!vault_channel_init || !vendorParam.present || vendorParam.len < 12 + 16) {
            VAULT_CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam,
                                      raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        size_t encrypted_len = vendorParam.len - 12;
        size_t request_len = encrypted_len - 16;
        printf("Vault request length: %zu\n", request_len);
        uint8_t *request = calloc(1, request_len);
        if (!request) {
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, vault_channel_key);
            ret = mbedtls_chachapoly_auth_decrypt(&chatx, request_len, vendorParam.data, NULL, 0, vendorParam.data + vendorParam.len - 16, vendorParam.data + 12, request);
        mbedtls_chachapoly_free(&chatx);
        if (ret != 0) {
            mbedtls_platform_zeroize(request, request_len);
            free(request);
            VAULT_CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        CborParser request_parser;
        CborValue request_map;
        DEBUG_DATA(request, request_len);
        CBOR_CHECK(cbor_parser_init(request, request_len, 0, &request_parser, &request_map));
        CBOR_PARSE_MAP_START(request_map, 5)
        {
            uint64_t key = 0;
            CBOR_FIELD_GET_UINT(key, 5);
            if (key == 0x01) {
                CBOR_FIELD_GET_BYTES(*requested_id, 5);
            }
            else {
                CBOR_ADVANCE(5);
            }
        }
        CBOR_PARSE_MAP_END(request_map, 5);
        mbedtls_platform_zeroize(request, request_len);
        free(request);
        if (!requested_id->present || requested_id->len == 0) {
                            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }

        Credential credential = {0};
        file_t *found = NULL;
        uint8_t rp_id_hash[RP_ID_HASH_LEN] = {0};
        for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS && !found; i++) {
            file_t *ef = file_search((uint16_t)(EF_CRED + i));
            if (!file_has_data(ef) || credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
                continue;
            }
            Credential current = {0};
            if (credential_load_resident(ef, rp_id_hash, &current) == 0) {
                if ((current.id.len == requested_id->len &&
                     mbedtls_ct_memcmp(current.id.data, requested_id->data, requested_id->len) == 0) ||
                    credential_resident_matches_id(ef, requested_id->data, requested_id->len)) {
                    credential = current;
                    found = ef;
                }
                else {
                    credential_free(&current);
                }
            }
        }
        if (!found) {
            credential_free(&credential);
            VAULT_CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }

        const uint8_t *key_seed = credential.id.data;
        if (credential.residentId.present &&
            credential_resident_id_uses_stable_keys(credential.residentId.data, credential.residentId.len)) {
            key_seed = credential.residentId.data;
        }
        mbedtls_ecp_keypair credential_key;
        mbedtls_ecp_keypair_init(&credential_key);
        ret = fido_load_key((int)credential.curve, key_seed, &credential_key);
        if (ret != 0) {
            mbedtls_ecp_keypair_free(&credential_key);
            credential_free(&credential);
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t private_key[80] = {0};
        size_t private_len = 0;
        ret = mbedtls_ecp_write_key_ext(&credential_key, &private_len, private_key, sizeof(private_key));
        mbedtls_ecp_keypair_free(&credential_key);
        if (ret != 0 || private_len == 0) {
            credential_free(&credential);
            mbedtls_platform_zeroize(private_key, sizeof(private_key));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t credential_metadata[VAULT_CREDENTIAL_METADATA_MAX] = {0};
        size_t metadata_len = 0;
        ret = vault_encode_credential_metadata(&credential, rp_id_hash, credential_metadata, sizeof(credential_metadata), &metadata_len);
        if (ret != PICOKEYS_OK) {
            credential_free(&credential);
            mbedtls_platform_zeroize(private_key, sizeof(private_key));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t plain[MAX_CRED_ID_LENGTH + VAULT_CREDENTIAL_METADATA_MAX] = {0};
        cbor_encoder_init(&encoder, plain, sizeof(plain), 0);
        CborEncoder plain_map;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &plain_map, 6));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x01));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 1));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&plain_map, credential.id.data, credential.id.len));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x03));
        CBOR_CHECK(cbor_encode_byte_string(&plain_map, private_key, private_len));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x04));
        CBOR_CHECK(cbor_encode_text_string(&plain_map, credential.rpId.data, credential.rpId.len));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x05));
        CBOR_CHECK(cbor_encode_byte_string(&plain_map, credential_metadata, metadata_len));
        CBOR_CHECK(cbor_encode_uint(&plain_map, 0x06));
        CBOR_CHECK(cbor_encode_byte_string(&plain_map, requested_id->data, requested_id->len));
        CBOR_CHECK(cbor_encoder_close_container(&encoder, &plain_map));
        size_t plain_len = cbor_encoder_get_buffer_size(&encoder, plain);
        printf("Vault credential plain length: %zu metadata length: %zu\n", plain_len, metadata_len);
        uint8_t envelope[MAX_CRED_ID_LENGTH + VAULT_CREDENTIAL_METADATA_MAX + 28] = {0};
        random_fill_buffer(BYTE_ARRAY(envelope, 12));
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, vault_channel_key);
        ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, plain_len, envelope, NULL, 0, plain, envelope + 12, envelope + 12 + plain_len);
        mbedtls_chachapoly_free(&chatx);
        credential_free(&credential);
        mbedtls_platform_zeroize(private_key, sizeof(private_key));
        mbedtls_platform_zeroize(credential_metadata, sizeof(credential_metadata));
        mbedtls_platform_zeroize(plain, sizeof(plain));
        if (ret != 0) {
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, envelope, plain_len + 28));
    }
    else {
        VAULT_CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }
err:
#undef VAULT_CBOR_ERROR
    if (*ctap_error != 0) {
        return CborNoError;
    }
    if (error != CborNoError) {
        return error;
    }
    if (response_started) {
        error = cbor_encoder_close_container(&encoder, &mapEncoder);
        if (error != CborNoError) {
            return error;
        }
        *resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    }
    *response_handled = true;
    return CborNoError;
}
