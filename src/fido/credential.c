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
#include "pico_time.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/sha256.h"
#include "credential.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "otp.h"
#include "resident_container.h"

int credential_derive_chacha_key(uint8_t *outk, const uint8_t *);

#define RP_RECORD_COUNT_LEN                 1
#define RP_RECORD_HEADER_LEN                (RP_RECORD_COUNT_LEN + RP_ID_HASH_LEN)
#define RP_SECURE_OVERHEAD                  CRED_ENVELOPE_OVERHEAD

static void credential_rp_id_iv(const uint8_t *rp_id_hash, uint8_t iv[CRED_IV_LEN]) {
    uint8_t digest[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, (const uint8_t *) CRED_PROTO_RP_S, CRED_PROTO_LEN);
    mbedtls_sha256_update(&ctx, rp_id_hash, RP_ID_HASH_LEN);
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
    memcpy(iv, digest, CRED_IV_LEN);
    mbedtls_platform_zeroize(digest, sizeof(digest));
}

static bool credential_rp_id_is_secure(const file_t *ef) {
    if (!file_has_data(ef) || file_get_size(ef) < RP_RECORD_HEADER_LEN + RP_SECURE_OVERHEAD) {
        return false;
    }
    return memcmp(file_get_data(ef) + RP_RECORD_HEADER_LEN, CRED_PROTO_RP_S, CRED_PROTO_LEN) == 0;
}

static int credential_rp_id_encrypt(const uint8_t *rp_id_hash, const uint8_t *rp_id, size_t rp_id_len, uint8_t **out, size_t *out_len) {
    uint8_t key[32] = {0};
    uint8_t iv[CRED_IV_LEN] = {0};
    int ret = credential_derive_chacha_key(key, (const uint8_t *) CRED_PROTO_RP_S);
    if (ret != 0) {
        return ret;
    }
    *out_len = CRED_PROTO_LEN + CRED_IV_LEN + rp_id_len + CRED_TAG_LEN;
    *out = (uint8_t *) calloc(1, *out_len);
    if (*out == NULL) {
        mbedtls_platform_zeroize(key, sizeof(key));
        return -1;
    }
    memcpy(*out, CRED_PROTO_RP_S, CRED_PROTO_LEN);
    credential_rp_id_iv(rp_id_hash, iv);
    memcpy(*out + CRED_PROTO_LEN, iv, CRED_IV_LEN);

    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rp_id_len, iv, rp_id_hash, RP_ID_HASH_LEN, rp_id, *out + CRED_PROTO_LEN + CRED_IV_LEN, *out + CRED_PROTO_LEN + CRED_IV_LEN + rp_id_len);
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    if (ret != 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
    }
    return ret;
}

int credential_rp_id_decrypt(const file_t *ef, uint8_t **rp_id, size_t *rp_id_len) {
    if (!file_has_data(ef) || file_get_size(ef) < RP_RECORD_HEADER_LEN) {
        return -1;
    }
    uint8_t *record = file_get_data(ef);
    uint32_t record_len = file_get_size(ef);
    uint8_t *tail = record + RP_RECORD_HEADER_LEN;
    size_t tail_len = record_len - RP_RECORD_HEADER_LEN;
    *rp_id = NULL;
    *rp_id_len = 0;

    if (!credential_rp_id_is_secure(ef)) {
        *rp_id = (uint8_t *) calloc(1, tail_len + 1);
        if (*rp_id == NULL) {
            return -1;
        }
        memcpy(*rp_id, tail, tail_len);
        *rp_id_len = tail_len;
        return 0;
    }

    if (tail_len < RP_SECURE_OVERHEAD) {
        return -1;
    }
    size_t plaintext_len = tail_len - RP_SECURE_OVERHEAD;
    *rp_id = (uint8_t *) calloc(1, plaintext_len + 1);
    if (*rp_id == NULL) {
        return -1;
    }

    uint8_t key[32] = {0};
    int ret = credential_derive_chacha_key(key, (const uint8_t *) CRED_PROTO_RP_S);
    if (ret == 0) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, plaintext_len, tail + CRED_PROTO_LEN, record + RP_RECORD_COUNT_LEN, RP_ID_HASH_LEN, tail + CRED_PROTO_LEN + CRED_IV_LEN + plaintext_len, tail + CRED_PROTO_LEN + CRED_IV_LEN, *rp_id);
        mbedtls_chachapoly_free(&chatx);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) {
        free(*rp_id);
        *rp_id = NULL;
        *rp_id_len = 0;
        return ret;
    }
    *rp_id_len = plaintext_len;
    return 0;
}

int credential_migrate_rp_secure(void) {
    bool changed = false;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search((uint16_t)(EF_RP + i));
        if (!file_has_data(ef) || credential_rp_id_is_secure(ef)) {
            continue;
        }
        uint8_t *record = file_get_data(ef);
        uint32_t record_len = file_get_size(ef);
        if (record_len < RP_RECORD_HEADER_LEN) {
            continue;
        }
        uint8_t *out = NULL;
        size_t out_len = 0;
        int ret = credential_rp_id_encrypt(record + RP_RECORD_COUNT_LEN, record + RP_RECORD_HEADER_LEN, record_len - RP_RECORD_HEADER_LEN, &out, &out_len);
        if (ret != 0) {
            free(out);
            continue;
        }
        uint8_t *data = (uint8_t *) calloc(1, RP_RECORD_HEADER_LEN + out_len);
        if (data == NULL) {
            free(out);
            continue;
        }
        memcpy(data, record, RP_RECORD_HEADER_LEN);
        memcpy(data + RP_RECORD_HEADER_LEN, out, out_len);
        file_put_data(ef, CONST_BYTE_ARRAY(data, RP_RECORD_HEADER_LEN + out_len));
        free(data);
        free(out);
        changed = true;
    }
    if (changed) {
        flash_commit();
    }
    return PICOKEYS_OK;
}

static bool credential_rp_legacy_valid(const file_t *ef) {
    return file_has_data(ef) && file_get_size(ef) >= RP_RECORD_HEADER_LEN && file_get_data(ef)[0] > 0;
}

typedef struct credential_rp_index_entry {
    uint8_t id_hash[RP_ID_HASH_LEN];
    uint16_t source_fid;
} credential_rp_index_entry_t;

static credential_rp_index_entry_t credential_rp_index[MAX_RESIDENT_CREDENTIALS];
static uint16_t credential_rp_index_count;

static int credential_rp_index_add(const uint8_t rp_id_hash[RP_ID_HASH_LEN], uint16_t source_fid) {
    for (uint16_t i = 0; i < credential_rp_index_count; i++) {
        if (mbedtls_ct_memcmp(credential_rp_index[i].id_hash, rp_id_hash, RP_ID_HASH_LEN) == 0) {
            return PICOKEYS_OK;
        }
    }
    if (credential_rp_index_count >= MAX_RESIDENT_CREDENTIALS) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    memcpy(credential_rp_index[credential_rp_index_count].id_hash, rp_id_hash, RP_ID_HASH_LEN);
    credential_rp_index[credential_rp_index_count].source_fid = source_fid;
    credential_rp_index_count++;
    return PICOKEYS_OK;
}

int credential_rp_count(uint16_t *count) {
    if (!count) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(credential_rp_index, 0, sizeof(credential_rp_index));
    credential_rp_index_count = 0;

    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search((uint16_t)(EF_RP + i));
        if (credential_rp_legacy_valid(ef)) {
            int ret = credential_rp_index_add(file_get_data(ef) + RP_RECORD_COUNT_LEN, ef->fid);
            if (ret != PICOKEYS_OK) {
                return ret;
            }
        }
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search((uint16_t)(EF_CRED + i));
        uint8_t rp_id_hash[RP_ID_HASH_LEN];
        if (!resident_container_is_marker(ef) || credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
            continue;
        }
        int ret = credential_rp_index_add(rp_id_hash, ef->fid);
        if (ret != PICOKEYS_OK) {
            return ret;
        }
    }
    *count = credential_rp_index_count;
    return PICOKEYS_OK;
}

void credential_rp_free(CredentialRp *rp) {
    if (!rp) {
        return;
    }
    free(rp->id);
    memset(rp, 0, sizeof(*rp));
}

int credential_rp_load(uint16_t index, CredentialRp *rp) {
    if (!rp) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(rp, 0, sizeof(*rp));
    if (index >= credential_rp_index_count) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    credential_rp_index_entry_t *entry = &credential_rp_index[index];
    file_t *ef = file_search(entry->source_fid);
    if (!file_has_data(ef)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    memcpy(rp->id_hash, entry->id_hash, sizeof(rp->id_hash));

    if ((entry->source_fid & 0xff00u) == EF_RP) {
        int ret = credential_rp_id_decrypt(ef, &rp->id, &rp->id_len);
        if (ret != 0) {
            credential_rp_free(rp);
        }
        return ret;
    }
    if ((entry->source_fid & 0xff00u) == EF_CRED && resident_container_is_marker(ef)) {
        Credential credential = { 0 };
        int ret = credential_load_resident(ef, entry->id_hash, &credential);
        if (ret != 0 || !credential.rpId.present) {
            credential_free(&credential);
            return ret != 0 ? ret : PICOKEYS_WRONG_DATA;
        }
        rp->id = (uint8_t *) calloc(1, credential.rpId.len + 1);
        if (!rp->id) {
            credential_free(&credential);
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
        memcpy(rp->id, credential.rpId.data, credential.rpId.len);
        rp->id_len = credential.rpId.len;
        credential_free(&credential);
        return PICOKEYS_OK;
    }
    return PICOKEYS_WRONG_DATA;
}

int credential_rp_legacy_decrement(const uint8_t rp_id_hash[RP_ID_HASH_LEN]) {
    if (!rp_id_hash) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search((uint16_t)(EF_RP + i));
        if (!credential_rp_legacy_valid(ef) || mbedtls_ct_memcmp(file_get_data(ef) + RP_RECORD_COUNT_LEN, rp_id_hash, RP_ID_HASH_LEN) != 0) {
            continue;
        }
        uint32_t size = file_get_size(ef);
        uint8_t *data = (uint8_t *) calloc(1, size);
        if (!data) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
        memcpy(data, file_get_data(ef), size);
        data[0]--;
        int ret = data[0] == 0 ? file_delete(ef) : file_put_data(ef, CONST_BYTE_ARRAY(data, size));
        free(data);
        return ret;
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

static int credential_silent_tag(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, uint8_t outk[CRED_SILENT_HMAC_LEN]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    if (otp_key_1) {
        mbedtls_sha256_update(&ctx, otp_key_1, CRED_SILENT_HMAC_LEN);
    }
    else {
        mbedtls_sha256_update(&ctx, pico_serial.id, sizeof(pico_serial.id));
    }
    if (memcmp(cred_id, CRED_PROTO_25_S, CRED_PROTO_LEN) == 0) {
        mbedtls_sha256_update(&ctx, certdev_sha256, sizeof(certdev_sha256));
    }
    mbedtls_sha256_update(&ctx, rp_id_hash, RP_ID_HASH_LEN);
    mbedtls_sha256_finish(&ctx, outk);
    mbedtls_sha256_free(&ctx);

    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, CRED_SILENT_HMAC_LEN, cred_id, cred_id_len - CRED_SILENT_TAG_LEN, outk);
}

int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, bool silent) {
    if (cred_id_len < CRED_ENVELOPE_OVERHEAD) {
        return -1;
    }
    uint8_t key[32] = {0}, *iv = cred_id + CRED_PROTO_LEN, *cipher = cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
            *tag = cred_id + cred_id_len - CRED_TAG_LEN;
    cred_proto_t proto = CRED_PROTO_21;
    if (memcmp(cred_id, CRED_PROTO_22_S, CRED_PROTO_LEN) == 0 || memcmp(cred_id, CRED_PROTO_25_S, CRED_PROTO_LEN) == 0) { // New format
        tag = cred_id + cred_id_len - CRED_SILENT_TAG_LEN - CRED_TAG_LEN;
        proto = CRED_PROTO_25;
    }
    int ret = 0;
    if (!silent) {
        int hdr_len = CRED_ENVELOPE_OVERHEAD;
        if (proto == CRED_PROTO_22 || proto == CRED_PROTO_25) {
            hdr_len += CRED_SILENT_TAG_LEN;
        }
        credential_derive_chacha_key(key, cred_id);
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id_len - hdr_len, iv, rp_id_hash, RP_ID_HASH_LEN, tag, cipher, cipher);
        mbedtls_chachapoly_free(&chatx);
    }
    else {
        if (proto <= CRED_PROTO_21) {
            return -1;
        }
        uint8_t outk[CRED_SILENT_HMAC_LEN];
        ret = credential_silent_tag(cred_id, cred_id_len, rp_id_hash, outk);
        ret = memcmp(outk, cred_id + cred_id_len - CRED_SILENT_TAG_LEN, CRED_SILENT_TAG_LEN);
    }
    return ret;
}

int credential_create(CborCharString *rpId, CborByteString *userId, CborCharString *userName, CborCharString *userDisplayName, CredOptions *opts, CredExtensions *extensions, bool use_sign_count, int alg, int curve, uint8_t *cred_id, uint16_t *cred_id_len) {
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    uint8_t rp_id_hash[RP_ID_HASH_LEN];
    mbedtls_sha256((uint8_t *) rpId->data, rpId->len, rp_id_hash, 0);
    uint8_t *cbor_payload = cred_id + CRED_CIPHERTEXT_OFFSET;
    cbor_encoder_init(&encoder, cbor_payload, MAX_CRED_ID_LENGTH - CRED_SILENT_ENVELOPE_OVERHEAD, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, *rpId);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, RP_ID_HASH_LEN));
    CBOR_APPEND_KEY_UINT_VAL_BYTES(mapEncoder, 0x03, *userId);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x04, *userName);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x05, *userDisplayName);
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, board_millis());
    if (extensions->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (extensions->credBlob.present == true &&
            extensions->credBlob.len < MAX_CREDBLOB_LENGTH) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, extensions->credBlob.data, extensions->credBlob.len));
        }
        if (extensions->credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, extensions->credProtect));
        }
        if (extensions->hmac_secret != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, *extensions->hmac_secret));
        }
        if (extensions->largeBlobKey == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        if (extensions->thirdPartyPayment == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, use_sign_count));
    if (alg != FIDO2_ALG_ES256 || curve != FIDO2_CURVE_P256) {
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x09, alg);
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x0A, curve);
    }
    if (opts->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (opts->rk != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, opts->rk == ptrue));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (has_set_rtc()) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, (uint64_t) get_rtc_time()));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cbor_payload);
    *cred_id_len = CRED_SILENT_ENVELOPE_OVERHEAD + (uint16_t) rs;
    uint8_t key[32] = {0};
    credential_derive_chacha_key(key, (const uint8_t *)CRED_PROTO);
    uint8_t iv[CRED_IV_LEN] = {0};
    random_fill_buffer(BYTE_ARRAY(iv, sizeof(iv)));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, RP_ID_HASH_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs);
    mbedtls_chachapoly_free(&chatx);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, CRED_PROTO, CRED_PROTO_LEN);
    memcpy(cred_id + CRED_PROTO_LEN, iv, CRED_IV_LEN);
    credential_silent_tag(cred_id, *cred_id_len, rp_id_hash, cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs + CRED_TAG_LEN);

err:
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    return 0;
}

int credential_load(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, Credential *cred) {
    int ret = 0;
    CborError error = CborNoError;
    uint8_t *copy_cred_id = (uint8_t *) calloc(1, cred_id_len);
    if (!cred) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
    memset(cred, 0, sizeof(Credential));
    memcpy(copy_cred_id, cred_id, cred_id_len);
    ret = credential_verify(copy_cred_id, cred_id_len, rp_id_hash, false);
    if (ret != 0) { // U2F?
        if (cred_id_len != KEY_HANDLE_LEN || verify_key(rp_id_hash, cred_id, NULL) != 0) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    else {
        CborParser parser;
        CborValue map;
        memset(cred, 0, sizeof(Credential));
        cred->curve = FIDO2_CURVE_P256;
        cred->alg = FIDO2_ALG_ES256;
        CBOR_CHECK(cbor_parser_init(copy_cred_id + CRED_CIPHERTEXT_OFFSET, cred_id_len - CRED_ENVELOPE_OVERHEAD, 0, &parser, &map));
        CBOR_PARSE_MAP_START(map, 1)
        {
            uint64_t val_u = 0;
            CBOR_FIELD_GET_UINT(val_u, 1);
            if (val_u == 0x01) {
                CBOR_FIELD_GET_TEXT(cred->rpId, 1);
            }
            else if (val_u == 0x03) {
                CBOR_FIELD_GET_BYTES(cred->userId, 1);
            }
            else if (val_u == 0x04) {
                CBOR_FIELD_GET_TEXT(cred->userName, 1);
            }
            else if (val_u == 0x05) {
                CBOR_FIELD_GET_TEXT(cred->userDisplayName, 1);
            }
            else if (val_u == 0x06) {
                CBOR_FIELD_GET_UINT(cred->board_creation, 1);
            }
            else if (val_u == 0x07) {
                cred->extensions.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", cred->extensions.hmac_secret);
                    CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", cred->extensions.credProtect);
                    CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "credBlob", cred->extensions.credBlob);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "largeBlobKey", cred->extensions.largeBlobKey);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "thirdPartyPayment", cred->extensions.thirdPartyPayment);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x08) {
                CBOR_FIELD_GET_BOOL(cred->use_sign_count, 1);
            }
            else if (val_u == 0x09) {
                CBOR_FIELD_GET_INT(cred->alg, 1);
            }
            else if (val_u == 0x0A) {
                CBOR_FIELD_GET_INT(cred->curve, 1);
            }
            else if (val_u == 0x0B) {
                cred->opts.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", cred->opts.rk);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x0C) {
                CBOR_FIELD_GET_UINT(cred->rtc_creation, 1);
            }
            else {
                CBOR_ADVANCE(1);
            }
        }
    }
    cred->id.present = true;
    cred->id.data = (uint8_t *) calloc(1, cred_id_len);
    memcpy(cred->id.data, cred_id, cred_id_len);
    cred->id.len = cred_id_len;
    cred->present = true;
err:
    free(copy_cred_id);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    return 0;
}

void credential_free(Credential *cred) {
    if (cred) {
        CBOR_FREE_BYTE_STRING(cred->rpId);
        CBOR_FREE_BYTE_STRING(cred->rpIdHash);
        CBOR_FREE_BYTE_STRING(cred->userId);
        CBOR_FREE_BYTE_STRING(cred->userName);
        CBOR_FREE_BYTE_STRING(cred->userDisplayName);
        CBOR_FREE_BYTE_STRING(cred->id);
        CBOR_FREE_BYTE_STRING(cred->residentId);
        if (cred->privateKey.present) {
            mbedtls_platform_zeroize(cred->privateKey.data, cred->privateKey.len);
        }
        CBOR_FREE_BYTE_STRING(cred->privateKey);
        if (cred->extensions.present) {
            CBOR_FREE_BYTE_STRING(cred->extensions.credBlob);
        }
        cred->present = false;
        cred->extensions.present = false;
        cred->opts.present = false;
    }
}

static int credential_parse_metadata(const uint8_t *data, size_t data_len, Credential *cred) {
    if (!data || !cred) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    memset(cred, 0, sizeof(Credential));
    cred->curve = FIDO2_CURVE_P256;
    cred->alg = FIDO2_ALG_ES256;
    CBOR_CHECK(cbor_parser_init(data, data_len, 0, &parser, &map));
    uint16_t seen = 0;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u >= 1 && val_u <= 13) {
            uint16_t field = (uint16_t)(1u << (val_u - 1u));
            if ((seen & field) != 0) {
                error = CborErrorImproperValue;
                goto err;
            }
            seen |= field;
        }
        if (val_u == 0x01) { CBOR_FIELD_GET_TEXT(cred->rpId, 1); }
        else if (val_u == 0x02) { CBOR_FIELD_GET_BYTES(cred->rpIdHash, 1); }
        else if (val_u == 0x03) { CBOR_FIELD_GET_BYTES(cred->userId, 1); }
        else if (val_u == 0x04) { CBOR_FIELD_GET_TEXT(cred->userName, 1); }
        else if (val_u == 0x05) { CBOR_FIELD_GET_TEXT(cred->userDisplayName, 1); }
        else if (val_u == 0x06) { CBOR_FIELD_GET_UINT(cred->board_creation, 1); }
        else if (val_u == 0x07) {
            cred->extensions.present = true;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", cred->extensions.hmac_secret);
                CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", cred->extensions.credProtect);
                CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "credBlob", cred->extensions.credBlob);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "largeBlobKey", cred->extensions.largeBlobKey);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "thirdPartyPayment", cred->extensions.thirdPartyPayment);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x08) { CBOR_FIELD_GET_BOOL(cred->use_sign_count, 1); }
        else if (val_u == 0x09) { CBOR_FIELD_GET_INT(cred->alg, 1); }
        else if (val_u == 0x0A) { CBOR_FIELD_GET_INT(cred->curve, 1); }
        else if (val_u == 0x0B) {
            cred->opts.present = true;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", cred->opts.rk);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x0C) { CBOR_FIELD_GET_UINT(cred->rtc_creation, 1); }
        else if (val_u == 0x0D) { CBOR_ADVANCE(1); }
        else { CBOR_ADVANCE(1); }
    }
    CBOR_PARSE_MAP_END(map, 1);
    if (!cbor_value_at_end(&map)) {
        error = CborErrorImproperValue;
        goto err;
    }
    cred->present = true;
err:
    if (error != CborNoError) {
        credential_free(cred);
        return error == CborErrorImproperValue ? CTAP2_ERR_CBOR_UNEXPECTED_TYPE : error;
    }
    return PICOKEYS_OK;
}

int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, const uint8_t *public_key, size_t public_key_len) {
    int sloti = -1;
    Credential cred = { 0 };
    int ret = 0;
    bool use_container = true;

    if (!cred_id || !rp_id_hash || !public_key || public_key_len == 0) {
        return -1;
    }
    ret = credential_load(cred_id, cred_id_len, rp_id_hash, &cred);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search(EF_CRED + i);
        Credential rcred = { 0 };
        if (!file_has_data(ef)) {
            if (sloti == -1 && resident_container_can_create((uint8_t)i)) {
                sloti = i;
            }
            continue;
        }
        if (!credential_resident_matches_rp(ef, rp_id_hash)) {
            continue;
        }
        ret = credential_load_resident(ef, rp_id_hash, &rcred);
        if (ret != 0) {
            credential_free(&rcred);
            continue;
        }
        if (rcred.userId.len == cred.userId.len && memcmp(rcred.userId.data, cred.userId.data, rcred.userId.len) == 0) {
            sloti = i;
            credential_free(&rcred);
            use_container = resident_container_is_marker(ef);
            break;
        }
        credential_free(&rcred);
    }
    if (sloti == -1) {
        credential_free(&cred);
        return -1;
    }
    uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
    ret = credential_derive_resident(cred_id, cred_id_len, cred_idr);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    uint8_t *data = NULL;
    file_t *ef = NULL;
    if (use_container) {
        uint8_t client_record[CRED_RESIDENT_RECORD_LEN] = { 0 };
        uint8_t silent_tag[CRED_SILENT_HMAC_LEN] = { 0 };
        memcpy(client_record, cred_idr, sizeof(cred_idr));
        client_record[CRED_RESIDENT_SILENT_VERSION_OFFSET] = CRED_RESIDENT_SILENT_VERSION;
        ret = credential_silent_tag(client_record, sizeof(client_record), rp_id_hash, silent_tag);
        if (ret == 0) {
            memcpy(client_record + CRED_RESIDENT_SILENT_TAG_OFFSET, silent_tag, CRED_SILENT_TAG_LEN);
            ret = resident_container_create((uint8_t)sloti, rp_id_hash, client_record, sizeof(client_record), cred_id, cred_id_len, public_key, public_key_len);
        }
        mbedtls_platform_zeroize(silent_tag, sizeof(silent_tag));
        mbedtls_platform_zeroize(client_record, sizeof(client_record));
    }
    else {
        data = (uint8_t *)calloc(1, cred_id_len + RP_ID_HASH_LEN + CRED_RESIDENT_LEN);
        if (!data) {
            credential_free(&cred);
            return -1;
        }
        memcpy(data, rp_id_hash, RP_ID_HASH_LEN);
        memcpy(data + RP_ID_HASH_LEN, cred_idr, CRED_RESIDENT_LEN);
        memcpy(data + RP_ID_HASH_LEN + CRED_RESIDENT_LEN, cred_id, cred_id_len);
        ef = file_new((uint16_t)(EF_CRED + sloti));
        ret = ef ? file_put_data(ef, CONST_BYTE_ARRAY(data, cred_id_len + RP_ID_HASH_LEN + CRED_RESIDENT_LEN)) : PICOKEYS_ERR_NO_MEMORY;
        free(data);
    }
    if (ret != PICOKEYS_OK) {
        credential_free(&cred);
        return ret;
    }

    credential_free(&cred);
    flash_commit();
    return 0;
}

static bool credential_algorithm_matches_curve(int64_t algorithm, int64_t curve) {
    if (curve == FIDO2_CURVE_P256) {
        return algorithm == FIDO2_ALG_ES256 || algorithm == FIDO2_ALG_ESP256;
    }
    if (curve == FIDO2_CURVE_P384) {
        return algorithm == FIDO2_ALG_ES384 || algorithm == FIDO2_ALG_ESP384;
    }
    if (curve == FIDO2_CURVE_P521) {
        return algorithm == FIDO2_ALG_ES512 || algorithm == FIDO2_ALG_ESP512;
    }
    if (curve == FIDO2_CURVE_P256K1) {
        return algorithm == FIDO2_ALG_ES256K;
    }
    if (curve == FIDO2_CURVE_BP256R1) {
        return algorithm == FIDO2_ALG_ESB256;
    }
    if (curve == FIDO2_CURVE_BP384R1) {
        return algorithm == FIDO2_ALG_ESB384;
    }
    if (curve == FIDO2_CURVE_BP512R1) {
        return algorithm == FIDO2_ALG_ESB512;
    }
    if (curve == FIDO2_CURVE_ED25519) {
        return algorithm == FIDO2_ALG_EDDSA || algorithm == FIDO2_ALG_ED25519;
    }
    if (curve == FIDO2_CURVE_ED448) {
        return algorithm == FIDO2_ALG_ED448;
    }
    if (curve == FIDO2_CURVE_X25519) {
        return algorithm == FIDO2_ALG_ECDH_ES_HKDF_256;
    }
    return false;
}

int credential_import(const credential_import_record_t *record) {
    if (!record || !record->credential_id || !record->private_key || !record->rp_id || !record->metadata || !record->requested_id || !record->credential_hash || record->credential_id_len == 0 || record->credential_id_len > MAX_CRED_ID_LENGTH || record->private_key_len == 0 || record->private_key_len > CREDENTIAL_PRIVATE_KEY_MAX || record->rp_id_len == 0 || record->metadata_len == 0 || record->requested_id_len == 0 || record->requested_id_len > MAX_CRED_ID_LENGTH) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    Credential parsed = {0};
    int ret = credential_parse_metadata(record->metadata, record->metadata_len, &parsed);
    mbedtls_ecp_group_id curve = fido_curve_to_mbedtls((int)parsed.curve);
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = {0};
    uint8_t credential_hash[RP_ID_HASH_LEN] = {0};
    if (ret != PICOKEYS_OK || !parsed.rpId.present || !parsed.rpIdHash.present || parsed.rpIdHash.len != RP_ID_HASH_LEN || parsed.rpId.len != record->rp_id_len || mbedtls_ct_memcmp(parsed.rpId.data, record->rp_id, record->rp_id_len) != 0 || !credential_algorithm_matches_curve(parsed.alg, parsed.curve) || curve == MBEDTLS_ECP_DP_NONE) {
        credential_free(&parsed);
        return PICOKEYS_WRONG_DATA;
    }
    if (mbedtls_sha256(record->rp_id, record->rp_id_len, rp_id_hash, 0) != 0 || mbedtls_sha256(record->requested_id, record->requested_id_len, credential_hash, 0) != 0 || mbedtls_ct_memcmp(parsed.rpIdHash.data, rp_id_hash, sizeof(rp_id_hash)) != 0 || mbedtls_ct_memcmp(record->credential_hash, credential_hash, sizeof(credential_hash)) != 0) {
        credential_free(&parsed);
        return PICOKEYS_WRONG_DATA;
    }
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    ret = mbedtls_ecp_read_key(curve, &key, record->private_key, record->private_key_len);
    if (ret == 0) {
        ret = mbedtls_ecp_keypair_calc_public(&key, random_fill_iterator, NULL);
    }
    uint8_t public_key[192] = {0};
    CborEncoder encoder, cose;
    CborError error = CborNoError;
    size_t public_key_len = 0;
    if (ret == 0) {
        cbor_encoder_init(&encoder, public_key, sizeof(public_key), 0);
        error = COSE_key(&key, (int)parsed.alg, &encoder, &cose);
        public_key_len = cbor_encoder_get_buffer_size(&encoder, public_key);
    }
    if (ret == 0 && error != CborNoError) {
        ret = PICOKEYS_EXEC_ERROR;
    }
    uint8_t client_id[CRED_RESIDENT_LEN] = {0};
    if (ret == 0 && error == CborNoError) {
        ret = credential_derive_resident(record->credential_id, record->credential_id_len, client_id);
    }
    int slot = -1;
    if (ret == 0) {
        for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            if (!file_has_data(file_search((uint16_t)(EF_CRED + i))) && resident_container_can_create(i)) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            ret = PICOKEYS_ERR_MEMORY_FATAL;
        }
    }
    if (ret == PICOKEYS_OK) {
        ret = resident_container_create_imported((uint8_t)slot, rp_id_hash, client_id, sizeof(client_id), record->credential_id, record->credential_id_len, public_key, public_key_len, record->private_key, record->private_key_len, record->metadata, record->metadata_len);
    }
    if (ret == PICOKEYS_OK) {
        dev_state_update(DEV_STATE_CRED_STATE);
        flash_commit();
    }
    mbedtls_platform_zeroize(public_key, sizeof(public_key));
    mbedtls_platform_zeroize(client_id, sizeof(client_id));
    mbedtls_platform_zeroize(rp_id_hash, sizeof(rp_id_hash));
    mbedtls_platform_zeroize(credential_hash, sizeof(credential_hash));
    mbedtls_ecp_keypair_free(&key);
    credential_free(&parsed);
    return ret == 0 ? PICOKEYS_OK : ret;
}

int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 64);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "hmac-secret", 11, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_chacha_key(uint8_t *outk, const uint8_t *proto) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) (proto ? proto : (const uint8_t *)CRED_PROTO), CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "Encryption key", 14, outk);
    return 0;
}

int credential_derive_large_blob_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "largeBlobKey", 12, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_resident(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, CRED_RESIDENT_LEN);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t *cred_idr = outk + CRED_RESIDENT_HEADER_LEN;
    mbedtls_md_hmac(md_info, cred_idr, 32, pico_serial.id, sizeof(pico_serial.id), outk);
    memcpy(outk + 4, CRED_PROTO_RESIDENT, CRED_PROTO_RESIDENT_LEN);
    outk[4 + CRED_PROTO_RESIDENT_LEN] = 0x00;
    outk[4 + CRED_PROTO_RESIDENT_LEN + 1] = 0x00;

    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "SLIP-0022", 9, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "resident", 8, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, cred_id, cred_id_len, cred_idr);
    return 0;
}

bool credential_is_resident(const uint8_t *cred_id, size_t cred_id_len) {
    if (cred_id_len < 4 + CRED_PROTO_RESIDENT_LEN) {
        return false;
    }
    return memcmp(cred_id + 4, CRED_PROTO_23_S, CRED_PROTO_RESIDENT_LEN) == 0 ||
           memcmp(cred_id + 4, CRED_PROTO_26_S, CRED_PROTO_RESIDENT_LEN) == 0;
}

bool credential_resident_id_uses_stable_keys(const uint8_t *resident_id, size_t resident_id_len) {
    return resident_id_len == CRED_RESIDENT_LEN &&
           memcmp(resident_id + 4, CRED_PROTO_26_S, CRED_PROTO_RESIDENT_LEN) == 0;
}

static int credential_resident_container_read_alloc(const file_t *ef, uint16_t object_type, uint8_t **data, size_t *data_len) {
    if (!resident_container_is_marker(ef) || !data || !data_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *data = NULL;
    *data_len = 0;
    uint32_t object_size = 0;
    int ret = resident_container_object_size((uint8_t)ef->fid, object_type, &object_size);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    if (object_size > 0) {
        *data = (uint8_t *)calloc(1, object_size);
        if (!*data) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
    }
    byte_buffer_t output = BYTE_BUFFER(*data, object_size);
    ret = resident_container_read((uint8_t)ef->fid, object_type, &output);
    if (ret != PICOKEYS_OK || output.len != object_size) {
        if (*data) {
            mbedtls_platform_zeroize(*data, object_size);
            free(*data);
            *data = NULL;
        }
        return ret == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : ret;
    }
    *data_len = output.len;
    return PICOKEYS_OK;
}

int credential_resident_read_metadata(const file_t *ef, fido_resident_metadata_t *metadata) {
    if (!file_has_data(ef) || !metadata) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!resident_container_is_marker(ef)) {
        *metadata = (fido_resident_metadata_t) {
            .status = FIDO_RESIDENT_STATUS_ACTIVE,
            .properties = FIDO_RESIDENT_PROPERTY_NATIVE,
            .expiration = 0
        };
        return PICOKEYS_OK;
    }
    int ret = resident_container_read_metadata((uint8_t)ef->fid, metadata);
    if (ret == PICOKEYS_OK && metadata->status == FIDO_RESIDENT_STATUS_ACTIVE && metadata->expiration != 0 &&
        has_set_rtc() && (uint64_t)metadata->expiration <= (uint64_t)get_rtc_time()) {
        metadata->status = FIDO_RESIDENT_STATUS_EXPIRED;
    }
    return ret;
}

int credential_resident_update_metadata(const file_t *ef, const fido_resident_metadata_t *metadata) {
    if (!file_has_data(ef) || !metadata) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    return resident_container_is_marker(ef) ? resident_container_update_metadata((uint8_t)ef->fid, metadata) : PICOKEYS_ERR_FILE_NOT_FOUND;
}

static bool credential_resident_usable(const file_t *ef) {
    fido_resident_metadata_t metadata;
    if (credential_resident_read_metadata(ef, &metadata) != PICOKEYS_OK ||
        metadata.status == FIDO_RESIDENT_STATUS_EXPIRED ||
        metadata.status == FIDO_RESIDENT_STATUS_REVOKED) {
        return false;
    }
    return metadata.expiration == 0 || !has_set_rtc() || (uint64_t)get_rtc_time() < metadata.expiration;
}

int credential_resident_rp_id_hash(const file_t *ef, uint8_t rp_id_hash[RP_ID_HASH_LEN]) {
    if (!file_has_data(ef) || !rp_id_hash) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!resident_container_is_marker(ef)) {
        if (file_get_size(ef) < RP_ID_HASH_LEN) {
            return PICOKEYS_WRONG_LENGTH;
        }
        memcpy(rp_id_hash, file_get_data(ef), RP_ID_HASH_LEN);
        return PICOKEYS_OK;
    }
    byte_buffer_t output = BYTE_BUFFER(rp_id_hash, RP_ID_HASH_LEN);
    int ret = resident_container_read((uint8_t)ef->fid, FIDO_RESIDENT_OBJECT_RP_ID_HASH, &output);
    return ret == PICOKEYS_OK && output.len == RP_ID_HASH_LEN ? PICOKEYS_OK : (ret == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : ret);
}

bool credential_resident_matches_rp(const file_t *ef, const uint8_t rp_id_hash[RP_ID_HASH_LEN]) {
    uint8_t stored_hash[RP_ID_HASH_LEN];
    return rp_id_hash && credential_resident_rp_id_hash(ef, stored_hash) == PICOKEYS_OK && mbedtls_ct_memcmp(stored_hash, rp_id_hash, sizeof(stored_hash)) == 0;
}

bool credential_resident_matches_id(const file_t *ef, const uint8_t *resident_id, size_t resident_id_len) {
    if (!file_has_data(ef) || !resident_id || resident_id_len != CRED_RESIDENT_LEN) {
        return false;
    }
    fido_resident_metadata_t imported_metadata;
    if (resident_container_read_metadata((uint8_t)ef->fid, &imported_metadata) == PICOKEYS_OK && imported_metadata.properties == FIDO_RESIDENT_PROPERTY_IMPORTED) {
        uint8_t *imported_resident_id = NULL;
        size_t imported_resident_id_len = 0;
        if (credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CLIENT_ID, &imported_resident_id, &imported_resident_id_len) != PICOKEYS_OK) {
            return false;
        }
        bool matches = imported_resident_id_len == resident_id_len && mbedtls_ct_memcmp(imported_resident_id, resident_id, resident_id_len) == 0;
        free(imported_resident_id);
        return matches;
    }
    uint8_t stored_id[CRED_RESIDENT_LEN];
    if (resident_container_is_marker(ef)) {
        uint8_t *client_record = NULL;
        size_t client_record_len = 0;
        if (credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CLIENT_ID, &client_record, &client_record_len) != PICOKEYS_OK || client_record_len < sizeof(stored_id)) {
            free(client_record);
            return false;
        }
        memcpy(stored_id, client_record, sizeof(stored_id));
        free(client_record);
    }
    else if (file_get_size(ef) >= RP_ID_HASH_LEN + CRED_RESIDENT_LEN && credential_is_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN)) {
        memcpy(stored_id, file_get_data(ef) + RP_ID_HASH_LEN, sizeof(stored_id));
    }
    else if (file_get_size(ef) > RP_ID_HASH_LEN) {
        if (credential_derive_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN, stored_id) != 0) {
            return false;
        }
    }
    else {
        return false;
    }
    return mbedtls_ct_memcmp(stored_id, resident_id, sizeof(stored_id)) == 0;
}

int credential_load_resident(const file_t *ef, const uint8_t *rp_id_hash, Credential *cred) {
    if (!file_has_data(ef) || !rp_id_hash || !cred) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    cred->imported = false;
    if (resident_container_is_marker(ef)) {
        if (!credential_resident_usable(ef)) {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        uint8_t stored_hash[RP_ID_HASH_LEN];
        if (credential_resident_rp_id_hash(ef, stored_hash) != PICOKEYS_OK || mbedtls_ct_memcmp(stored_hash, rp_id_hash, sizeof(stored_hash)) != 0) {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        uint8_t *credential = NULL;
        uint8_t *resident_id = NULL;
        uint8_t *metadata = NULL;
        uint8_t *private_key = NULL;
        size_t credential_len = 0;
        size_t resident_id_len = 0;
        size_t metadata_len = 0;
        size_t private_key_len = 0;
        int ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CREDENTIAL, &credential, &credential_len);
        if (ret == PICOKEYS_OK) {
            ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CLIENT_ID, &resident_id, &resident_id_len);
        }
        if (ret == PICOKEYS_OK && resident_id_len < CRED_RESIDENT_LEN) {
            ret = PICOKEYS_WRONG_LENGTH;
        }
        if (ret == PICOKEYS_OK) {
            fido_resident_metadata_t resident_metadata;
            ret = resident_container_read_metadata((uint8_t)ef->fid, &resident_metadata);
            if (ret == PICOKEYS_OK && resident_metadata.properties == FIDO_RESIDENT_PROPERTY_IMPORTED) {
                cred->imported = true;
                ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_METADATA, &metadata, &metadata_len);
                if (ret == PICOKEYS_OK) ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_PRIVATE_KEY, &private_key, &private_key_len);
                if (ret == PICOKEYS_OK) ret = credential_parse_metadata(metadata, metadata_len, cred);
                if (ret == PICOKEYS_OK) {
                    cred->id.data = (uint8_t *)calloc(1, credential_len);
                    if (!cred->id.data) ret = PICOKEYS_ERR_NO_MEMORY;
                    else {
                        memcpy(cred->id.data, credential, credential_len);
                        cred->id.len = credential_len;
                        cred->id.present = true;
                        cred->privateKey.data = (uint8_t *)calloc(1, private_key_len);
                        if (!cred->privateKey.data) ret = PICOKEYS_ERR_NO_MEMORY;
                        else {
                            memcpy(cred->privateKey.data, private_key, private_key_len);
                            cred->privateKey.len = private_key_len;
                            cred->privateKey.present = true;
                        }
                    }
                }
            }
            else if (ret == PICOKEYS_OK) {
                ret = credential_load(credential, credential_len, rp_id_hash, cred);
            }
        }
        if (ret == 0) {
            cred->residentId.present = true;
            cred->residentId.len = CRED_RESIDENT_LEN;
            cred->residentId.data = resident_id;
            resident_id = NULL;
        }
        if (credential) {
            mbedtls_platform_zeroize(credential, credential_len);
            free(credential);
        }
        free(metadata);
        if (private_key) {
            mbedtls_platform_zeroize(private_key, private_key_len);
        }
        free(private_key);
        free(resident_id);
        return ret;
    }
    if (file_get_size(ef) <= RP_ID_HASH_LEN) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    if (credential_is_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN)) {
        int ret = credential_load(file_get_data(ef) + RP_ID_HASH_LEN + CRED_RESIDENT_LEN, file_get_size(ef) - RP_ID_HASH_LEN - CRED_RESIDENT_LEN, rp_id_hash, cred);
        if (ret == 0) {
            cred->residentId.present = true;
            cred->residentId.len = CRED_RESIDENT_LEN;
            cred->residentId.data = (uint8_t *) calloc(1, CRED_RESIDENT_LEN);
            if (cred->residentId.data == NULL) {
                credential_free(cred);
                return CTAP2_ERR_PROCESSING;
            }
            memcpy(cred->residentId.data, file_get_data(ef) + RP_ID_HASH_LEN, CRED_RESIDENT_LEN);
        }
        return ret;
    }
    return credential_load(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN, rp_id_hash, cred);
}

int credential_resident_public_key(const file_t *ef, uint8_t **public_key, size_t *public_key_len) {
    if (!public_key || !public_key_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!resident_container_is_marker(ef)) {
        *public_key = NULL;
        *public_key_len = 0;
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, public_key_len);
}

int credential_resident_update(const file_t *ef, const uint8_t *credential, size_t credential_len) {
    if (!file_has_data(ef) || (!credential && credential_len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (resident_container_is_marker(ef)) {
        return resident_container_update_credential((uint8_t)ef->fid, credential, credential_len);
    }
    uint8_t rp_id_hash[RP_ID_HASH_LEN];
    if (credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t resident_id[CRED_RESIDENT_LEN];
    if (file_get_size(ef) >= RP_ID_HASH_LEN + CRED_RESIDENT_LEN && credential_is_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN)) {
        memcpy(resident_id, file_get_data(ef) + RP_ID_HASH_LEN, sizeof(resident_id));
    }
    else {
        if (file_get_size(ef) <= RP_ID_HASH_LEN || credential_derive_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN, resident_id) != 0) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    if (credential_len > SIZE_MAX - RP_ID_HASH_LEN - sizeof(resident_id)) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t updated_len = RP_ID_HASH_LEN + sizeof(resident_id) + credential_len;
    uint8_t *updated = (uint8_t *)calloc(1, updated_len);
    if (!updated) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    memcpy(updated, rp_id_hash, sizeof(rp_id_hash));
    memcpy(updated + RP_ID_HASH_LEN, resident_id, sizeof(resident_id));
    memcpy(updated + RP_ID_HASH_LEN + sizeof(resident_id), credential, credential_len);
    int ret = file_put_data((file_t *)ef, CONST_BYTE_ARRAY(updated, updated_len));
    mbedtls_platform_zeroize(updated, updated_len);
    free(updated);
    return ret;
}

int credential_resident_delete(const file_t *ef) {
    if (!file_has_data(ef)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (resident_container_is_marker(ef)) {
        return resident_container_delete((uint8_t)ef->fid);
    }
    return file_delete((file_t *)ef);
}

int credential_resident_verify(const file_t *ef, const uint8_t rp_id_hash[RP_ID_HASH_LEN], bool silent) {
    if (!file_has_data(ef) || !rp_id_hash) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!resident_container_is_marker(ef)) {
        if (file_get_size(ef) <= RP_ID_HASH_LEN) {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        size_t offset = credential_is_resident(file_get_data(ef) + RP_ID_HASH_LEN, file_get_size(ef) - RP_ID_HASH_LEN) ? RP_ID_HASH_LEN + CRED_RESIDENT_LEN : RP_ID_HASH_LEN;
        return credential_verify(file_get_data(ef) + offset, file_get_size(ef) - offset, rp_id_hash, silent);
    }
    if (!credential_resident_usable(ef)) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    if (silent) {
        uint8_t *client_record = NULL;
        size_t client_record_len = 0;
        int ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CLIENT_ID, &client_record, &client_record_len);
        if (ret != PICOKEYS_OK || client_record_len != CRED_RESIDENT_RECORD_LEN || client_record[CRED_RESIDENT_SILENT_VERSION_OFFSET] != CRED_RESIDENT_SILENT_VERSION) {
            free(client_record);
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        uint8_t tag[CRED_SILENT_HMAC_LEN] = { 0 };
        ret = credential_silent_tag(client_record, client_record_len, rp_id_hash, tag);
        if (ret == 0 && mbedtls_ct_memcmp(tag, client_record + CRED_RESIDENT_SILENT_TAG_OFFSET, CRED_SILENT_TAG_LEN) != 0) {
            ret = CTAP2_ERR_NO_CREDENTIALS;
        }
        mbedtls_platform_zeroize(tag, sizeof(tag));
        mbedtls_platform_zeroize(client_record, client_record_len);
        free(client_record);
        return ret;
    }
    uint8_t *credential = NULL;
    size_t credential_len = 0;
    int ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CREDENTIAL, &credential, &credential_len);
    if (ret == PICOKEYS_OK) {
        ret = credential_verify(credential, credential_len, rp_id_hash, silent);
    }
    if (credential) {
        mbedtls_platform_zeroize(credential, credential_len);
        free(credential);
    }
    return ret;
}
