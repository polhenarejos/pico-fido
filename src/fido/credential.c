/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "mbedtls/chachapoly.h"
#include "mbedtls/sha256.h"
#include "credential.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "pico_keys.h"

int credential_derive_chacha_key(uint8_t *outk);

int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash) {
    if (cred_id_len < 4 + 12 + 16) {
        return -1;
    }
    uint8_t key[32], *iv = cred_id + 4, *cipher = cred_id + 4 + 12,
            *tag = cred_id + cred_id_len - 16;
    memset(key, 0, sizeof(key));
    credential_derive_chacha_key(key);
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id_len - (4 + 12 + 16), iv, rp_id_hash, 32, tag, cipher, cipher);
    mbedtls_chachapoly_free(&chatx);
    return ret;
}

int credential_create(CborCharString *rpId,
                      CborByteString *userId,
                      CborCharString *userName,
                      CborCharString *userDisplayName,
                      CredOptions *opts,
                      CredExtensions *extensions,
                      bool use_sign_count,
                      int alg,
                      int curve,
                      uint8_t *cred_id,
                      size_t *cred_id_len) {
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *) rpId->data, rpId->len, rp_id_hash, 0);
    cbor_encoder_init(&encoder, cred_id + 4 + 12, MAX_CRED_ID_LENGTH - (4 + 12 + 16), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, *rpId);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, 32));
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
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cred_id);
    *cred_id_len = 4 + 12 + rs + 16;
    uint8_t key[32];
    memset(key, 0, sizeof(key));
    credential_derive_chacha_key(key);
    uint8_t iv[12];
    random_gen(NULL, iv, sizeof(iv));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, 32,
                                                 cred_id + 4 + 12,
                                                 cred_id + 4 + 12,
                                                 cred_id + 4 + 12 + rs);
    mbedtls_chachapoly_free(&chatx);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, CRED_PROTO, 4);
    memcpy(cred_id + 4, iv, 12);

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
    memcpy(copy_cred_id, cred_id, cred_id_len);
    ret = credential_verify(copy_cred_id, cred_id_len, rp_id_hash);
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
        CBOR_CHECK(cbor_parser_init(copy_cred_id + 4 + 12, cred_id_len - (4 + 12 + 16), 0, &parser,
                                    &map));
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
                CBOR_FIELD_GET_UINT(cred->creation, 1);
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
    CBOR_FREE_BYTE_STRING(cred->rpId);
    CBOR_FREE_BYTE_STRING(cred->userId);
    CBOR_FREE_BYTE_STRING(cred->userName);
    CBOR_FREE_BYTE_STRING(cred->userDisplayName);
    CBOR_FREE_BYTE_STRING(cred->id);
    if (cred->extensions.present) {
        CBOR_FREE_BYTE_STRING(cred->extensions.credBlob);
    }
    cred->present = false;
    cred->extensions.present = false;
    cred->opts.present = false;
}

int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash) {
    int sloti = -1;
    Credential cred = { 0 };
    int ret = 0;
    bool new_record = true;
    ret = credential_load(cred_id, cred_id_len, rp_id_hash, &cred);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = search_dynamic_file(EF_CRED + i);
        Credential rcred = { 0 };
        if (!file_has_data(ef)) {
            if (sloti == -1) {
                sloti = i;
            }
            continue;
        }
        if (memcmp(file_get_data(ef), rp_id_hash, 32) != 0) {
            continue;
        }
        ret = credential_load(file_get_data(ef) + 32, file_get_size(ef) - 32, rp_id_hash, &rcred);
        if (ret != 0) {
            credential_free(&rcred);
            continue;
        }
        if (memcmp(rcred.userId.data, cred.userId.data, MIN(rcred.userId.len, cred.userId.len)) == 0) {
            sloti = i;
            credential_free(&rcred);
            new_record = false;
            break;
        }
        credential_free(&rcred);
    }
    if (sloti == -1) {
        return -1;
    }
    uint8_t *data = (uint8_t *) calloc(1, cred_id_len + 32);
    memcpy(data, rp_id_hash, 32);
    memcpy(data + 32, cred_id, cred_id_len);
    file_t *ef = file_new((uint16_t)(EF_CRED + sloti));
    file_put_data(ef, data, (uint16_t)cred_id_len + 32);
    free(data);

    if (new_record == true) { //increase rps
        sloti = -1;
        for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            ef = search_dynamic_file(EF_RP + i);
            if (!file_has_data(ef)) {
                if (sloti == -1) {
                    sloti = i;
                }
                continue;
            }
            if (memcmp(file_get_data(ef) + 1, rp_id_hash, 32) == 0) {
                sloti = i;
                break;
            }
        }
        if (sloti == -1) {
            return -1;
        }
        ef = search_dynamic_file((uint16_t)(EF_RP + sloti));
        if (file_has_data(ef)) {
            data = (uint8_t *) calloc(1, file_get_size(ef));
            memcpy(data, file_get_data(ef), file_get_size(ef));
            data[0] += 1;
            file_put_data(ef, data, file_get_size(ef));
            free(data);
        }
        else {
            ef = file_new((uint16_t)(EF_RP + sloti));
            data = (uint8_t *) calloc(1, 1 + 32 + cred.rpId.len);
            data[0] = 1;
            memcpy(data + 1, rp_id_hash, 32);
            memcpy(data + 1 + 32, cred.rpId.data, cred.rpId.len);
            file_put_data(ef, data, (uint16_t)(1 + 32 + cred.rpId.len));
            free(data);
        }
    }
    credential_free(&cred);
    low_flash_available();
    return 0;
}

int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 64);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) CRED_PROTO, 4, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "hmac-secret", 11, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_chacha_key(uint8_t *outk) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) CRED_PROTO, 4, outk);
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
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) CRED_PROTO, 4, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "largeBlobKey", 12, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}
