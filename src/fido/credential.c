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

#include "common.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/sha256.h"
#include "credential.h"
#include "bsp/board.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"

int credential_verify(CborByteString *cred_id, const uint8_t *rp_id_hash) {
    if (cred_id->len < 4+12+16)
            return -1;
    uint8_t key[32], *iv = cred_id->data + 4, *cipher = cred_id->data + 4 + 12, *tag = cred_id->data - 16;
    memset(key, 0, sizeof(key));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    return mbedtls_chachapoly_auth_decrypt(&chatx, cred_id->len - (4 + 12 + 16), iv, rp_id_hash, 32, tag, cipher, cipher);
}

int credential_create(CborCharString *rpId, CborByteString *userId, CborCharString *userName, CborCharString *userDisplayName, const bool *hmac_secret, bool use_sign_count, int alg, int curve, uint8_t *cred_id, size_t *cred_id_len) {
    CborEncoder encoder, mapEncoder;
    CborError error = CborNoError;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *)rpId->data, rpId->len, rp_id_hash, 0);
    cbor_encoder_init(&encoder, cred_id+4+12, sizeof(cred_id)-(4+12+16), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, *rpId);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, 32));
    CBOR_APPEND_KEY_UINT_VAL_BYTES(mapEncoder, 0x03, *userId);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x04, *userName);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x05, *userDisplayName);
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, board_millis());
    CBOR_APPEND_KEY_UINT_VAL_PBOOL(mapEncoder, 0x07, hmac_secret);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, use_sign_count));
    if (alg != FIDO2_ALG_ES256 || curve != FIDO2_CURVE_P256) {
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x09, alg);
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x0A, curve);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cred_id);
    *cred_id_len = 4 + 12 + rs + 16;
    uint8_t key[32];
    memset(key, 0, sizeof(key));
    uint8_t iv[12];
    random_gen(NULL, iv, sizeof(12));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, 32, cred_id + 4 + 12, cred_id + 4 + 12, cred_id + 4 + 12 + rs);
    mbedtls_chachapoly_free(&chatx);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, "\xf1\xd0\x02\x00", 4);
    memcpy(cred_id + 4, iv, 12);
    err:
    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    return 0;
}

int credential_load(CborByteString *cred_id, const uint8_t *rp_id_hash, Credential *cred) {
    int ret = 0;
    ret = credential_verify(cred_id, rp_id_hash);
    if (ret != 0)
        return ret;
    CborParser parser;
    CborValue map;
    CborError error;
    memset(cred, 0, sizeof(Credential));
    CBOR_CHECK(cbor_parser_init(cred_id->data + 4 + 12, cred_id->len - (4 + 12 + 16), 0, &parser, &map));
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u == 0x01) {
            CBOR_FIELD_GET_TEXT(cred->rpId, 1);
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_BYTES(cred->userId, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_UINT(cred->creation, 1);
        }
        else if (val_u == 0x07) {
            CBOR_FIELD_GET_BOOL(cred->hmac_secret, 1);
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
        else {
            CBOR_ADVANCE(1);
        }
    }

    cred->present = true;
    err:
    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    return 0;
}

void credential_free(Credential *cred) {
    CBOR_FREE_BYTE_STRING(cred->rpId);
    CBOR_FREE_BYTE_STRING(cred->userId);
}
