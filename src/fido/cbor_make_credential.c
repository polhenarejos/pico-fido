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

#include "ctap2_cbor.h"
#include "cbor_make_credential.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"

bool credential_verify(CborByteString *cred_id, const uint8_t *rp_id_hash) {
    if (cred_id->len < 4+12+16)
        return false;
    size_t cipher_len = cred_id->len - (4 + 12 + 16);
    uint8_t key[32], *iv = cred_id->data + 4, *cipher = cred_id->data + 4 + 12, *tag = cred_id->data - 16, *data = (uint8_t *)calloc(1, cipher_len);
    memset(key, 0, sizeof(key));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id->len - (4 + 12 + 16), iv, rp_id_hash, 32, tag, cipher, data);
    free(data);
    if (ret == 0)
        return true;
    return false;
}

int verify(CborByteString *clientDataHash, CborByteString *pinUvAuthParam) {
    return CborNoError;
}

int cbor_make_credential(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString clientDataHash = {0}, pinUvAuthParam = {0};
    PublicKeyCredentialRpEntity rp = {0};
    PublicKeyCredentialUserEntity user = {0};
    PublicKeyCredentialParameters pubKeyCredParams[16] = {0};
    size_t pubKeyCredParams_len = 0;
    PublicKeyCredentialDescriptor excludeList[16] = {0};
    size_t excludeList_len = 0;
    CredOptions options = {0};
    uint64_t pinUvAuthProtocol = 0, enterpriseAttestation = 0;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u == 0x01) { // clientDataHash
            CBOR_FIELD_GET_BYTES(clientDataHash, 1);
        }
        else if (val_u == 0x02) { // rp
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "id", rp.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", rp.parent.name);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x03) { // user
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "id", user.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", user.parent.name);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "displayName", user.displayName);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_PARSE_ARRAY_START(_f1, 2) {
                PublicKeyCredentialParameters *pk = &pubKeyCredParams[pubKeyCredParams_len];
                CBOR_PARSE_MAP_START(_f2, 3) {
                    CBOR_FIELD_GET_KEY_TEXT(3);
                    CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", pk->type);
                    CBOR_FIELD_KEY_TEXT_VAL_INT(3, "alg", pk->alg);
                }
                CBOR_PARSE_MAP_END(_f2, 3);
                pubKeyCredParams_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x05) { // excludeList
            CBOR_PARSE_ARRAY_START(_f1, 2) {
                    PublicKeyCredentialDescriptor *pc = &excludeList[excludeList_len];
                CBOR_PARSE_MAP_START(_f1, 3) {
                    CBOR_FIELD_GET_KEY_TEXT(3);
                    CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", pc->id);
                    CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", pc->type);
                    if (strcmp(_fd3, "transports") == 0) {
                        CBOR_PARSE_ARRAY_START(_f2, 4) {
                            CBOR_FIELD_GET_TEXT(pc->transports[pc->transports_len], 4);
                            pc->transports_len++;
                        }
                        CBOR_PARSE_ARRAY_END(_f2, 4);
                    }
                }
                CBOR_PARSE_MAP_END(_f1, 3);
                excludeList_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x06) { // extensions
            CBOR_ADVANCE(1);
        }
        else if (val_u == 0x07) { // options
            options.present = true;
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", options.rk);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "up", options.up);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "uv", options.uv);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x08) { // pinUvAuthParam
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x09) { // pinUvAuthProtocol
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x0A) { // enterpriseAttestation
            CBOR_FIELD_GET_UINT(enterpriseAttestation, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *)rp.id.data, rp.id.len, rp_id_hash, 0);

    for (int i = 0; i < pubKeyCredParams_len; i++) {
        if (strcmp(pubKeyCredParams[i].type.data, "public-key") != 0)
            continue;
        if (pubKeyCredParams[i].alg != FIDO2_ALG_ES256 && pubKeyCredParams[i].alg != FIDO2_ALG_ES384 && pubKeyCredParams[i].alg != FIDO2_ALG_ES512)
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    }

    if (pinUvAuthParam.len == 0 || pinUvAuthParam.data == NULL) {
        if (wait_button_pressed() == true)
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        if (!file_has_data(ef_pin))
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        else
            CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
    }
    else if (pinUvAuthParam.present == true) {
        if (pinUvAuthProtocol == 0)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    bool *rup = pfalse;
    if (options.present) {
        if (options.uv == ptrue) { //5.3
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        if (options.up == pfalse) { //5.6
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        else if (options.up == NULL) //5.7
            rup = ptrue;
    }
    if (pinUvAuthParam.present == false && options.uv == pfalse && file_has_data(ef_pin)) { //8.1
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (enterpriseAttestation > 0) {
        if (enterpriseAttestation != 1 && enterpriseAttestation != 2) { //9.2.1
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //Unfinished. See 6.1.2.9
    }
    if (pinUvAuthParam.present == true) { //11.1
        int ret = verify(&clientDataHash, &pinUvAuthParam);
        if (ret != CborNoError)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        //Check pinUvAuthToken permissions. See 6.1.2.11
    }

    for (int e = 0; e < excludeList_len; e++) { //12.1
        if (strcmp(excludeList[e].type.data, "public-key") != 0)
            continue;
        if (credential_verify(&excludeList[e].id, rp_id_hash) == true)
            CBOR_ERROR(CTAP2_ERR_CREDENTIAL_EXCLUDED);
    }

    if (pinUvAuthParam.present && options.up == ptrue) { //14.1
        if (wait_button_pressed() == true)
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        rup = ptrue;
    }
    err:
        CBOR_FREE_BYTE_STRING(clientDataHash);
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(rp.id);
    CBOR_FREE_BYTE_STRING(rp.parent.name);
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    for (int n = 0; n < pubKeyCredParams_len; n++) {
        CBOR_FREE_BYTE_STRING(pubKeyCredParams[n].type);
    }

    for (int m = 0; m < excludeList_len; m++) {
        CBOR_FREE_BYTE_STRING(excludeList[m].type);
        CBOR_FREE_BYTE_STRING(excludeList[m].id);
        for (int n = 0; n < excludeList[m].transports_len; n++) {
            CBOR_FREE_BYTE_STRING(excludeList[m].transports[n]);
        }
    }
    if (error != CborNoError)
        return -CTAP2_ERR_INVALID_CBOR;
    driver_exec_finished(1);
    return 0;
}
