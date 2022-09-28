
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
#include "fido.h"
#include "ctap.h"
#include "bsp/board.h"
#include "cbor_make_credential.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"

uint8_t rp_counter = 1;
uint8_t rp_total = 0;
uint8_t cred_counter = 1;
uint8_t cred_total = 0;

int cbor_cred_mgmt(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0;
    CborByteString pinUvAuthParam = {0}, rpIdHash = {0};
    PublicKeyCredentialDescriptor credentialId = {0};
    PublicKeyCredentialUserEntity user = {0};
    size_t resp_size = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 4 && val_c != val_u)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (val_u < val_c)
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *)cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(rpIdHash, 2);
                }
                else if (subpara == 0x02) {

                    CBOR_PARSE_MAP_START(_f2, 3) {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", credentialId.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", credentialId.type);
                        if (strcmp(_fd3, "transports") == 0) {
                            CBOR_PARSE_ARRAY_START(_f3, 4) {
                                CBOR_FIELD_GET_TEXT(credentialId.transports[credentialId.transports_len], 4);
                                credentialId.transports_len++;
                            }
                            CBOR_PARSE_ARRAY_END(_f3, 4);
                        }
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                }
                else if (subpara == 0x03) {
                    CBOR_PARSE_MAP_START(_f1, 3) {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", user.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "name", user.parent.name);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "displayName", user.displayName);
                    }
                    CBOR_PARSE_MAP_END(_f1, 3);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (subcommand != 0x03) {
        if (pinUvAuthParam.present == false)
            CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    if(subcommand == 0x01) {
        if (verify(pinUvAuthProtocol, paut.data, (const uint8_t *)"\x01", 1, pinUvAuthParam.data) != CborNoError)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        uint8_t existing = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            if (file_has_data(search_dynamic_file(EF_CRED + i)))
                existing++;
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, existing));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_RESIDENT_CREDENTIALS-existing));
    }
    else if (subcommand == 0x02 || subcommand == 0x03) {
        file_t *rp_ef = NULL;
        if (subcommand == 0x02) {
            if (verify(pinUvAuthProtocol, paut.data, (const uint8_t *)"\x02", 1, pinUvAuthParam.data) != CborNoError)
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        else {
            if (rp_counter >= rp_total)
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        uint8_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = search_dynamic_file(EF_RP + i);
            if (file_has_data(tef)) {
                if (++skip == rp_counter) {
                    if (rp_ef == NULL)
                        rp_ef = tef;
                    if (subcommand == 0x03)
                        break;
                }
                rp_total++;
            }
        }
        if (rp_ef == NULL) // should not happen
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        rp_counter++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, subcommand == 0x02 ? 3 : 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, file_get_data(rp_ef)+33, file_get_size(rp_ef)-33));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(rp_ef)+1, 32));
        if (subcommand == 0x02) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, rp_total));
        }
    }
    else if (subcommand == 0x04 || subcommand == 0x05) {
        if (rpIdHash.present == false)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (subcommand == 0x04) {
            *(raw_subpara-1) = 0x04;
            if (verify(pinUvAuthProtocol, paut.data, raw_subpara-1, raw_subpara_len+1, pinUvAuthParam.data) != CborNoError)
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        else {
            if (cred_counter >= cred_total)
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        file_t *cred_ef = NULL;
        uint8_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = search_dynamic_file(EF_CRED + i);
            if (file_has_data(tef) && memcmp(file_get_data(tef), rpIdHash.data, 32) == 0) {
                if (++skip == cred_counter) {
                    if (cred_ef == NULL)
                        cred_ef = tef;
                    if (subcommand == 0x05)
                        break;
                }
                cred_total++;
            }
        }
        if (!file_has_data(cred_ef))
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);

        Credential cred = {0};
        if (credential_load(file_get_data(cred_ef)+32, file_get_size(cred_ef)-32, rpIdHash.data, &cred) != 0)
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);

        mbedtls_ecdsa_context key;
        mbedtls_ecdsa_init(&key);
        if (fido_load_key(cred.curve, cred.id.data, &key) != 0) {
            credential_free(&cred);
            mbedtls_ecdsa_free(&key);
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }

        cred_counter++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, subcommand == 0x04 ? 5 : 4));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        uint8_t l = 0;
        if (cred.userId.present == true)
            l++;
        if (cred.userName.present == true)
            l++;
        if (cred.userDisplayName.present == true)
            l++;
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, l));
        if (cred.userId.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred.userId.data, cred.userId.len));
        }
        if (cred.userName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "name"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userName.data, cred.userName.len));
        }
        if (cred.userDisplayName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "displayName"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userDisplayName.data, cred.userDisplayName.len));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 2));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred.id.data, cred.id.len));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "type"));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "public-key"));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  5));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 3));
        CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, cred.alg));
        CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder2, cred.curve));
        CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 2));
        uint8_t pkey[66];
        mbedtls_mpi_write_binary(&key.Q.X, pkey, mbedtls_mpi_size(&key.Q.X));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, pkey, mbedtls_mpi_size(&key.Q.X)));
        CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 3));
        mbedtls_mpi_write_binary(&key.Q.Y, pkey, mbedtls_mpi_size(&key.Q.Y));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, pkey, mbedtls_mpi_size(&key.Q.Y)));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        if (subcommand == 0x04) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred_total));
        }
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred.extensions.credProtect));
        credential_free(&cred);
        mbedtls_ecdsa_free(&key);
    }
    else if (subcommand == 0x06) {
        *(raw_subpara-1) = 0x06;
        if (verify(pinUvAuthProtocol, paut.data, raw_subpara-1, raw_subpara_len+1, pinUvAuthParam.data) != CborNoError)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }
    else if (subcommand == 0x07) {

    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);

    CBOR_FREE_BYTE_STRING(rpIdHash);
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    CBOR_FREE_BYTE_STRING(credentialId.type);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}
