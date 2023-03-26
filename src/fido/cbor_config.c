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
#include "hid/ctap_hid.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"
#include "hsm.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/sha256.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

int cbor_config(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0, vendorCommandId = 0, newMinPinLength = 0;
    CborByteString pinUvAuthParam = { 0 }, vendorAutCt = { 0 };
    CborCharString minPinLengthRPIDs[32] = { 0 };
    size_t resp_size = 0, raw_subpara_len = 0, minPinLengthRPIDs_len = 0;
    CborEncoder encoder, mapEncoder;
    uint8_t *raw_subpara = NULL;
    const bool *forceChangePin = NULL;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *) cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                if (subcommand == 0xff) {
                    CBOR_FIELD_GET_UINT(subpara, 2);
                    if (subpara == 0x01) {
                        CBOR_FIELD_GET_UINT(vendorCommandId, 2);
                    }
                    else if (subpara == 0x02) {
                        CBOR_FIELD_GET_BYTES(vendorAutCt, 2);
                    }
                }
                else if (subcommand == 0x03) {
                    CBOR_FIELD_GET_UINT(subpara, 2);
                    if (subpara == 0x01) {
                        CBOR_FIELD_GET_UINT(newMinPinLength, 2);
                    }
                    else if (subpara == 0x02) {
                        CBOR_PARSE_ARRAY_START(_f2, 3)
                        {
                            CBOR_FIELD_GET_TEXT(minPinLengthRPIDs[minPinLengthRPIDs_len], 3);
                            minPinLengthRPIDs_len++;
                            if (minPinLengthRPIDs_len >= 32) {
                                CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
                            }
                        }
                        CBOR_PARSE_ARRAY_END(_f2, 3);
                    }
                    else if (subpara == 0x03) {
                        CBOR_FIELD_GET_BOOL(forceChangePin, 2);
                    }
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);

    if (pinUvAuthParam.present == false) {
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (pinUvAuthProtocol  == 0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }

    uint8_t *verify_payload = (uint8_t *) calloc(1, 32 + 1 + 1 + raw_subpara_len);
    memset(verify_payload, 0xff, 32);
    verify_payload[32] = 0x0d;
    verify_payload[33] = subcommand;
    memcpy(verify_payload + 34, raw_subpara, raw_subpara_len);
    error = verify(pinUvAuthProtocol,
                   paut.data,
                   verify_payload,
                   32 + 1 + 1 + raw_subpara_len,
                   pinUvAuthParam.data);
    free(verify_payload);
    if (error != CborNoError) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }

    if (!(paut.permissions & CTAP_PERMISSION_ACFG)) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }

    if (subcommand == 0xff) {
        if (vendorCommandId == CTAP_CONFIG_AUT_DISABLE) {
            if (!file_has_data(ef_keydev_enc)) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            if (has_keydev_dec == false) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
            flash_write_data_to_file(ef_keydev, keydev_dec, sizeof(keydev_dec));
            mbedtls_platform_zeroize(keydev_dec, sizeof(keydev_dec));
            flash_write_data_to_file(ef_keydev_enc, NULL, 0); // Set ef to 0 bytes
            low_flash_available();
        }
        else if (vendorCommandId == CTAP_CONFIG_AUT_ENABLE) {
            if (!file_has_data(ef_keydev)) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            if (mse.init == false) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }

            mbedtls_chachapoly_context chatx;
            int ret = mse_decrypt_ct(vendorAutCt.data, vendorAutCt.len);
            if (ret != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            uint8_t key_dev_enc[12 + 32 + 16];
            random_gen(NULL, key_dev_enc, 12);
            mbedtls_chachapoly_init(&chatx);
            mbedtls_chachapoly_setkey(&chatx, vendorAutCt.data);
            ret = mbedtls_chachapoly_encrypt_and_tag(&chatx,
                                                     file_get_size(ef_keydev),
                                                     key_dev_enc,
                                                     NULL,
                                                     0,
                                                     file_get_data(ef_keydev),
                                                     key_dev_enc + 12,
                                                     key_dev_enc + 12 + file_get_size(ef_keydev));
            mbedtls_chachapoly_free(&chatx);
            if (ret != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            flash_write_data_to_file(ef_keydev_enc, key_dev_enc, sizeof(key_dev_enc));
            mbedtls_platform_zeroize(key_dev_enc, sizeof(key_dev_enc));
            flash_write_data_to_file(ef_keydev, key_dev_enc, file_get_size(ef_keydev)); // Overwrite ef with 0
            flash_write_data_to_file(ef_keydev, NULL, 0); // Set ef to 0 bytes
            low_flash_available();
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
        goto err;
    }
    else if (subcommand == 0x03) {
        uint8_t currentMinPinLen = 4;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            currentMinPinLen = *file_get_data(ef_minpin);
        }
        if (newMinPinLength == 0) {
            newMinPinLength = currentMinPinLen;
        }
        else if (newMinPinLength > 0 && newMinPinLength < currentMinPinLen) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if (forceChangePin == ptrue && !file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (file_has_data(ef_pin) && file_get_data(ef_pin)[1] < newMinPinLength) {
            forceChangePin = ptrue;
        }
        uint8_t *data = (uint8_t *) calloc(1, 2 + minPinLengthRPIDs_len * 32);
        data[0] = newMinPinLength;
        data[1] = forceChangePin == ptrue ? 1 : 0;
        for (int m = 0; m < minPinLengthRPIDs_len; m++) {
            mbedtls_sha256((uint8_t *) minPinLengthRPIDs[m].data,
                           minPinLengthRPIDs[m].len,
                           data + 2 + m * 32,
                           0);
        }
        flash_write_data_to_file(ef_minpin, data, 2 + minPinLengthRPIDs_len * 32);
        low_flash_available();
        goto err; //No return
    }
    else if (subcommand == 0x01) {
        set_opts(get_opts() | FIDO2_OPT_EA);
        goto err;
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorAutCt);
    for (int i = 0; i < minPinLengthRPIDs_len; i++) {
        CBOR_FREE_BYTE_STRING(minPinLengthRPIDs[i]);
    }

    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}
