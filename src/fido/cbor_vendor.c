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
#include "files.h"
#include "apdu.h"
#include "hsm.h"

extern bool has_keydev_dec;

int cbor_vendor_generic(uint8_t cmd, const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = {0}, vendorParam = {0};
    size_t resp_size = 0;
    uint64_t vendorCmd = 0, pinUvAuthProtocol = 0;
    CborEncoder encoder, mapEncoder;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (val_u < val_c)
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(vendorCmd, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(vendorParam, 2);
                }
                else
                    CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
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

    if (cmd == CTAP_VENDOR_BACKUP) {
        if (vendorCmd == 0x01) {
            if (has_keydev_dec == false)
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);

            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_keydev_enc), file_get_size(ef_keydev_enc)));
        }
        else if (vendorCmd == 0x02) {
            if (vendorParam.present == false)
                    CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            uint8_t zeros[32];
            memset(zeros, 0, sizeof(zeros));
            flash_write_data_to_file(ef_keydev_enc, vendorParam.data, vendorParam.len);
            flash_write_data_to_file(ef_keydev, zeros, file_get_size(ef_keydev)); // Overwrite ef with 0
            flash_write_data_to_file(ef_keydev, NULL, 0); // Set ef to 0 bytes
            low_flash_available();
            goto err;
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

    err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorParam);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}

int cbor_vendor(const uint8_t *data, size_t len) {
    if (len == 0)
        return CTAP1_ERR_INVALID_LEN;
    if (data[0] == CTAP_VENDOR_BACKUP)
        return cbor_vendor_generic(data[0], data + 1, len - 1);
    return CTAP2_ERR_INVALID_CBOR;
}
