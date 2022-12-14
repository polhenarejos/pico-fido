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
#include "version.h"
#include "hsm.h"
#include "mbedtls/sha256.h"

static uint64_t expectedLength = 0, expectedNextOffset = 0;
uint8_t temp_lba[MAX_LARGE_BLOB_SIZE];

int cbor_large_blobs(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborEncoder encoder, mapEncoder;
    CborError error = CborNoError;
    uint64_t get = 0, offset = UINT64_MAX, length = 0, pinUvAuthProtocol = 0;
    CborByteString set = {0}, pinUvAuthParam = {0};

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
            CBOR_FIELD_GET_UINT(get, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_BYTES(set, 1);
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(offset, 1);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_UINT(length, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (offset == 0)
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    if (get == 0 && set.present == false)
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    if (get != 0 && set.present == true)
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    if (get > 0) {
        if (length != 0)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (length > MAX_FRAGMENT_LENGTH)
            CBOR_ERROR(CTAP1_ERR_INVALID_LEN);
        if (offset > file_get_size(ef_largeblob))
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_largeblob)+offset, MIN(get, file_get_size(ef_largeblob)-offset)));
    }
    else {
        if (set.len > MAX_FRAGMENT_LENGTH)
            CBOR_ERROR(CTAP1_ERR_INVALID_LEN);
        if (offset == 0) {
            if (length == 0)
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            if (length > MAX_LARGE_BLOB_SIZE) {
                CBOR_ERROR(CTAP2_ERR_LARGE_BLOB_STORAGE_FULL);
            }
            if (length < 17) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            expectedLength = length;
            expectedNextOffset = 0;
        }
        else {
            if (length != 0)
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (offset != expectedNextOffset)
            CBOR_ERROR(CTAP1_ERR_INVALID_SEQ);
        if (pinUvAuthParam.present == false)
            CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
        if (pinUvAuthProtocol == 0)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        uint8_t verify_data[70] = {0};
        memset(verify_data, 0xff, 32);
        verify_data[32] = 0x0C;
        verify_data[34] = offset & 0xff;
        verify_data[35] = offset >> 8;
        verify_data[36] = offset >> 16;
        verify_data[37] = offset >> 24;
        mbedtls_sha256(set.data, set.len, verify_data+38, 0);
        if (verify(pinUvAuthProtocol, paut.data, verify_data, sizeof(verify_data), pinUvAuthParam.data) != 0)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        if (!(paut.permissions & CTAP_PERMISSION_LBW))
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        if (offset+set.len > expectedLength)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (offset == 0)
            memset(temp_lba, 0, sizeof(temp_lba));
        memcpy(temp_lba+expectedNextOffset, set.data, set.len);
        expectedNextOffset += set.len;
        if (expectedNextOffset == expectedLength) {
            uint8_t sha[32];
            mbedtls_sha256(temp_lba, expectedLength, sha, 0);
            if (expectedLength > 17 && memcmp(sha, temp_lba+expectedLength-16, 16) != 0)
                CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
            flash_write_data_to_file(ef_largeblob, temp_lba, expectedLength);
            low_flash_available();
        }
        goto err;
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));

    err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(set);
    if (error != CborNoError)
        return -CTAP2_ERR_INVALID_CBOR;
    res_APDU_size = cbor_encoder_get_buffer_size(&encoder, res_APDU + 1);
    return 0;
}
