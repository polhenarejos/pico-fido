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
#include "ctap2_cbor.h"
#include "fido.h"
#include "ctap.h"
#include "bsp/board.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"
#include "hsm.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"


static mbedtls_ecdh_context hkey;
static bool hkey_init = false;
extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

int cbor_config(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0, vendorCommandId = 0;
    int64_t kty = 0, alg = 0, crv = 0;
    CborByteString pinUvAuthParam = {0}, vendorAutCt = {0}, kax = {0}, kay = {0};
    size_t resp_size = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;

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
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            CBOR_PARSE_MAP_START(_f1, 2) {
                if (subcommand == 0xff) {
                    CBOR_FIELD_GET_UINT(subpara, 2);
                    if (subpara == 0x01) {
                        CBOR_FIELD_GET_UINT(vendorCommandId, 2);
                    }
                    else if (subpara == 0x02) {
                        int64_t key = 0;
                        CBOR_PARSE_MAP_START(_f2, 3) {
                            CBOR_FIELD_GET_INT(key, 3);
                            if (key == 1) {
                                CBOR_FIELD_GET_INT(kty, 3);
                            }
                            else if (key == 3) {
                                CBOR_FIELD_GET_INT(alg, 3);
                            }
                            else if (key == -1) {
                                CBOR_FIELD_GET_INT(crv, 3);
                            }
                            else if (key == -2) {
                                CBOR_FIELD_GET_BYTES(kax, 3);
                            }
                            else if (key == -3) {
                                CBOR_FIELD_GET_BYTES(kay, 3);
                            }
                            else
                                CBOR_ADVANCE(3);
                        }
                        CBOR_PARSE_MAP_END(_f2, 3);
                    }
                    else if (subpara == 0x03) {
                        CBOR_FIELD_GET_BYTES(vendorAutCt, 2);
                    }
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);

    if (subcommand == 0xff) {
        if (vendorCommandId == CTAP_CONFIG_KEY_AGREEMENT) {
            if (hkey_init == true)
                mbedtls_ecdh_free(&hkey);

            mbedtls_ecdh_init(&hkey);
            mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
            mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            if (ret != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            hkey_init = true;
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  5));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 2));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 3));
            CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, -FIDO2_ALG_ECDH_ES_HKDF_256));
            CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, FIDO2_CURVE_P256));
            CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 2));
            uint8_t pkey[32];
            mbedtls_mpi_write_binary(&hkey.ctx.mbed_ecdh.Q.X, pkey, 32);
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, pkey, 32));
            CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, 3));
            mbedtls_mpi_write_binary(&hkey.ctx.mbed_ecdh.Q.Y, pkey, 32);
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, pkey, 32));
            CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
        }
        else if (vendorCommandId == CTAP_CONFIG_AUT || vendorCommandId == CTAP_CONFIG_UNLOCK) {
            if (vendorCommandId == CTAP_CONFIG_AUT && (kax.present == false || kay.present == false || vendorAutCt.present == false || alg == 0)) { // Disable
                if (!file_has_data(ef_keydev_enc))
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                if (has_keydev_dec == false)
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                flash_write_data_to_file(ef_keydev, keydev_dec, sizeof(keydev_dec));
                mbedtls_platform_zeroize(keydev_dec, sizeof(keydev_dec));
                flash_write_data_to_file(ef_keydev_enc, NULL, 0); // Set ef to 0 bytes
                low_flash_available();
            }
            else { // Enable
                if (vendorCommandId == CTAP_CONFIG_AUT && !file_has_data(ef_keydev))
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                if (kax.present == false || kay.present == false || alg == 0)
                    CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);

                if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }

                mbedtls_mpi z;
                mbedtls_mpi_init(&z);
                int ret = mbedtls_ecdh_compute_shared(&hkey.ctx.mbed_ecdh.grp, &z, &hkey.ctx.mbed_ecdh.Qp, &hkey.ctx.mbed_ecdh.d, random_gen, NULL);
                if (ret != 0) {
                    mbedtls_mpi_free(&z);
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                uint8_t buf[32], Qpt[65];
                size_t olen = 0;
                ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Qp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, Qpt, sizeof(Qpt));
                if (ret != 0) {
                    mbedtls_mpi_free(&z);
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                ret = mbedtls_mpi_write_binary(&z, buf, sizeof(buf));
                mbedtls_mpi_free(&z);
                if (ret != 0) {
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                uint8_t key_enc[12+32];
                ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, buf, sizeof(buf), Qpt, 65, key_enc, 12+32);
                if (ret != 0){
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }

                mbedtls_chachapoly_context chatx;
                mbedtls_chachapoly_init(&chatx);
                mbedtls_chachapoly_setkey(&chatx, key_enc + 12);
                ret = mbedtls_chachapoly_auth_decrypt(&chatx, vendorAutCt.len - 16, key_enc, Qpt, 65, vendorAutCt.data + vendorAutCt.len - 16, vendorAutCt.data, vendorAutCt.data);
                mbedtls_chachapoly_free(&chatx);
                mbedtls_ecdh_free(&hkey);
                hkey_init = false;
                if (ret != 0) {
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }

                if (vendorCommandId == CTAP_CONFIG_AUT) {
                    uint8_t key_dev_enc[12+32+16];
                    random_gen(NULL, key_dev_enc, 12);
                    mbedtls_chachapoly_init(&chatx);
                    mbedtls_chachapoly_setkey(&chatx, vendorAutCt.data);
                    ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, file_get_size(ef_keydev), key_dev_enc, NULL, 0, file_get_data(ef_keydev), key_dev_enc + 12, key_dev_enc + 12 + file_get_size(ef_keydev));
                    mbedtls_chachapoly_free(&chatx);
                    if (ret != 0){
                        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                    }

                    flash_write_data_to_file(ef_keydev_enc, key_dev_enc, sizeof(key_dev_enc));
                    mbedtls_platform_zeroize(key_dev_enc, sizeof(key_dev_enc));
                    flash_write_data_to_file(ef_keydev, key_dev_enc, file_get_size(ef_keydev)); // Overwrite ef with 0
                    flash_write_data_to_file(ef_keydev, NULL, 0); // Set ef to 0 bytes
                    low_flash_available();
                }
                else if (vendorCommandId == CTAP_CONFIG_UNLOCK) {
                    if (!file_has_data(ef_keydev_enc))
                        CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);

                    uint8_t *keyenc = file_get_data(ef_keydev_enc);
                    size_t keyenc_len = file_get_size(ef_keydev_enc);
                    mbedtls_chachapoly_init(&chatx);
                    mbedtls_chachapoly_setkey(&chatx, vendorAutCt.data);
                    ret = mbedtls_chachapoly_auth_decrypt(&chatx, sizeof(keydev_dec), keyenc, NULL, 0, keyenc + keyenc_len - 16, keyenc + 12, keydev_dec);
                    mbedtls_chachapoly_free(&chatx);
                    if (ret != 0){
                        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                    }
                    has_keydev_dec = true;
                }
            }
            goto err; //No return
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
    CBOR_FREE_BYTE_STRING(vendorAutCt);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}
