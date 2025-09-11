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
#include "pico_keys.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/x509_csr.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

mse_t mse = { .init = false };

int mse_decrypt_ct(uint8_t *data, size_t len) {
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, mse.key_enc + 12);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, len - 16, mse.key_enc, mse.Qpt, 65, data + len - 16, data, data);
    mbedtls_chachapoly_free(&chatx);
    return ret;
}

int cbor_vendor_generic(uint8_t cmd, const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 }, vendorParam = { 0 }, kax = { 0 }, kay = { 0 };
    size_t resp_size = 0;
    uint64_t vendorCmd = 0, pinUvAuthProtocol = 0;
    int64_t kty = 0, alg = 0, crv = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;

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
            CBOR_FIELD_GET_UINT(vendorCmd, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(vendorParam, 2);
                }
                else if (subpara == 0x02) {
                    CBOR_CHECK(COSE_read_key(&_f2, &kty, &alg, &crv, &kax, &kay));
                }
                else {
                    CBOR_ADVANCE(2);
                }
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

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);

    if (cmd == CTAP_VENDOR_BACKUP) {
        if (vendorCmd == 0x01) {
            if (has_keydev_dec == false) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }

            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_keydev_enc), file_get_size(ef_keydev_enc)));
        }
        else if (vendorCmd == 0x02) {
            if (vendorParam.present == false) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            uint8_t zeros[32];
            memset(zeros, 0, sizeof(zeros));
            file_put_data(ef_keydev_enc, vendorParam.data, (uint16_t)vendorParam.len);
            file_put_data(ef_keydev, zeros, file_get_size(ef_keydev)); // Overwrite ef with 0
            file_put_data(ef_keydev, NULL, 0); // Set ef to 0 bytes
            low_flash_available();
            goto err;
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else if (cmd == CTAP_VENDOR_MSE) {
        if (vendorCmd == 0x01) { // KeyAgreement
            if (kax.present == false || kay.present == false || alg == 0) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }

            mbedtls_ecdh_context hkey;
            mbedtls_ecdh_init(&hkey);
            mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
            mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            if (ret != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Qp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, mse.Qpt,sizeof(mse.Qpt));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            ret = mbedtls_ecdh_calc_secret(&hkey, &olen, buf, MBEDTLS_ECP_MAX_BYTES, random_gen, NULL);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                mbedtls_platform_zeroize(buf, sizeof(buf));
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, buf, olen, mse.Qpt, sizeof(mse.Qpt), mse.key_enc, sizeof(mse.key_enc));
            mbedtls_platform_zeroize(buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            mse.init = true;

            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2));
            mbedtls_ecdh_free(&hkey);
        }
    }
    else if (cmd == CTAP_VENDOR_UNLOCK) {
        if (mse.init == false) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }

        mbedtls_chachapoly_context chatx;
        int ret = mse_decrypt_ct(vendorParam.data, vendorParam.len);
        if (ret != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }

        if (!file_has_data(ef_keydev_enc)) {
            CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }

        uint8_t *keyenc = file_get_data(ef_keydev_enc);
        size_t keyenc_len = file_get_size(ef_keydev_enc);
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, vendorParam.data);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, sizeof(keydev_dec), keyenc, NULL, 0, keyenc + keyenc_len - 16, keyenc + 12, keydev_dec);
        mbedtls_chachapoly_free(&chatx);
        if (ret != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        has_keydev_dec = true;
        goto err;
    }
    else if (cmd == CTAP_VENDOR_EA) {
        if (vendorCmd == 0x01) {
            uint8_t buffer[1024];
            mbedtls_ecdsa_context ekey;
            mbedtls_ecdsa_init(&ekey);
            int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ekey, file_get_data(ef_keydev), file_get_size(ef_keydev));
            if (ret != 0) {
                mbedtls_ecdsa_free(&ekey);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            ret = mbedtls_ecp_mul(&ekey.grp, &ekey.Q, &ekey.d, &ekey.grp.G, random_gen, NULL);
            if (ret != 0) {
                mbedtls_ecdsa_free(&ekey);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            mbedtls_x509write_csr ctx;
            mbedtls_x509write_csr_init(&ctx);
            snprintf((char *) buffer, sizeof(buffer), "C=ES,O=Pico Keys,OU=Authenticator Attestation,CN=Pico Fido EE Serial %s", pico_serial_str);
            mbedtls_x509write_csr_set_subject_name(&ctx, (char *) buffer);
            mbedtls_pk_context key;
            mbedtls_pk_init(&key);
            mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            key.pk_ctx = &ekey;
            mbedtls_x509write_csr_set_key(&ctx, &key);
            mbedtls_x509write_csr_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
            mbedtls_x509write_csr_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xE5\x1C\x01\x01\x04", 0xB, 0, aaguid, sizeof(aaguid));
            ret = mbedtls_x509write_csr_der(&ctx, buffer, sizeof(buffer), random_gen, NULL);
            mbedtls_ecdsa_free(&ekey);
            if (ret <= 0) {
                mbedtls_x509write_csr_free(&ctx);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, buffer + sizeof(buffer) - ret, ret));
        }
    }
#ifndef ENABLE_EMULATION
    else if (cmd == CTAP_VENDOR_PHY_OPTS) {
        if (vendorCmd == 0x01) {
            uint16_t opts = 0;
            if (file_has_data(ef_phy)) {
                uint8_t *data = file_get_data(ef_phy);
                opts = get_uint16_t_be(data + PHY_OPTS);
            }
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, opts));
        }
        else {
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }
 #endif
    else if (cmd == CTAP_VENDOR_MEMORY) {
        if (vendorCmd == 0x01) {
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 5));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_free_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_used_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_total_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_num_files()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_size()));
        }
        else {
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorParam);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}

int cbor_vendor(const uint8_t *data, size_t len) {
    if (len == 0) {
        return CTAP1_ERR_INVALID_LEN;
    }
    if (data[0] >= CTAP_VENDOR_BACKUP) {
        return cbor_vendor_generic(data[0], data + 1, len - 1);
    }
    return CTAP2_ERR_INVALID_CBOR;
}
