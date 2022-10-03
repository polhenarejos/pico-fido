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
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "bsp/board.h"
#include "fido.h"
#include "files.h"
#include "random.h"
#include "crypto_utils.h"
#include "hsm.h"
#include "apdu.h"

uint8_t permissions_rp_id = 0, permission_set = 0;
uint32_t usage_timer = 0, initial_usage_time_limit = 0;
uint32_t max_usage_time_period  = 600*1000;
bool needs_power_cycle = false;
mbedtls_ecdh_context hkey;
bool hkey_init = false;

int beginUsingPinUvAuthToken(bool userIsPresent) {
    paut.user_present = userIsPresent;
    paut.user_verified = true;
    initial_usage_time_limit = board_millis();
    usage_timer = board_millis();
    paut.in_use = true;
    return 0;
}

void clearUserPresentFlag() {
    if (paut.in_use == true)
        paut.user_present = false;
}

void clearUserVerifiedFlag() {
    if (paut.in_use == true)
        paut.user_verified = false;
}

void clearPinUvAuthTokenPermissionsExceptLbw() {
    if (paut.in_use == true)
        paut.permissions = FIDO2_PERMISSION_LBW;
}

void stopUsingPinUvAuthToken() {
    permissions_rp_id = 0;
    paut.permissions = 0;
    usage_timer = 0;
    paut.in_use = false;
    memset(paut.rp_id_hash, 0, sizeof(paut.rp_id_hash));
    initial_usage_time_limit = 0;
    paut.user_present = paut.user_verified = false;
    user_present_time_limit = 0;
}

bool getUserPresentFlagValue() {
    if (paut.in_use != true)
        paut.user_present = false;
    return paut.user_present;
}

 bool getUserVerifiedFlagValue() {
    if (paut.in_use != true)
        paut.user_verified = false;
    return paut.user_verified;
 }

int regenerate() {
    if (hkey_init == true)
        mbedtls_ecdh_free(&hkey);

    mbedtls_ecdh_init(&hkey);
    hkey_init = true;
    mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
    mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
    if (ret != 0)
        return ret;
    return 0;
}

int kdf(uint8_t protocol, const mbedtls_mpi *z, uint8_t *sharedSecret) {
    int ret = 0;
    uint8_t buf[32];
    ret = mbedtls_mpi_write_binary(z, buf, sizeof(buf));
    if (ret != 0)
        return ret;
    if (protocol == 1) {
        return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buf, sizeof(buf), sharedSecret);
    }
    else if (protocol == 2) {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        ret = mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *)"CTAP2 HMAC key", 14, sharedSecret, 32);
        if (ret != 0)
            return ret;
        return mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *)"CTAP2 AES key", 13, sharedSecret+32, 32);
    }
    return -1;
}

int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret) {
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    int ret = mbedtls_ecdh_compute_shared(&hkey.ctx.mbed_ecdh.grp, &z, Q, &hkey.ctx.mbed_ecdh.d, random_gen, NULL);
    ret = kdf(protocol, &z, sharedSecret);
    mbedtls_mpi_free(&z);
    return ret;
}

int resetPinUvAuthToken() {
    uint8_t t[32];
    random_gen(NULL, t, sizeof(t));
    flash_write_data_to_file(ef_authtoken, t, sizeof(t));
    paut.permissions = 0;
    paut.data = file_get_data(ef_authtoken);
    paut.len = file_get_size(ef_authtoken);

    low_flash_available();
    return 0;
}

int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_encrypt(key, NULL, 32*8, HSM_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        random_gen(NULL, out, IV_SIZE);
        memcpy(out + IV_SIZE, in, in_len);
        return aes_encrypt(key+32, out, 32*8, HSM_AES_MODE_CBC, out+IV_SIZE, in_len);
    }

    return -1;
}

int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_decrypt(key, NULL, 32*8, HSM_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        memcpy(out, in+IV_SIZE, in_len);
        return aes_decrypt(key+32, in, 32*8, HSM_AES_MODE_CBC, out, in_len-IV_SIZE);
    }

    return -1;
}

int authenticate(uint8_t protocol, const uint8_t *key, const uint8_t *data, size_t len, uint8_t *sign) {
    uint8_t hmac[32];
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0)
        return ret;
    if (protocol == 1) {
        memcpy(sign, hmac, 16);
    }
    else if (protocol == 2) {
        memcpy(sign, hmac, 32);
    }
    else
        return -1;
    return 0;
}

int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, size_t len, uint8_t *sign) {
    uint8_t hmac[32];
    //if (paut.in_use == false)
    //    return -2;
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0)
        return ret;
    if (protocol == 1)
        return memcmp(sign, hmac, 16);
    else if (protocol == 2)
        return memcmp(sign, hmac, 32);
    return -1;
}

int initialize() {
    regenerate();
    return resetPinUvAuthToken();
}

int getPublicKey() {
    return 0;
}

int pinUvAuthTokenUsageTimerObserver() {
    if (usage_timer == 0)
        return -1;
    if (usage_timer+max_usage_time_period > board_millis()) {
        if (user_present_time_limit == 0 || user_present_time_limit+TRANSPORT_TIME_LIMIT < board_millis())
            clearUserPresentFlag();
        if (paut.in_use == true) {
            if (initial_usage_time_limit == 0 ||  initial_usage_time_limit+TRANSPORT_TIME_LIMIT < board_millis()) {
                stopUsingPinUvAuthToken();
                return 1;
            }
        }
        // TO DO: implement a rolling timer
    }
    return 0;
}

uint8_t new_pin_mismatches = 0;

int cbor_client_pin(const uint8_t *data, size_t len) {
    size_t resp_size = 0;
    uint64_t subcommand = 0x0, pinUvAuthProtocol = 0, permissions = 0;
    int64_t kty = 0, alg = 0, crv = 0;
    CborParser parser;
    CborEncoder encoder, mapEncoder;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = {0}, newPinEnc = {0}, pinHashEnc = {0}, kax = {0}, kay = {0};
    CborCharString rpId = {0};
    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    if (hkey_init == false)
        initialize();
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 2 && val_c != val_u)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (val_u < val_c)
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            int64_t key = 0;
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_INT(key, 2);
                if (key == 1) {
                    CBOR_FIELD_GET_INT(kty, 2);
                }
                else if (key == 3) {
                    CBOR_FIELD_GET_INT(alg, 2);
                }
                else if (key == -1) {
                    CBOR_FIELD_GET_INT(crv, 2);
                }
                else if (key == -2) {
                    CBOR_FIELD_GET_BYTES(kax, 2);
                }
                else if (key == -3) {
                    CBOR_FIELD_GET_BYTES(kay, 2);
                }
                else
                    CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(newPinEnc, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_BYTES(pinHashEnc, 1);
        }
        else if (val_u == 0x09) {
            CBOR_FIELD_GET_UINT(permissions, 1);
        }
        else if (val_u == 0x0A) {
            CBOR_FIELD_GET_TEXT(rpId, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    if (subcommand == 0x0)
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    else if (subcommand == 0x1) { //getPINRetries
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, needs_power_cycle ? 2 : 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, (uint64_t)*file_get_data(ef_pin)));
        if (needs_power_cycle) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
        }
    }
    else if (subcommand == 0x2) { //getKeyAgreement
        if (pinUvAuthProtocol == 1 || pinUvAuthProtocol == 2) {
            CborEncoder mapEncoder2;
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
        else if (pinUvAuthProtocol == 0)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        else
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    else if (subcommand == 0x3) { //setPIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (file_has_data(ef_pin))
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        if ((pinUvAuthProtocol == 1 && newPinEnc.len != 64) || (pinUvAuthProtocol == 2 && newPinEnc.len != 64+IV_SIZE))
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh(pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (verify(pinUvAuthProtocol, sharedSecret, newPinEnc.data, newPinEnc.len, pinUvAuthParam.data) != 0) {
                mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t paddedNewPin[64];
        ret = decrypt(pinUvAuthProtocol, sharedSecret, newPinEnc.data, newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        if (paddedNewPin[63] != 0)
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin))
            pin_len++;
        if (pin_len < 4)
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        uint8_t hsh[33];
        hsh[0] = MAX_PIN_RETRIES;
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, hsh + 1);
        flash_write_data_to_file(ef_pin, hsh, 1+16);
        low_flash_available();
        goto err; //No return
    }
    else if (subcommand == 0x4) { //changePIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0 || pinHashEnc.present == false)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (!file_has_data(ef_pin))
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        if (*file_get_data(ef_pin) == 0)
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        if ((pinUvAuthProtocol == 1 && (newPinEnc.len != 64 || pinHashEnc.len != 16)) || (pinUvAuthProtocol == 2 && (newPinEnc.len != 64+IV_SIZE || pinHashEnc.len != 16+IV_SIZE)))
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh(pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t tmp[64 + 16];
        memcpy(tmp, newPinEnc.data, 64);
        memcpy(tmp + 64, pinHashEnc.data, 16);
        if (verify(pinUvAuthProtocol, sharedSecret, tmp, sizeof(tmp), pinUvAuthParam.data) != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t retries = *file_get_data(ef_pin) - 1;
        flash_write_data_to_file(ef_pin, &retries, 1);
        uint8_t paddedNewPin[64];
        ret = decrypt(pinUvAuthProtocol, sharedSecret, pinHashEnc.data, pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        low_flash_available();
        if (memcmp(paddedNewPin, file_get_data(ef_pin)+1, 16) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches == 3)  {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        retries = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;
        flash_write_data_to_file(ef_pin, &retries, 1);
        ret = decrypt(pinUvAuthProtocol, sharedSecret, newPinEnc.data, newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paddedNewPin[63] != 0)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin))
            pin_len++;
        if (pin_len < 4)
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        uint8_t hsh[33];
        hsh[0] = MAX_PIN_RETRIES;
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, hsh + 1);
        flash_write_data_to_file(ef_pin, hsh, 1+16);
        low_flash_available();
        resetPinUvAuthToken();
        goto err; // No return
    }
    else if (subcommand == 0x9 || subcommand == 0x5) { //getUVRgetPinUvAuthTokenUsingPinWithPermissionsetries
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || alg == 0 || pinHashEnc.present == false)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if ((subcommand == 0x9 && permissions == 0) || (subcommand == 0x5 && (permissions != 0 || rpId.present == true)))
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        if (!file_has_data(ef_pin))
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        if (*file_get_data(ef_pin) == 0)
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh(pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t retries = *file_get_data(ef_pin) - 1;
        flash_write_data_to_file(ef_pin, &retries, 1);
        uint8_t paddedNewPin[64], poff = (pinUvAuthProtocol-1)*IV_SIZE;
        ret = decrypt(pinUvAuthProtocol, sharedSecret, pinHashEnc.data, pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        low_flash_available();
        if (memcmp(paddedNewPin, file_get_data(ef_pin)+1, 16) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches >= 3)  {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        retries = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;
        flash_write_data_to_file(ef_pin, &retries, 1);
        low_flash_available();
        beginUsingPinUvAuthToken(false);
        paut.permissions = permissions;
        if (rpId.present == true)
            memcpy(paut.rp_id_hash, rpId.data, 32);
        else
            memset(paut.rp_id_hash, 0, sizeof(paut.rp_id_hash));
        uint8_t pinUvAuthToken_enc[32+IV_SIZE];
        encrypt(pinUvAuthProtocol, sharedSecret, paut.data, 32, pinUvAuthToken_enc);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pinUvAuthToken_enc, 32+poff));
    }
    else
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(newPinEnc);
    CBOR_FREE_BYTE_STRING(pinHashEnc);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);
    CBOR_FREE_BYTE_STRING(rpId);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}
