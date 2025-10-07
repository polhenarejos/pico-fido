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

#include "pico_keys.h"
#ifndef ESP_PLATFORM
#include "common.h"
#else
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "files.h"
#include "random.h"
#include "crypto_utils.h"
#include "apdu.h"
#include "kek.h"

uint32_t usage_timer = 0, initial_usage_time_limit = 0;
uint32_t max_usage_time_period  = 600 * 1000;
bool needs_power_cycle = false;
static mbedtls_ecdh_context hkey;
static bool hkey_init = false;
extern int encrypt_keydev_f1(const uint8_t keydev[32]);

int beginUsingPinUvAuthToken(bool userIsPresent) {
    paut.user_present = userIsPresent;
    paut.user_verified = true;
    initial_usage_time_limit = board_millis();
    usage_timer = board_millis();
    paut.in_use = true;
    return 0;
}

void clearUserPresentFlag() {
    if (paut.in_use == true) {
        paut.user_present = false;
    }
}

void clearUserVerifiedFlag() {
    if (paut.in_use == true) {
        paut.user_verified = false;
    }
}

void clearPinUvAuthTokenPermissionsExceptLbw() {
    if (paut.in_use == true) {
        paut.permissions = CTAP_PERMISSION_LBW;
    }
}

void stopUsingPinUvAuthToken() {
    paut.permissions = 0;
    usage_timer = 0;
    paut.in_use = false;
    memset(paut.rp_id_hash, 0, sizeof(paut.rp_id_hash));
    paut.has_rp_id = false;
    initial_usage_time_limit = 0;
    paut.user_present = paut.user_verified = false;
    user_present_time_limit = 0;
}

bool getUserPresentFlagValue() {
    if (paut.in_use != true) {
        paut.user_present = false;
    }
    return paut.user_present;
}

bool getUserVerifiedFlagValue() {
    if (paut.in_use != true) {
        paut.user_verified = false;
    }
    return paut.user_verified;
}

int regenerate() {
    if (hkey_init == true) {
        mbedtls_ecdh_free(&hkey);
    }

    mbedtls_ecdh_init(&hkey);
    hkey_init = true;
    mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
    mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
    if (ret != 0) {
        return ret;
    }
    return 0;
}

int kdf(uint8_t protocol, const mbedtls_mpi *z, uint8_t *sharedSecret) {
    int ret = 0;
    uint8_t buf[32];
    ret = mbedtls_mpi_write_binary(z, buf, sizeof(buf));
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buf, sizeof(buf), sharedSecret);
    }
    else if (protocol == 2) {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        ret = mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 HMAC key", 14, sharedSecret, 32);
        if (ret != 0) {
            return ret;
        }
        return mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 AES key", 13, sharedSecret + 32, 32);
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

void resetAuthToken(bool persistent) {
    uint16_t fid = EF_AUTHTOKEN;
    if (persistent) {
        fid = EF_PAUTHTOKEN;
    }
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
    uint8_t t[32];
    random_gen(NULL, t, sizeof(t));
    file_put_data(ef, t, sizeof(t));
    low_flash_available();
}

int resetPinUvAuthToken() {
    resetAuthToken(false);
    paut.permissions = 0;
    paut.data = file_get_data(ef_authtoken);
    paut.len = file_get_size(ef_authtoken);
    return 0;
}

int resetPersistentPinUvAuthToken() {
    resetAuthToken(true);
    file_t *ef_pauthtoken = search_by_fid(EF_PAUTHTOKEN, NULL, SPECIFY_EF);
    ppaut.permissions = 0;
    ppaut.data = file_get_data(ef_pauthtoken);
    ppaut.len = file_get_size(ef_pauthtoken);
    return 0;
}

int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_encrypt(key, NULL, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        random_gen(NULL, out, IV_SIZE);
        memcpy(out + IV_SIZE, in, in_len);
        return aes_encrypt(key + 32, out, 32 * 8, PICO_KEYS_AES_MODE_CBC, out + IV_SIZE, in_len);
    }

    return -1;
}

int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_decrypt(key, NULL, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        memcpy(out, in + IV_SIZE, in_len - IV_SIZE);
        return aes_decrypt(key + 32, in, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len - IV_SIZE);
    }

    return -1;
}

int authenticate(uint8_t protocol, const uint8_t *key, const uint8_t *data, size_t len, uint8_t *sign) {
    uint8_t hmac[32];
    int ret =
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        memcpy(sign, hmac, 16);
    }
    else if (protocol == 2) {
        memcpy(sign, hmac, 32);
    }
    else {
        return -1;
    }
    return 0;
}

int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, uint8_t *sign) {
    uint8_t hmac[32];
    //if (paut.in_use == false)
    //    return -2;
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        return ct_memcmp(sign, hmac, 16);
    }
    else if (protocol == 2) {
        return ct_memcmp(sign, hmac, 32);
    }
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
    if (usage_timer == 0) {
        return -1;
    }
    if (usage_timer + max_usage_time_period > board_millis()) {
        if (user_present_time_limit == 0 ||
            user_present_time_limit + TRANSPORT_TIME_LIMIT < board_millis()) {
            clearUserPresentFlag();
        }
        if (paut.in_use == true) {
            if (initial_usage_time_limit == 0 ||
                initial_usage_time_limit + TRANSPORT_TIME_LIMIT < board_millis()) {
                stopUsingPinUvAuthToken();
                return 1;
            }
        }
        // TO DO: implement a rolling timer
    }
    return 0;
}

int check_keydev_encrypted(const uint8_t pin_token[32]) {
    if (file_get_data(ef_keydev) && *file_get_data(ef_keydev) == 0x01) {
        uint8_t tmp_keydev[61];
        tmp_keydev[0] = 0x02; // Change format to encrypted
        encrypt_with_aad(pin_token, file_get_data(ef_keydev) + 1, 32, tmp_keydev + 1);
        DEBUG_DATA(tmp_keydev, sizeof(tmp_keydev));
        file_put_data(ef_keydev, tmp_keydev, sizeof(tmp_keydev));
        mbedtls_platform_zeroize(tmp_keydev, sizeof(tmp_keydev));
        low_flash_available();
    }
    return PICOKEY_OK;
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
    CborByteString pinUvAuthParam = { 0 }, newPinEnc = { 0 }, pinHashEnc = { 0 }, kax = { 0 }, kay = { 0 };
    CborCharString rpId = { 0 };
    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    uint8_t keydev[32] = {0};
    if (hkey_init == false) {
        initialize();
    }
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 2 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            CBOR_CHECK(COSE_read_key(&_f1, &kty, &alg, &crv, &kax, &kay));
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

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    if (subcommand == 0x0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    else if (subcommand == 0x1) { //getPINRetries
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, needs_power_cycle ? 2 : 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, (uint64_t) *file_get_data(ef_pin)));
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

            CBOR_CHECK(COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2));
        }
        else if (pinUvAuthProtocol == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        else {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    else if (subcommand == 0x3) { //setPIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if ((pinUvAuthProtocol == 1 && newPinEnc.len != 64) ||
            (pinUvAuthProtocol == 2 && newPinEnc.len != 64 + IV_SIZE)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, pinUvAuthParam.data) != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t paddedNewPin[64];
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin)) {
            pin_len++;
        }
        uint8_t minPin = 4;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            minPin = *file_get_data(ef_minpin);
        }
        if (pin_len < minPin) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint8_t hsh[35], dhash[32];
        hsh[0] = MAX_PIN_RETRIES;
        hsh[1] = pin_len;
        hsh[2] = 1; // New format indicator
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, dhash);
        pin_derive_verifier(dhash, 16, hsh + 3);
        file_put_data(ef_pin, hsh, sizeof(hsh));
        low_flash_available();

        pin_derive_session(dhash, 16, session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEY_OK) {
            CBOR_ERROR(ret);
        }
        mbedtls_platform_zeroize(hsh, sizeof(hsh));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        goto err; //No return
    }
    else if (subcommand == 0x4) { //changePIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (*file_get_data(ef_pin) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if ((pinUvAuthProtocol == 1 && (newPinEnc.len != 64 || pinHashEnc.len != 16)) ||
            (pinUvAuthProtocol == 2 &&
             (newPinEnc.len != 64 + IV_SIZE || pinHashEnc.len != 16 + IV_SIZE))) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t tmp[80 + 32];
        memcpy(tmp, newPinEnc.data, newPinEnc.len);
        memcpy(tmp + newPinEnc.len, pinHashEnc.data, pinHashEnc.len);
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, tmp, (uint16_t)(newPinEnc.len + pinHashEnc.len), pinUvAuthParam.data) != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t pin_data[35];
        memcpy(pin_data, file_get_data(ef_pin), file_get_size(ef_pin));
        pin_data[0] -= 1;
        file_put_data(ef_pin, pin_data, file_get_size(ef_pin));
        low_flash_available();
        uint8_t retries = pin_data[0];
        uint8_t paddedNewPin[64];
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (file_get_size(ef_pin) == 34) {
            off = 2;
            double_hash_pin(paddedNewPin, 16, dhash);
        }
        else {
            pin_derive_verifier(paddedNewPin, 16, dhash);
        }

        if (ct_memcmp(dhash, file_get_data(ef_pin) + off, 32) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches >= 3) {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        if (off == 2) {
            // Upgrade pin file to new format
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(paddedNewPin, 16, pin_data + 3);

            hash_multi(paddedNewPin, 16, session_pin);
            ret = load_keydev(keydev);
            if (ret != PICOKEY_OK) {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
            encrypt_keydev_f1(keydev);
        }
        pin_derive_session(paddedNewPin, 16, session_pin);
        pin_data[0] = MAX_PIN_RETRIES;
        file_put_data(ef_pin, pin_data, sizeof(pin_data));
        low_flash_available();

        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEY_OK) {
            CBOR_ERROR(ret);
        }

        new_pin_mismatches = 0;
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin)) {
            pin_len++;
        }
        uint8_t minPin = 4;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            minPin = *file_get_data(ef_minpin);
        }
        if (pin_len < minPin) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        // New PIN is valid and verified
        ret = load_keydev(keydev);
        if (ret != PICOKEY_OK) {
            CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        encrypt_keydev_f1(keydev);

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, dhash);
        pin_derive_session(dhash, 16, session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEY_OK) {
            CBOR_ERROR(ret);
        }
        low_flash_available();

        pin_data[0] = MAX_PIN_RETRIES;
        pin_data[1] = pin_len;
        pin_data[2] = 1; // New format indicator
        pin_derive_verifier(dhash, 16, pin_data + 3);

        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1 && ct_memcmp(pin_data + 3, file_get_data(ef_pin) + 3, 32) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        file_put_data(ef_pin, pin_data, sizeof(pin_data));

        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
            uint8_t *tmpf = (uint8_t *) calloc(1, file_get_size(ef_minpin));
            memcpy(tmpf, file_get_data(ef_minpin), file_get_size(ef_minpin));
            tmpf[1] = 0;
            file_put_data(ef_minpin, tmpf, file_get_size(ef_minpin));
            free(tmpf);
        }
        low_flash_available();
        resetPinUvAuthToken();
        resetPersistentPinUvAuthToken();
        goto err; // No return
    }
    else if (subcommand == 0x9 || subcommand == 0x5) { //getPinUvAuthTokenUsingPinWithPermissions
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x5 && (permissions != 0 || rpId.present == true)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x9) {
            if (permissions == 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if ((permissions & CTAP_PERMISSION_BE)) { // Not supported yet
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
            if ((permissions & CTAP_PERMISSION_PCMR) && permissions != CTAP_PERMISSION_PCMR) {
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (*file_get_data(ef_pin) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t pin_data[35];
        memcpy(pin_data, file_get_data(ef_pin), file_get_size(ef_pin));
        pin_data[0] -= 1;
        file_put_data(ef_pin, pin_data, file_get_size(ef_pin));
        low_flash_available();
        uint8_t retries = pin_data[0];
        uint8_t paddedNewPin[64], poff = ((uint8_t)pinUvAuthProtocol - 1) * IV_SIZE;
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (file_get_size(ef_pin) == 34) {
            off = 2;
            double_hash_pin(paddedNewPin, 16, dhash);
        }
        else {
            pin_derive_verifier(paddedNewPin, 16, dhash);
        }
        if (ct_memcmp(dhash, file_get_data(ef_pin) + off, 32) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches >= 3) {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        mbedtls_platform_zeroize(dhash, sizeof(dhash));

        if (off == 2) {
            // Upgrade pin file to new format
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(paddedNewPin, 16, pin_data + 3);
            hash_multi(paddedNewPin, 16, session_pin);
            ret = load_keydev(keydev);
            if (ret != PICOKEY_OK) {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
            encrypt_keydev_f1(keydev);
        }

        pin_derive_session(paddedNewPin, 16, session_pin);
        ret = check_keydev_encrypted(session_pin);
        if (ret != PICOKEY_OK) {
            CBOR_ERROR(ret);
        }

        pin_data[0] = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;

        file_put_data(ef_pin, pin_data, sizeof(pin_data));
        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));

        low_flash_available();
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
            CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        uint8_t pinUvAuthToken_enc[32 + IV_SIZE], *pdata = NULL;
        if (permissions & CTAP_PERMISSION_PCMR) {
            ppaut.permissions = CTAP_PERMISSION_PCMR;
            pdata = ppaut.data;
        }
        else {
            resetPinUvAuthToken();
            beginUsingPinUvAuthToken(false);
            if (subcommand == 0x05) {
                permissions = CTAP_PERMISSION_MC | CTAP_PERMISSION_GA;
            }
            paut.permissions = (uint8_t)permissions;
            if (rpId.present == true) {
                mbedtls_sha256((uint8_t *) rpId.data, rpId.len, paut.rp_id_hash, 0);
                paut.has_rp_id = true;
            }
            else {
                paut.has_rp_id = false;
            }
            pdata = paut.data;
        }
        encrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pdata, 32, pinUvAuthToken_enc);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pinUvAuthToken_enc, 32 + poff));
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(newPinEnc);
    CBOR_FREE_BYTE_STRING(pinHashEnc);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);
    CBOR_FREE_BYTE_STRING(rpId);
    mbedtls_platform_zeroize(keydev, sizeof(keydev));
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
