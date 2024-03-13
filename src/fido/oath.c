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

#include "fido.h"
#include "pico_keys.h"
#include "apdu.h"
#include "files.h"
#include "random.h"
#include "version.h"
#include "asn1.h"
#include "crypto_utils.h"
#include "management.h"

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8
#define MAX_OTP_COUNTER 3

#define TAG_NAME            0x71
#define TAG_NAME_LIST       0x72
#define TAG_KEY             0x73
#define TAG_CHALLENGE       0x74
#define TAG_RESPONSE        0x75
#define TAG_T_RESPONSE      0x76
#define TAG_NO_RESPONSE     0x77
#define TAG_PROPERTY        0x78
#define TAG_T_VERSION       0x79
#define TAG_IMF             0x7a
#define TAG_ALGO            0x7b
#define TAG_TOUCH_RESPONSE  0x7c
#define TAG_PASSWORD        0x80
#define TAG_NEW_PASSWORD    0x81
#define TAG_PIN_COUNTER     0x82

#define ALG_HMAC_SHA1       0x01
#define ALG_HMAC_SHA256     0x02
#define ALG_HMAC_SHA512     0x03
#define ALG_MASK            0x0f

#define OATH_TYPE_HOTP      0x10
#define OATH_TYPE_TOTP      0x20
#define OATH_TYPE_MASK      0xf0

#define PROP_INC            0x01
#define PROP_TOUCH          0x02

int oath_process_apdu();
int oath_unload();

static bool validated = true;
static uint8_t challenge[CHALLENGE_LEN] = { 0 };

const uint8_t oath_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

int oath_select(app_t *a) {
    if (cap_supported(CAP_OATH)) {
        a->process_apdu = oath_process_apdu;
        a->unload = oath_unload;
        res_APDU_size = 0;
        res_APDU[res_APDU_size++] = TAG_T_VERSION;
        res_APDU[res_APDU_size++] = 3;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
        res_APDU[res_APDU_size++] = 0;
        res_APDU[res_APDU_size++] = TAG_NAME;
        res_APDU[res_APDU_size++] = 8;
#ifndef ENABLE_EMULATION
	    pico_get_unique_board_id((pico_unique_board_id_t *) (res_APDU + res_APDU_size));
	    res_APDU_size += 8;
#else
    	memset(res_APDU + res_APDU_size, 0, 8); res_APDU_size += 8;
#endif
        if (file_has_data(search_dynamic_file(EF_OATH_CODE)) == true) {
            random_gen(NULL, challenge, sizeof(challenge));
            res_APDU[res_APDU_size++] = TAG_CHALLENGE;
            res_APDU[res_APDU_size++] = sizeof(challenge);
            memcpy(res_APDU + res_APDU_size, challenge, sizeof(challenge));
            res_APDU_size += sizeof(challenge);
        }
        file_t *ef_otp_pin = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
        if (file_has_data(ef_otp_pin)) {
            const uint8_t *pin_data = file_get_data(ef_otp_pin);
            res_APDU[res_APDU_size++] = TAG_PIN_COUNTER;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = *pin_data;
        }
        res_APDU[res_APDU_size++] = TAG_ALGO;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = ALG_HMAC_SHA1;
        apdu.ne = res_APDU_size;
        return CCID_OK;
    }
    return CCID_ERR_FILE_NOT_FOUND;
}

void __attribute__((constructor)) oath_ctor() {
    register_app(oath_select, oath_aid);
}

int oath_unload() {
    return CCID_OK;
}

file_t *find_oath_cred(const uint8_t *name, size_t name_len) {
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        asn1_ctx_t ctxi, ef_tag = { 0 };
        asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
        if (file_has_data(ef) && asn1_find_tag(&ctxi, TAG_NAME, &ef_tag) == true && ef_tag.len == name_len && memcmp(ef_tag.data, name, name_len) == 0) {
            return ef;
        }
    }
    return NULL;
}

int cmd_put() {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, key = { 0 }, name = { 0 }, imf = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (asn1_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (asn1_find_tag(&ctxi, TAG_IMF, &imf) == false) {
            memcpy(apdu.data + apdu.nc, "\x7a\x08\x00\x00\x00\x00\x00\x00\x00\x00", 10);
            apdu.nc += 10;
        }
        else { //prepend zero-valued bytes
            if (imf.len < 8) {
                memmove(imf.data + (8 - imf.len), imf.data, imf.len);
                memset(imf.data, 0, 8 - imf.len);
                *(imf.data - 1) = 8;
                apdu.nc += (8 - imf.len);
            }

        }
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef)) {
        flash_write_data_to_file(ef, apdu.data, apdu.nc);
        low_flash_available();
    }
    else {
        for (int i = 0; i < MAX_OATH_CRED; i++) {
            file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
            if (!file_has_data(ef)) {
                ef = file_new(EF_OATH_CRED + i);
                flash_write_data_to_file(ef, apdu.data, apdu.nc);
                low_flash_available();
                return SW_OK();
            }
        }
        return SW_FILE_FULL();
    }
    return SW_OK();
}


int cmd_delete() {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, ctxo = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_NAME, &ctxo) == true) {
        file_t *ef = find_oath_cred(ctxo.data, ctxo.len);
        if (ef) {
            delete_file(ef);
            return SW_OK();
        }
        return SW_DATA_INVALID();
    }
    return SW_INCORRECT_PARAMS();
}

const mbedtls_md_info_t *get_oath_md_info(uint8_t alg) {
    if ((alg & ALG_MASK) == ALG_HMAC_SHA1) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA256) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA512) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    return NULL;
}

int cmd_set_code() {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        delete_file(search_dynamic_file(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    asn1_ctx_t ctxi, key = { 0 }, chal = { 0 }, resp = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key.len == 0) {
        delete_file(search_dynamic_file(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    if (asn1_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (asn1_find_tag(&ctxi, TAG_RESPONSE, &resp) == false) {
        return SW_INCORRECT_PARAMS();
    }

    const mbedtls_md_info_t *md_info = get_oath_md_info(key.data[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, chal.data, chal.len, hmac);
    if (r != 0) {
        return SW_EXEC_ERROR();
    }
    if (memcmp(hmac, resp.data, resp.len) != 0) {
        return SW_DATA_INVALID();
    }
    random_gen(NULL, challenge, sizeof(challenge));
    file_t *ef = file_new(EF_OATH_CODE);
    flash_write_data_to_file(ef, key.data, key.len);
    low_flash_available();
    validated = false;
    return SW_OK();
}

int cmd_reset() {
    if (P1(apdu) != 0xde || P2(apdu) != 0xad) {
        return SW_INCORRECT_P1P2();
    }
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            delete_file(ef);
        }
    }
    delete_file(search_dynamic_file(EF_OATH_CODE));
    flash_clear_file(search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
    low_flash_available();
    validated = true;
    return SW_OK();
}

int cmd_list() {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            asn1_ctx_t ctxi, key = { 0 }, name = { 0 };
            asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
            if (asn1_find_tag(&ctxi, TAG_NAME, &name) == true && asn1_find_tag(&ctxi, TAG_KEY, &key) == true) {
                res_APDU[res_APDU_size++] = TAG_NAME_LIST;
                res_APDU[res_APDU_size++] = name.len + 1;
                res_APDU[res_APDU_size++] = key.data[0];
                memcpy(res_APDU + res_APDU_size, name.data, name.len); res_APDU_size += name.len;
            }
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int cmd_validate() {
    asn1_ctx_t ctxi, key = { 0 }, chal = { 0 }, resp = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (asn1_find_tag(&ctxi, TAG_RESPONSE, &resp) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = search_dynamic_file(EF_OATH_CODE);
    if (file_has_data(ef) == false) {
        validated = true;
        return SW_DATA_INVALID();
    }
    key.data = file_get_data(ef);
    key.len = file_get_size(ef);
    const mbedtls_md_info_t *md_info = get_oath_md_info(key.data[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int ret = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, challenge, sizeof(challenge), hmac);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    if (memcmp(hmac, resp.data, resp.len) != 0) {
        return SW_DATA_INVALID();
    }
    ret = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, chal.data, chal.len, hmac);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    validated = true;
    res_APDU[res_APDU_size++] = TAG_RESPONSE;
    res_APDU[res_APDU_size++] = mbedtls_md_get_size(md_info);
    memcpy(res_APDU + res_APDU_size, hmac, mbedtls_md_get_size(md_info));
    res_APDU_size += mbedtls_md_get_size(md_info);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int calculate_oath(uint8_t truncate,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *chal,
                   size_t chal_len) {
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key + 2, key_len - 2, chal, chal_len, hmac);
    size_t hmac_size = mbedtls_md_get_size(md_info);
    if (r != 0) {
        return CCID_EXEC_ERROR;
    }
    if (truncate == 0x01) {
        res_APDU[res_APDU_size++] = 4 + 1;
        res_APDU[res_APDU_size++] = key[1];
        uint8_t offset = hmac[hmac_size - 1] & 0x0f;
        res_APDU[res_APDU_size++] = hmac[offset] & 0x7f;
        res_APDU[res_APDU_size++] = hmac[offset + 1];
        res_APDU[res_APDU_size++] = hmac[offset + 2];
        res_APDU[res_APDU_size++] = hmac[offset + 3];
    }
    else {
        res_APDU[res_APDU_size++] = hmac_size + 1;
        res_APDU[res_APDU_size++] = key[1];
        memcpy(res_APDU + res_APDU_size, hmac, hmac_size); res_APDU_size += hmac_size;
    }
    apdu.ne = res_APDU_size;
    return CCID_OK;
}

int cmd_calculate() {
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (asn1_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    asn1_ctx_t ctxe;
    asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    if (asn1_find_tag(&ctxe, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }

    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (asn1_find_tag(&ctxe, TAG_IMF, &chal) == false) {
            return SW_INCORRECT_PARAMS();
        }
    }

    res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);

    int ret = calculate_oath(P2(apdu), key.data, key.len, chal.data, chal.len);
    if (ret != CCID_OK) {
        return SW_EXEC_ERROR();
    }
    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        uint64_t v =
            ((uint64_t) chal.data[0] <<
                56) |
            ((uint64_t) chal.data[1] <<
                48) |
            ((uint64_t) chal.data[2] <<
                40) |
            ((uint64_t) chal.data[3] <<
                32) |
            ((uint64_t) chal.data[4] <<
                24) | ((uint64_t) chal.data[5] << 16) | ((uint64_t) chal.data[6] << 8) | (uint64_t) chal.data[7];
        size_t ef_size = file_get_size(ef);
        v++;
        uint8_t *tmp = (uint8_t *) calloc(1, ef_size);
        memcpy(tmp, file_get_data(ef), ef_size);
        asn1_ctx_t ctxt;
        asn1_ctx_init(tmp, ef_size, &ctxt);
        asn1_find_tag(&ctxt, TAG_IMF, &chal);
        chal.data[0] = v >> 56;
        chal.data[1] = v >> 48;
        chal.data[2] = v >> 40;
        chal.data[3] = v >> 32;
        chal.data[4] = v >> 24;
        chal.data[5] = v >> 16;
        chal.data[6] = v >> 8;
        chal.data[7] = v & 0xff;
        flash_write_data_to_file(ef, tmp, ef_size);
        low_flash_available();
        free(tmp);
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int cmd_calculate_all() {
    asn1_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, prop = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (asn1_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    res_APDU_size = 0;
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            const uint8_t *ef_data = file_get_data(ef);
            size_t ef_len = file_get_size(ef);
            asn1_ctx_t ctxe;
            asn1_ctx_init((uint8_t *)ef_data, ef_len, &ctxe);
            if (asn1_find_tag(&ctxe, TAG_NAME, &name) == false || asn1_find_tag(&ctxe, TAG_KEY, &key) == false) {
                continue;
            }
            res_APDU[res_APDU_size++] = TAG_NAME;
            res_APDU[res_APDU_size++] = name.len;
            memcpy(res_APDU + res_APDU_size, name.data, name.len); res_APDU_size += name.len;
            if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
                res_APDU[res_APDU_size++] = TAG_NO_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key.data[1];
            }
            else if (asn1_find_tag(&ctxe, TAG_PROPERTY, &prop) == true && (prop.data[0] & PROP_TOUCH)) {
                res_APDU[res_APDU_size++] = TAG_TOUCH_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key.data[1];
            }
            else {
                res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);
                int ret = calculate_oath(P2(apdu), key.data, key.len, chal.data, chal.len);
                if (ret != CCID_OK) {
                    res_APDU[res_APDU_size++] = 1;
                    res_APDU[res_APDU_size++] = key.data[1];
                }
            }
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int cmd_send_remaining() {
    return SW_OK();
}

int cmd_set_otp_pin() {
    uint8_t hsh[33] = { 0 };
    file_t *ef_otp_pin = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, pw = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    hsh[0] = MAX_OTP_COUNTER;
    double_hash_pin(pw.data, pw.len, hsh + 1);
    flash_write_data_to_file(ef_otp_pin, hsh, sizeof(hsh));
    low_flash_available();
    return SW_OK();
}

int cmd_change_otp_pin() {
    uint8_t hsh[33] = { 0 };
    file_t *ef_otp_pin = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (!file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, pw = { 0 }, new_pw = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_PASSWORD,  &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    double_hash_pin(pw.data, pw.len, hsh + 1);
    if (memcmp(file_get_data(ef_otp_pin) + 1, hsh + 1, 32) != 0) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (asn1_find_tag(&ctxi, TAG_NEW_PASSWORD, &new_pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    hsh[0] = MAX_OTP_COUNTER;
    double_hash_pin(new_pw.data, new_pw.len, hsh + 1);
    flash_write_data_to_file(ef_otp_pin, hsh, sizeof(hsh));
    low_flash_available();
    return SW_OK();
}

int cmd_verify_otp_pin() {
    uint8_t hsh[33] = { 0 }, data_hsh[33];
    file_t *ef_otp_pin = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (!file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, pw = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    double_hash_pin(pw.data, pw.len, hsh + 1);
    memcpy(data_hsh, file_get_data(ef_otp_pin), sizeof(data_hsh));
    if (data_hsh[0] == 0 || memcmp(data_hsh + 1, hsh + 1, 32) != 0) {
        if (data_hsh[0] > 0) {
            data_hsh[0] -= 1;
        }
        flash_write_data_to_file(ef_otp_pin, data_hsh, sizeof(data_hsh));
        low_flash_available();
        validated = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    data_hsh[0] = MAX_OTP_COUNTER;
    flash_write_data_to_file(ef_otp_pin, data_hsh, sizeof(data_hsh));
    low_flash_available();
    validated = true;
    return SW_OK();
}

int cmd_verify_hotp() {
    asn1_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, code = { 0 };
    asn1_ctx_init(apdu.data, apdu.nc, &ctxi);
    uint32_t code_int = 0;
    if (asn1_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    asn1_ctx_t ctxe;
    asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxe);
    if (asn1_find_tag(&ctxe, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }

    if ((key.data[0] & OATH_TYPE_MASK) != OATH_TYPE_HOTP) {
        return SW_DATA_INVALID();
    }
    if (asn1_find_tag(&ctxe, TAG_IMF, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (asn1_find_tag(&ctxi, TAG_RESPONSE, &code) == true) {
        code_int = (code.data[0] << 24) | (code.data[1] << 16) | (code.data[2] << 8) | code.data[3];
    }

    int ret = calculate_oath(0x01, key.data, key.len, chal.data, chal.len);
    if (ret != CCID_OK) {
        return SW_EXEC_ERROR();
    }
    uint32_t res_int = (res_APDU[2] << 24) | (res_APDU[3] << 16) | (res_APDU[4] << 8) | res_APDU[5];
    if (res_APDU[1] == 6) {
        res_int %= (uint32_t) 1e6;
    }
    else {
        res_int %= (uint32_t) 1e8;
    }
    if (res_int != code_int) {
        return SW_WRONG_DATA();
    }
    res_APDU_size = apdu.ne = 0;
    return SW_OK();
}

#define INS_PUT             0x01
#define INS_DELETE          0x02
#define INS_SET_CODE        0x03
#define INS_RESET           0x04
#define INS_LIST            0xa1
#define INS_CALCULATE       0xa2
#define INS_VALIDATE        0xa3
#define INS_CALC_ALL        0xa4
#define INS_SEND_REMAINING  0xa5
#define INS_VERIFY_CODE     0xb1
#define INS_VERIFY_PIN      0xb2
#define INS_CHANGE_PIN      0xb3
#define INS_SET_PIN         0xb4

static const cmd_t cmds[] = {
    { INS_PUT, cmd_put },
    { INS_DELETE, cmd_delete },
    { INS_SET_CODE, cmd_set_code },
    { INS_RESET, cmd_reset },
    { INS_LIST, cmd_list },
    { INS_VALIDATE, cmd_validate },
    { INS_CALCULATE, cmd_calculate },
    { INS_CALC_ALL, cmd_calculate_all },
    { INS_SEND_REMAINING, cmd_send_remaining },
    { INS_SET_PIN, cmd_set_otp_pin },
    { INS_CHANGE_PIN, cmd_change_otp_pin },
    { INS_VERIFY_PIN, cmd_verify_otp_pin },
    { INS_VERIFY_CODE, cmd_verify_hotp },
    { 0x00, 0x0 }
};

int oath_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_OATH)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
