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
#include "fido.h"
#include "hsm.h"
#include "apdu.h"
#include "ctap.h"
#include "files.h"
#include "file.h"
#include "usb.h"
#include "random.h"
#include "bsp/board.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/hkdf.h"
#include "pk_wrap.h"
#include "crypto_utils.h"
#include "ccid.h"
#include "version.h"
#include "asn1.h"
#include <stdio.h>

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8

#define TAG_NAME            0x71
#define TAG_NAME_LIST       0x72
#define TAG_KEY             0x73
#define TAG_CHALLENGE       0x74
#define TAG_RESPONSE        0x75
#define TAG_T_RESPONSE      0x76
#define TAG_NO_RESPONSE     0x77
#define TAG_PROPERTY        0x78
#define TAG_VERSION         0x79
#define TAG_IMF             0x7a
#define TAG_ALGO            0x7b
#define TAG_TOUCH_RESPONSE  0x7c

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
static uint8_t challenge[CHALLENGE_LEN] = {0};

const uint8_t oath_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

app_t *oath_select(app_t *a, const uint8_t *aid, uint8_t aid_len) {
    if (!memcmp(aid, oath_aid+1, MIN(aid_len,oath_aid[0]))) {
        a->aid = oath_aid;
        a->process_apdu = oath_process_apdu;
        a->unload = oath_unload;
        res_APDU_size = 0;
        res_APDU[res_APDU_size++] = TAG_VERSION;
        res_APDU[res_APDU_size++] = 3;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
        res_APDU[res_APDU_size++] = 0;
        res_APDU[res_APDU_size++] = TAG_NAME;
        res_APDU[res_APDU_size++] = 8;
        pico_get_unique_board_id((pico_unique_board_id_t *)(res_APDU+res_APDU_size)); res_APDU_size += 8;
        if (file_has_data(search_dynamic_file(EF_OATH_CODE)) == true) {
            res_APDU[res_APDU_size++] = TAG_CHALLENGE;
            res_APDU[res_APDU_size++] = sizeof(challenge);
            memcpy(res_APDU+res_APDU_size, challenge, sizeof(challenge)); res_APDU_size += sizeof(challenge);
        }
        return a;
    }
    return NULL;
}

void __attribute__ ((constructor)) oath_ctor() {
    register_app(oath_select);
}

int oath_unload() {
    return CCID_OK;
}

int cmd_put() {
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    size_t key_len = 0, imf_len = 0;
    uint8_t *key = NULL, *imf;
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_KEY, &key_len, &key) == false)
        return SW_INCORRECT_PARAMS();
    if ((key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (asn1_find_tag(apdu.data, apdu.nc, TAG_IMF, &imf_len, &imf) == false) {
            memcpy(apdu.data + apdu.nc, "\x7a\x08\x00\x00\x00\x00\x00\x00\x00\x00", 10);
            apdu.nc += 10;
        }
        else { //prepend zero-valued bytes
            if (imf_len < 8) {
                memmove(imf+(8-imf_len), imf, imf_len);
                memset(imf, 0, 8-imf_len);
                *(imf-1) = 8;
                apdu.nc += (8-imf_len);
            }

        }
    }
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

file_t *find_oath_cred(const uint8_t *name, size_t name_len) {
    size_t ef_tag_len = 0;
    uint8_t *ef_tag_data = NULL;
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef) && asn1_find_tag(file_get_data(ef), file_get_size(ef), TAG_NAME, &ef_tag_len, &ef_tag_data) == true && ef_tag_len == name_len && memcmp(ef_tag_data, name, name_len) == 0) {
            return ef;
        }
    }
    return NULL;
}

int cmd_delete() {
    size_t tag_len = 0;
    uint8_t *tag_data = NULL;
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_NAME, &tag_len, &tag_data) == true) {
        file_t *ef = find_oath_cred(tag_data, tag_len);
        if (ef) {
            delete_file(ef);
            return SW_OK();
        }
        return SW_DATA_INVALID();
    }
    return SW_INCORRECT_PARAMS();
}

const mbedtls_md_info_t *get_oath_md_info(uint8_t alg) {
    if ((alg & ALG_MASK) == ALG_HMAC_SHA1)
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA256)
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA512)
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    return NULL;
}

int cmd_set_code() {
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (apdu.nc == 0) {
        delete_file(search_dynamic_file(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    size_t key_len = 0, chal_len = 0, resp_len = 0;
    uint8_t *key = NULL, *chal = NULL, *resp = NULL;
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_KEY, &key_len, &key) == false)
        return SW_INCORRECT_PARAMS();
    if (key_len == 0) {
        delete_file(search_dynamic_file(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_CHALLENGE, &chal_len, &chal) == false)
        return SW_INCORRECT_PARAMS();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_RESPONSE, &resp_len, &resp) == false)
        return SW_INCORRECT_PARAMS();

    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL)
        return SW_INCORRECT_PARAMS();
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key+1, key_len-1, chal, chal_len, hmac);
    if (r != 0)
        return SW_EXEC_ERROR();
    if (memcmp(hmac, resp, resp_len) != 0)
        return SW_DATA_INVALID();
    random_gen(NULL, challenge, sizeof(challenge));
    file_t *ef = file_new(EF_OATH_CODE);
    flash_write_data_to_file(ef, key, key_len);
    low_flash_available();
    validated = false;
    return SW_OK();
}

int cmd_reset() {
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            delete_file(ef);
        }
    }
    delete_file(search_dynamic_file(EF_OATH_CODE));
    validated = true;
    return SW_OK();
}

int cmd_list() {
    size_t name_len = 0, key_len = 0;
    uint8_t *name = NULL, *key = NULL;
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            uint8_t *data = file_get_data(ef);
            size_t data_len = file_get_size(ef);
            if (asn1_find_tag(data, data_len, TAG_NAME, &name_len, &name) == true && asn1_find_tag(data, data_len, TAG_KEY, &key_len, &key) == true) {
                res_APDU[res_APDU_size++] = TAG_NAME_LIST;
                res_APDU[res_APDU_size++] = name_len + 1;
                res_APDU[res_APDU_size++] = key[0];
                memcpy(res_APDU+res_APDU_size, name, name_len); res_APDU_size += name_len;
            }
        }
    }
    return SW_OK();
}

int cmd_validate() {
    size_t chal_len = 0, resp_len = 0, key_len = 0;
    uint8_t *chal = NULL, *resp = NULL, *key = NULL;
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_CHALLENGE, &chal_len, &chal) == false)
        return SW_INCORRECT_PARAMS();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_RESPONSE, &resp_len, &resp) == false)
        return SW_INCORRECT_PARAMS();
    file_t *ef = search_dynamic_file(EF_OATH_CODE);
    if (file_has_data(ef) == false) {
        validated = true;
        return SW_DATA_INVALID();
    }
    key = file_get_data(ef);
    key_len = file_get_size(ef);
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL)
        return SW_INCORRECT_PARAMS();
    uint8_t hmac[64];
    int ret = mbedtls_md_hmac(md_info, key+1, key_len-1, challenge, sizeof(challenge), hmac);
    if (ret != 0)
        return SW_EXEC_ERROR();
    if (memcmp(hmac, resp, resp_len) != 0)
        return SW_DATA_INVALID();
    ret = mbedtls_md_hmac(md_info, key+1, key_len-1, chal, chal_len, hmac);
    if (ret != 0)
        return SW_EXEC_ERROR();
    validated = true;
    res_APDU[res_APDU_size++] = TAG_RESPONSE;
    res_APDU[res_APDU_size++] = mbedtls_md_get_size(md_info);
    memcpy(res_APDU+res_APDU_size, hmac, mbedtls_md_get_size(md_info)); res_APDU_size += mbedtls_md_get_size(md_info);
    return SW_OK();
}

int calculate_oath(uint8_t truncate, const uint8_t *key, size_t key_len, const uint8_t *chal, size_t chal_len) {
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL)
        return SW_INCORRECT_PARAMS();
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key+2, key_len-2, chal, chal_len, hmac);
    size_t hmac_size = mbedtls_md_get_size(md_info);
    if (r != 0)
        return CCID_EXEC_ERROR;
    if (truncate == 0x01) {
        res_APDU[res_APDU_size++] = 4+1;
        res_APDU[res_APDU_size++] = key[1];
        uint8_t offset = hmac[hmac_size-1] & 0x0f;
        res_APDU[res_APDU_size++] = hmac[offset] & 0x7f;
        res_APDU[res_APDU_size++] = hmac[offset+1];
        res_APDU[res_APDU_size++] = hmac[offset+2];
        res_APDU[res_APDU_size++] = hmac[offset+3];
    }
    else {
        res_APDU[res_APDU_size++] = hmac_size+1;
        res_APDU[res_APDU_size++] = key[1];
        memcpy(res_APDU+res_APDU_size, hmac, hmac_size); res_APDU_size += hmac_size;
    }
    return CCID_OK;
}

int cmd_calculate() {
    size_t chal_len = 0, name_len = 0, key_len = 0;
    uint8_t *chal = NULL, *name = NULL, *key = NULL;
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1)
        return SW_INCORRECT_P1P2();
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_CHALLENGE, &chal_len, &chal) == false)
        return SW_INCORRECT_PARAMS();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_NAME, &name_len, &name) == false)
        return SW_INCORRECT_PARAMS();
    file_t *ef = find_oath_cred(name, name_len);
    if (file_has_data(ef) == false)
        return SW_DATA_INVALID();

    if (asn1_find_tag(file_get_data(ef), file_get_size(ef), TAG_KEY, &key_len, &key) == false)
        return SW_INCORRECT_PARAMS();

    if ((key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (asn1_find_tag(file_get_data(ef), file_get_size(ef), TAG_IMF, &chal_len, &chal) == false)
        return SW_INCORRECT_PARAMS();
    }

    res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);

    int ret = calculate_oath(P2(apdu), key, key_len, chal, chal_len);
    if (ret != CCID_OK)
        return SW_EXEC_ERROR();
    if ((key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        uint64_t v = ((uint64_t)chal[0] << 56) | ((uint64_t)chal[1] << 48) | ((uint64_t)chal[2] << 40) | ((uint64_t)chal[3] << 32) | ((uint64_t)chal[4] << 24) | ((uint64_t)chal[5] << 16) | ((uint64_t)chal[6] << 8) | (uint64_t)chal[7];
        size_t ef_size = file_get_size(ef);
        v++;
        uint8_t *tmp = (uint8_t *)calloc(1, ef_size);
        memcpy(tmp, file_get_data(ef), ef_size);
        asn1_find_tag(tmp, ef_size, TAG_IMF, &chal_len, &chal);
        chal[0] = v >> 56;
        chal[1] = v >> 48;
        chal[2] = v >> 40;
        chal[3] = v >> 32;
        chal[4] = v >> 24;
        chal[5] = v >> 16;
        chal[6] = v >> 8;
        chal[7] = v & 0xff;
        flash_write_data_to_file(ef, tmp, ef_size);
        low_flash_available();
        free(tmp);
    }
    return SW_OK();
}

int cmd_calculate_all() {
    size_t chal_len = 0, name_len = 0, key_len = 0, prop_len = 0;
    uint8_t *chal = NULL, *name = NULL, *key = NULL, *prop = NULL;
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1)
        return SW_INCORRECT_P1P2();
    if (validated == false)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (asn1_find_tag(apdu.data, apdu.nc, TAG_CHALLENGE, &chal_len, &chal) == false)
        return SW_INCORRECT_PARAMS();
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file(EF_OATH_CRED + i);
        if (file_has_data(ef)) {
            const uint8_t *ef_data = file_get_data(ef);
            size_t ef_len = file_get_size(ef);
            if (asn1_find_tag(ef_data, ef_len, TAG_NAME, &name_len, &name) == false || asn1_find_tag(ef_data, ef_len, TAG_KEY, &key_len, &key) == false)
                continue;
            res_APDU[res_APDU_size++] = TAG_NAME;
            res_APDU[res_APDU_size++] = name_len;
            memcpy(res_APDU+res_APDU_size, name, name_len); res_APDU_size += name_len;
            if ((key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
                res_APDU[res_APDU_size++] = TAG_NO_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key[1];
            }
            else if (asn1_find_tag(ef_data, ef_len, TAG_PROPERTY, &prop_len, &prop) == true && (prop[0] & PROP_TOUCH)) {
                res_APDU[res_APDU_size++] = TAG_TOUCH_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key[1];
            }
            else {
                res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);
                int ret = calculate_oath(P2(apdu), key, key_len, chal, chal_len);
                if (ret != CCID_OK) {
                    res_APDU[res_APDU_size++] = 1;
                    res_APDU[res_APDU_size++] = key[1];
                }
            }
        }
    }
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

static const cmd_t cmds[] = {
    { INS_PUT, cmd_put },
    { INS_DELETE, cmd_delete },
    { INS_SET_CODE, cmd_set_code },
    { INS_RESET, cmd_reset },
    { INS_LIST, cmd_list },
    { INS_VALIDATE, cmd_validate },
    { INS_CALCULATE, cmd_calculate },
    { INS_CALC_ALL, cmd_calculate_all },
    { 0x00, 0x0}
};

int oath_process_apdu() {
    if (CLA(apdu) != 0x00)
        return SW_CLA_NOT_SUPPORTED();
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++)
    {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
