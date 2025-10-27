/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pico_keys.h"
#include "fido.h"
#include "apdu.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "hid/ctap_hid.h"
#include "management.h"

const uint8_t u2f_aid[] = {
    7,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02
};

int u2f_unload();
int u2f_process_apdu();

int u2f_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_U2F)) {
        a->process_apdu = u2f_process_apdu;
        a->unload = u2f_unload;
        return PICOKEY_OK;
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

INITIALIZER ( u2f_ctor ) {
    register_app(u2f_select, u2f_aid);
}

int u2f_unload() {
    return PICOKEY_OK;
}

const uint8_t *bogus_firefox = (const uint8_t *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const uint8_t *bogus_chrome = (const uint8_t *) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

extern int ctap_error(uint8_t error);
int cmd_register() {
    CTAP_REGISTER_REQ *req = (CTAP_REGISTER_REQ *) apdu.data;
    CTAP_REGISTER_RESP *resp = (CTAP_REGISTER_RESP *) res_APDU;
    resp->registerId = CTAP_REGISTER_ID;
    resp->keyHandleLen = KEY_HANDLE_LEN;
    //if (scan_files_fido(true) != PICOKEY_OK)
    //    return SW_EXEC_ERROR();
    if (apdu.nc != CTAP_APPID_SIZE + CTAP_CHAL_SIZE) {
        return SW_WRONG_LENGTH();
    }
    if (wait_button_pressed() == true) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (memcmp(req->appId, bogus_firefox,
               CTAP_APPID_SIZE) == 0 || memcmp(req->appId, bogus_chrome, CTAP_APPID_SIZE) == 0)
    { return ctap_error(CTAP1_ERR_CHANNEL_BUSY); }
    mbedtls_ecdsa_context key;
    mbedtls_ecdsa_init(&key);
    int ret = derive_key(req->appId, true, resp->keyHandleCertSig, MBEDTLS_ECP_DP_SECP256R1, &key);
    if (ret != PICOKEY_OK) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&key.grp, &key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (uint8_t *) &resp->pubKey, CTAP_EC_POINT_SIZE);
    mbedtls_ecdsa_free(&key);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    uint16_t ef_certdev_size = file_get_size(ef_certdev);
    memcpy(resp->keyHandleCertSig + KEY_HANDLE_LEN, file_get_data(ef_certdev), ef_certdev_size);
    uint8_t hash[32], sign_base[1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE + KEY_HANDLE_LEN + CTAP_EC_POINT_SIZE];
    sign_base[0] = CTAP_REGISTER_HASH_ID;
    memcpy(sign_base + 1, req->appId, CTAP_APPID_SIZE);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE, req->chal, CTAP_CHAL_SIZE);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE, resp->keyHandleCertSig, KEY_HANDLE_LEN);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE + KEY_HANDLE_LEN, (uint8_t *) &resp->pubKey, CTAP_EC_POINT_SIZE);
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sign_base, sizeof(sign_base), hash);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    mbedtls_ecdsa_init(&key);
    uint8_t key_dev[32] = {0};
    ret = load_keydev(key_dev);
    if (ret != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, key_dev, 32);
    mbedtls_platform_zeroize(key_dev, sizeof(key_dev));
    if (ret != PICOKEY_OK) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    ret = mbedtls_ecdsa_write_signature(&key,MBEDTLS_MD_SHA256, hash, 32, (uint8_t *) resp->keyHandleCertSig + KEY_HANDLE_LEN + ef_certdev_size, CTAP_MAX_EC_SIG_SIZE, &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&key);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = sizeof(CTAP_REGISTER_RESP) - sizeof(resp->keyHandleCertSig) + KEY_HANDLE_LEN + ef_certdev_size + (uint16_t)olen;
    return SW_OK();
}

extern int cmd_register();
extern int cmd_authenticate();
extern int cmd_version();

static const cmd_t cmds[] = {
    { CTAP_REGISTER, cmd_register },
    { CTAP_AUTHENTICATE, cmd_authenticate },
    { CTAP_VERSION, cmd_version },
    { 0x00, 0x0 }
};

int u2f_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_U2F)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
