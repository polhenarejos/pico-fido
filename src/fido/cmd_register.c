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
#include "hsm.h"
#include "apdu.h"
#include "ctap.h"
#include "mbedtls/ecdsa.h"
#include "random.h"
#include "files.h"

const uint8_t *bogus_firefox = (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const uint8_t *bogus_chrome = (const uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

extern int ctap_error(uint8_t error);
int cmd_register() {
    CTAP_REGISTER_REQ *req = (CTAP_REGISTER_REQ *)apdu.data;
    CTAP_REGISTER_RESP *resp = (CTAP_REGISTER_RESP *)res_APDU;
    resp->registerId = CTAP_REGISTER_ID;
    resp->keyHandleLen = KEY_HANDLE_LEN;
    //if (scan_files(true) != CCID_OK)
    //    return SW_EXEC_ERROR();
    if (apdu.nc != CTAP_APPID_SIZE + CTAP_CHAL_SIZE)
        return SW_WRONG_LENGTH();
    if (wait_button_pressed() == true)
        return SW_CONDITIONS_NOT_SATISFIED();
    if (memcmp(req->appId, bogus_firefox, CTAP_APPID_SIZE) == 0 || memcmp(req->appId, bogus_chrome, CTAP_APPID_SIZE) == 0)
        return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
    mbedtls_ecdsa_context key;
    mbedtls_ecdsa_init(&key);
    int ret = derive_key(req->appId, true, resp->keyHandleCertSig, MBEDTLS_ECP_DP_SECP256R1, &key);
    if (ret != CCID_OK) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&key.grp, &key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (uint8_t *)&resp->pubKey, CTAP_EC_POINT_SIZE);
    mbedtls_ecdsa_free(&key);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    size_t ef_certdev_size = file_get_size(ef_certdev);
    memcpy(resp->keyHandleCertSig + KEY_HANDLE_LEN, file_get_data(ef_certdev), ef_certdev_size);
    uint8_t hash[32], sign_base[1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE + KEY_HANDLE_LEN + CTAP_EC_POINT_SIZE];
    sign_base[0] = CTAP_REGISTER_HASH_ID;
    memcpy(sign_base + 1, req->appId, CTAP_APPID_SIZE);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE, req->chal, CTAP_CHAL_SIZE);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE, resp->keyHandleCertSig, KEY_HANDLE_LEN);
    memcpy(sign_base + 1 + CTAP_APPID_SIZE + CTAP_CHAL_SIZE + KEY_HANDLE_LEN, (uint8_t *)&resp->pubKey, CTAP_EC_POINT_SIZE);
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sign_base, sizeof(sign_base), hash);
    if (ret != 0)
        return SW_EXEC_ERROR();
    mbedtls_ecdsa_init(&key);
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, file_get_data(ef_keydev), 32);
    if (ret != CCID_OK) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    ret = mbedtls_ecdsa_write_signature(&key, MBEDTLS_MD_SHA256, hash, 32, (uint8_t *)resp->keyHandleCertSig + KEY_HANDLE_LEN + ef_certdev_size, CTAP_MAX_EC_SIG_SIZE, &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&key);
    if (ret != 0)
        return SW_EXEC_ERROR();
    res_APDU_size = sizeof(CTAP_REGISTER_RESP) - sizeof(resp->keyHandleCertSig) + KEY_HANDLE_LEN + ef_certdev_size + olen;
    return SW_OK();
}
