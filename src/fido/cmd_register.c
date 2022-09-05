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
#include "u2f.h"
#include "mbedtls/ecdsa.h"
#include "random.h"
#include "files.h"

extern int scan_files();

int cmd_register() {
    U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)apdu.data;
    U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)res_APDU;
    resp->registerId = U2F_REGISTER_ID;
    resp->keyHandleLen = KEY_HANDLE_LEN;
    if (scan_files() != CCID_OK)
        return SW_EXEC_ERROR();
    mbedtls_ecdsa_context key;
    mbedtls_ecdsa_init(&key);
    int ret = derive_key(req->appId, true, resp->keyHandleCertSig, &key);
    if (ret != CCID_OK)
    {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&key.grp, &key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, (uint8_t *)&resp->pubKey, U2F_EC_POINT_SIZE);
    mbedtls_ecdsa_free(&key);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    size_t ef_certdev_size = file_get_size(ef_certdev);
    memcpy(resp->keyHandleCertSig + KEY_HANDLE_LEN, file_get_data(ef_certdev), ef_certdev_size);
    uint8_t hash[32], sign_base[1 + U2F_APPID_SIZE + U2F_CHAL_SIZE + KEY_HANDLE_LEN + U2F_EC_POINT_SIZE];
    sign_base[0] = 0x00;
    memcpy(sign_base + 1, req->appId, U2F_APPID_SIZE);
    memcpy(sign_base + 1 + U2F_APPID_SIZE, req->chal, U2F_CHAL_SIZE);
    memcpy(sign_base + 1 + U2F_APPID_SIZE + U2F_CHAL_SIZE, resp->keyHandleCertSig, KEY_HANDLE_LEN);
    memcpy(sign_base + 1 + U2F_APPID_SIZE + U2F_CHAL_SIZE + KEY_HANDLE_LEN, (uint8_t *)&resp->pubKey, U2F_EC_POINT_SIZE);
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sign_base, sizeof(sign_base), hash);
    if (ret != 0)
        return SW_EXEC_ERROR();
    mbedtls_ecdsa_init(&key);
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, file_get_data(ef_keydev), 32);if (ret != CCID_OK)
    {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    ret = mbedtls_ecdsa_write_signature(&key, MBEDTLS_MD_SHA256, hash, 32, (uint8_t *)resp->keyHandleCertSig + KEY_HANDLE_LEN + ef_certdev_size, U2F_MAX_EC_SIG_SIZE, &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&key);
    if (ret != 0)
        return SW_EXEC_ERROR();
    res_APDU_size = sizeof(U2F_REGISTER_RESP) - U2F_MAX_ATT_CERT_SIZE - U2F_MAX_KH_SIZE + KEY_HANDLE_LEN + ef_certdev_size;
    DEBUG_PAYLOAD(res_APDU, res_APDU_size);
    return SW_OK();
}
