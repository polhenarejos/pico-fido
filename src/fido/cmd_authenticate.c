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

int cmd_authenticate() {
    U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)apdu.data;
    U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)res_APDU;
    if (scan_files() != CCID_OK)
        return SW_EXEC_ERROR();
    if (req->keyHandleLen != KEY_HANDLE_LEN)
        return SW_WRONG_DATA();
    if (P1(apdu) == 0x03 && wait_button_pressed() == true)
        return SW_CONDITIONS_NOT_SATISFIED();

    mbedtls_ecdsa_context key;
    mbedtls_ecdsa_init(&key);
    int ret = derive_key(req->appId, false, req->keyHandle, &key);
    if (ret != CCID_OK) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    if (P1(apdu) == 0x07) {
        for (int i = 0; i < KEY_PATH_ENTRIES; i++) {
            uint32_t k = *(uint32_t *)&req->keyHandle[i*sizeof(uint32_t)];
            if (!(k & 0x80000000)) {
                mbedtls_ecdsa_free(&key);
                return SW_WRONG_DATA();
            }
        }
        uint8_t hmac[32], d[32];
        ret = mbedtls_ecp_write_key(&key, d, sizeof(d));
        mbedtls_ecdsa_free(&key);
        if (ret != 0)
            return SW_WRONG_DATA();
        uint8_t key_base[U2F_APPID_SIZE + KEY_PATH_LEN];
        memcpy(key_base, req->appId, U2F_APPID_SIZE);
        memcpy(key_base + U2F_APPID_SIZE, req->keyHandle, KEY_PATH_LEN);
        ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), d, 32, key_base, sizeof(key_base), hmac);
        mbedtls_platform_zeroize(d, sizeof(d));
        if (memcmp(req->keyHandle + KEY_PATH_LEN, hmac, sizeof(hmac)) != 0)
            return SW_WRONG_DATA();
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    resp->flags = 0x1;
    resp->ctr[0] = 0;
    uint8_t hash[32], sig_base[U2F_APPID_SIZE+1+4+U2F_CHAL_SIZE];
    memcpy(sig_base, req->appId, U2F_APPID_SIZE);
    memcpy(sig_base+U2F_APPID_SIZE, &resp->flags, sizeof(uint8_t));
    memcpy(sig_base + U2F_APPID_SIZE + 1, resp->ctr, 4);
    memcpy(sig_base + U2F_APPID_SIZE + 1 + 4, req->chal, U2F_CHAL_SIZE);
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sig_base, sizeof(sig_base), hash);
    if (ret != 0) {
        mbedtls_ecdsa_free(&key);
        return SW_EXEC_ERROR();
    }
    size_t olen = 0;
    ret = mbedtls_ecdsa_write_signature(&key, MBEDTLS_MD_SHA256, hash, 32, (uint8_t *)resp->sig, U2F_MAX_EC_SIG_SIZE, &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&key);
    if (ret != 0)
        return SW_EXEC_ERROR();
    res_APDU_size = 1 + 4 + olen;
    return SW_OK();
}
