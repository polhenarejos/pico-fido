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
#include <math.h>
#include <stdio.h>

void init_fido(bool);
int fido_process_apdu();
int fido_unload();

pinUvAuthToken_t paut = {0};

const uint8_t fido_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

app_t *fido_select(app_t *a) {
    a->aid = fido_aid;
    a->process_apdu = fido_process_apdu;
    a->unload = fido_unload;
    current_app = a;
    init_fido(false);
    return a;
}

void __attribute__ ((constructor)) fido_ctor() {
    register_app(fido_select);
    //fido_select(&apps[0]);
}

int fido_unload() {
    return CCID_OK;
}

mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve) {
    if (curve == FIDO2_CURVE_P256)
        return MBEDTLS_ECP_DP_SECP256R1;
    else if (curve == FIDO2_CURVE_P384)
        return MBEDTLS_ECP_DP_SECP384R1;
    else if (curve == FIDO2_CURVE_P521)
        return MBEDTLS_ECP_DP_SECP521R1;
    else if (curve == FIDO2_CURVE_P256K1)
        return MBEDTLS_ECP_DP_SECP256K1;
    else if (curve == FIDO2_CURVE_X25519)
        return MBEDTLS_ECP_DP_CURVE25519;
    else if (curve == FIDO2_CURVE_X448)
        return MBEDTLS_ECP_DP_CURVE448;
    return MBEDTLS_ECP_DP_NONE;
}

int fido_load_key(int curve, const uint8_t *cred_id, mbedtls_ecdsa_context *key) {
    mbedtls_ecp_group_id mbedtls_curve = fido_curve_to_mbedtls(curve);
    if (mbedtls_curve == MBEDTLS_ECP_DP_NONE)
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    uint8_t key_path[KEY_PATH_LEN];
    memcpy(key_path, cred_id, KEY_PATH_LEN);
    *(uint32_t *)key_path = 0x80000000 | 10022;
    for (int i = 1; i < KEY_PATH_ENTRIES; i++)
        *(uint32_t *)(key_path+i*sizeof(uint32_t)) |= 0x80000000;
    return derive_key(NULL, false, key_path, mbedtls_curve, key);
}

int x509_create_cert(mbedtls_ecdsa_context *ecdsa, uint8_t *buffer, size_t buffer_size, bool core1) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20220901000000", "20320831235959" );
    mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    mbedtls_x509write_crt_set_subject_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_fill_random(&serial, 32, core1 ? random_gen : random_gen_core0, NULL);
    mbedtls_x509write_crt_set_serial(&ctx, &serial);
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    key.pk_ctx = ecdsa;
    mbedtls_x509write_crt_set_subject_key(&ctx, &key);
    mbedtls_x509write_crt_set_issuer_key(&ctx, &key);
    mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN);
    int ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, core1 ? random_gen : random_gen_core0, NULL);
    return ret;
}

int load_keydev(uint8_t *key) {
    if (!ef_keydev || file_get_size(ef_keydev) == 0)
        return CCID_ERR_MEMORY_FATAL;
    memcpy(key, file_get_data(ef_keydev), file_get_size(ef_keydev));
    //return mkek_decrypt(key, file_get_size(ef_keydev));
    return CCID_OK;
}

int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, int curve, mbedtls_ecdsa_context *key) {
    uint8_t outk[64] = {0};
    int r = 0;
    memset(outk, 0, sizeof(outk));
    if ((r = load_keydev(outk)) != CCID_OK)
        return r;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    for (int i = 0; i < KEY_PATH_ENTRIES; i++)
    {
        if (new_key == true) {
            uint32_t val = 0;
            random_gen(NULL, (uint8_t *) &val, sizeof(val));
            val |= 0x80000000;
            memcpy(&key_handle[i*sizeof(uint32_t)], &val, sizeof(uint32_t));
        }
        r = mbedtls_hkdf(md_info, &key_handle[i * sizeof(uint32_t)], sizeof(uint32_t), outk, 32, outk + 32, 32, outk, sizeof(outk));
        if (r != 0)
        {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return r;
        }
    }
    if (new_key == true) {
        uint8_t key_base[CTAP_APPID_SIZE + KEY_PATH_LEN];
        memcpy(key_base, app_id, CTAP_APPID_SIZE);
        memcpy(key_base + CTAP_APPID_SIZE, key_handle, KEY_PATH_LEN);
        if ((r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, key_base, sizeof(key_base), key_handle + 32)) != 0)
        {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return r;
        }
    }
    if (key != NULL) {
        mbedtls_ecp_group_load(&key->grp, curve);
        const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(curve);
        if (cinfo == NULL)
            return 1;
        r = mbedtls_ecp_read_key(curve, key, outk, ceil((float)cinfo->bit_size/8));
        mbedtls_platform_zeroize(outk, sizeof(outk));
        if (r != 0)
            return r;
        return mbedtls_ecp_mul(&key->grp, &key->Q, &key->d, &key->grp.G, random_gen, NULL);
    }
    mbedtls_platform_zeroize(outk, sizeof(outk));
    return r;
}

int scan_files(bool core1) {
    ef_keydev = search_by_fid(EF_KEY_DEV, NULL, SPECIFY_EF);
    if (ef_keydev) {
        if (!file_has_data(ef_keydev)) {
            printf("KEY DEVICE is empty. Generating SECP256R1 curve...");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            uint8_t index = 0;
            int ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1, core1 ? random_gen : random_gen_core0, &index);
            if (ret != 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return ret;
            }
            uint8_t kdata[32];
            int key_size = mbedtls_mpi_size(&ecdsa.d);
            mbedtls_mpi_write_binary(&ecdsa.d, kdata, key_size);
            ret = flash_write_data_to_file(ef_keydev, kdata, key_size);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            mbedtls_ecdsa_free(&ecdsa);
            if (ret != CCID_OK) {
                return ret;
            }
            printf(" done!\n");
        }
    }
    else {
        printf("FATAL ERROR: KEY DEV not found in memory!\r\n");
    }
    ef_certdev = search_by_fid(EF_EE_DEV, NULL, SPECIFY_EF);
    if (ef_certdev) {
        if (!file_has_data(ef_certdev)) {
            uint8_t cert[4096];
            mbedtls_ecdsa_context key;
            mbedtls_ecdsa_init(&key);
            int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, file_get_data(ef_keydev), file_get_size(ef_keydev));
            if (ret != 0)
                return ret;
            ret = mbedtls_ecp_mul(&key.grp, &key.Q, &key.d, &key.grp.G, random_gen, NULL);
            if (ret != 0)
                return ret;
            ret = x509_create_cert(&key, cert, sizeof(cert), core1);
            mbedtls_ecdsa_free(&key);
            if (ret <= 0)
                return ret;
            flash_write_data_to_file(ef_certdev, cert + sizeof(cert) - ret, ret);
        }
    }
    else {
        printf("FATAL ERROR: CERT DEV not found in memory!\r\n");
    }
    ef_counter = search_by_fid(EF_COUNTER, NULL, SPECIFY_EF);
    if (ef_counter) {
        if (!file_has_data(ef_counter)) {
            uint32_t v = 0;
            flash_write_data_to_file(ef_counter, (uint8_t *)&v, sizeof(v));
        }
    }
    else {
        printf("FATAL ERROR: Global counter not found in memory!\r\n");
    }
    ef_pin = search_by_fid(EF_PIN, NULL, SPECIFY_EF);
    ef_authtoken = search_by_fid(EF_AUTHTOKEN, NULL, SPECIFY_EF);
    if (ef_authtoken) {
        if (!file_has_data(ef_authtoken)) {
            uint8_t t[32];
            if (core1)
                random_gen(NULL, t, sizeof(t));
            else
                random_gen_core0(NULL, t, sizeof(t));
            flash_write_data_to_file(ef_authtoken, t, sizeof(t));
        }
        paut.data = file_get_data(ef_authtoken);
        paut.len = file_get_size(ef_authtoken);
    }
    else {
        printf("FATAL ERROR: Auth Token not found in memory!\r\n");
    }
    low_flash_available();
    return CCID_OK;
}

void scan_all(bool core1) {
    scan_flash();
    scan_files(core1);
}

void init_fido(bool core1) {
    scan_all(core1);
}

bool wait_button_pressed() {
    uint32_t val = EV_PRESS_BUTTON;
#if defined(ENABLE_UP_BUTTON) && ENABLE_UP_BUTTON==1
    queue_try_add(&card_to_usb_q, &val);
    do {
        queue_remove_blocking(&usb_to_card_q, &val);
    } while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
#endif
    return (val == EV_BUTTON_TIMEOUT);
}

uint32_t user_present_time_limit = 0;

bool check_user_presence() {
#if defined(ENABLE_UP_BUTTON) && ENABLE_UP_BUTTON==1
    if (user_present_time_limit == 0 || user_present_time_limit+TRANSPORT_TIME_LIMIT < board_millis()) {
        if (wait_button_pressed() == true) //timeout
            return false;
        user_present_time_limit = board_millis();
    }
#endif
    return true;
}

uint32_t get_sign_counter() {
    uint8_t *caddr = file_get_data(ef_counter);
    return (*caddr) | (*(caddr + 1) << 8) | (*(caddr + 2) << 16) | (*(caddr + 3) << 24);
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

extern int cmd_register();
extern int cmd_authenticate();
extern int cmd_version();

static const cmd_t cmds[] = {
    { CTAP_REGISTER, cmd_register },
    { CTAP_AUTHENTICATE, cmd_authenticate },
    { CTAP_VERSION, cmd_version },
    { 0x00, 0x0}
};

int fido_process_apdu() {
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++)
    {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
