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
#include "u2f.h"
#include "files.h"
#include "file.h"
#include "random.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/hkdf.h"
#include "pk_wrap.h"
#include "crypto_utils.h"
#include <stdio.h>

void init_fido();
int fido_process_apdu();
int fido_unload();

const uint8_t fido_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

app_t *fido_select(app_t *a) {
    a->aid = fido_aid;
    a->process_apdu = fido_process_apdu;
    a->unload = fido_unload;
    current_app = a;
    init_fido();
    return a;
}

void __attribute__ ((constructor)) fido_ctor() {
    register_app(fido_select);
    //fido_select(&apps[0]);
}

int fido_unload() {
    return CCID_OK;
}

int x509_create_cert(mbedtls_ecdsa_context *ecdsa, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20220901000000", "20320831235959" );
    mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    mbedtls_x509write_crt_set_subject_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_fill_random(&serial, 32, random_gen, NULL);
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
    int ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_gen, NULL);
    return ret;
}

int load_keydev(uint8_t *key) {
    if (!ef_keydev || file_get_size(ef_keydev) == 0)
        return CCID_ERR_MEMORY_FATAL;
    memcpy(key, file_get_data(ef_keydev), file_get_size(ef_keydev));
    //return mkek_decrypt(key, file_get_size(ef_keydev));
    return CCID_OK;
}

int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, mbedtls_ecdsa_context *key) {
    const int entries = KEY_PATH_LEN / sizeof(uint32_t);
    uint8_t outk[64] = {0};
    int r = 0;
    memset(outk, 0, sizeof(outk));
    if ((r = load_keydev(outk)) != CCID_OK)
        return r;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    for (int i = 0; i < entries; i++)
    {
        if (new_key == true) {
            uint32_t val = 0x80000000 | *((uint32_t *)random_bytes_get(sizeof(uint32_t)));
            memcpy(&key_handle[i*sizeof(uint32_t)], &val, sizeof(uint32_t));
        }
        if ((r = mbedtls_hkdf(md_info, &key_handle[i], sizeof(uint32_t), outk, 32, outk + 32, 32, outk, sizeof(outk))) != 0)
        {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return r;
        }
    }
    if ((r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, app_id, 32, key_handle + 32)) != 0)
    {
        mbedtls_platform_zeroize(outk, sizeof(outk));
        return r;
    }
    mbedtls_ecp_group_load(&key->grp, MBEDTLS_ECP_DP_SECP256R1);
    r = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, key, outk, 32);
    mbedtls_platform_zeroize(outk, sizeof(outk));
    if (r != 0)
        return r;
    return mbedtls_ecp_mul(&key->grp, &key->Q, &key->d, &key->grp.G, random_gen, NULL );
}

int scan_files() {
    ef_keydev = search_by_fid(EF_KEY_DEV, NULL, SPECIFY_EF);
    if (ef_keydev) {
        if (!ef_keydev->data) {
            printf("KEY DEVICE is empty. Generating SECP256R1 curve...");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            uint8_t index = 0;
            int ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1, random_gen, &index);
            if (ret != 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return ret;
            }
            uint8_t kdata[32];
            int key_size = mbedtls_mpi_size(&ecdsa.d);
            mbedtls_mpi_write_binary(&ecdsa.d, kdata, key_size);
            ret = flash_write_data_to_file(ef_keydev, kdata, key_size);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (ret != CCID_OK) {
                mbedtls_ecdsa_free(&ecdsa);
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
        if (file_get_size(ef_certdev) == 0 || !ef_certdev->data) {
            uint8_t cert[4096];
            mbedtls_ecdsa_context key;
            mbedtls_ecdsa_init(&key);
            int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, file_get_data(ef_keydev), 32);
            printf("ret %d\n", ret);
            if (ret != 0)
                return ret;
            ret = x509_create_cert(&key, cert, sizeof(cert));
            mbedtls_ecdsa_free(&key);
            printf("ret %d\n", ret);
            if (ret <= 0)
                return ret;
            flash_write_data_to_file(ef_certdev, cert + sizeof(cert) - ret, ret);
            DEBUG_PAYLOAD(cert + sizeof(cert) - ret, ret);
        }
    }
    else {
        printf("FATAL ERROR: CERT DEV not found in memory!\r\n");
    }
    low_flash_available();
    return CCID_OK;
}

void scan_all() {
    scan_flash();
}

void init_fido() {
    scan_all();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

extern int cmd_register();

static const cmd_t cmds[] = {
    { U2F_REGISTER, cmd_register },
    { 0x00, 0x0}
};

int fido_process_apdu() {
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
