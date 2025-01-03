/*
 * This file is part of the Pico Fido distribution (https://github.com/polhenarejos/pico-fido).
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
#include "stdlib.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "kek.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/md.h"
#include "mbedtls/cmac.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/chachapoly.h"
#include "files.h"
#include "otp.h"

extern uint8_t session_pin[32];
uint8_t mkek_mask[MKEK_KEY_SIZE];
bool has_mkek_mask = false;

#define POLY 0xedb88320

uint32_t crc32c(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xffffffff;
    while (len--) {
        crc ^= *buf++;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (POLY & (0 - (crc & 1)));
        }
    }
    return ~crc;
}

void mkek_masked(uint8_t *mkek, const uint8_t *mask) {
    if (mask) {
        for (int i = 0; i < MKEK_KEY_SIZE; i++) {
            MKEK_KEY(mkek)[i] ^= mask[i];
        }
    }
}
#include <stdio.h>
int load_mkek(uint8_t *mkek) {
    if (paut.in_use == false) {
        return PICOKEY_NO_LOGIN;
    }
    file_t *tf = search_file(EF_MKEK);
    printf("file_size = %d\n", file_get_size(tf));
    if (file_has_data(tf)) {
        memcpy(mkek, file_get_data(tf), MKEK_SIZE);
    }

    if (has_mkek_mask) {
        mkek_masked(mkek, mkek_mask);
    }
    if (file_get_size(tf) == MKEK_SIZE) {
        int ret = aes_decrypt_cfb_256(session_pin, MKEK_IV(mkek), MKEK_KEY(mkek), MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE);
        if (ret != 0) {
            return PICOKEY_EXEC_ERROR;
        }
        if (crc32c(MKEK_KEY(mkek), MKEK_KEY_SIZE) != *(uint32_t *) MKEK_CHECKSUM(mkek)) {
            return PICOKEY_WRONG_DKEK;
        }
    }
    if (otp_key_1) {
        mkek_masked(mkek, otp_key_1);
    }
    return PICOKEY_OK;
}

void release_mkek(uint8_t *mkek) {
    mbedtls_platform_zeroize(mkek, MKEK_SIZE);
}

int store_mkek(const uint8_t *mkek) {
    uint8_t tmp_mkek[MKEK_SIZE];
    if (mkek == NULL) {
        const uint8_t *rd = random_bytes_get(MKEK_IV_SIZE + MKEK_KEY_SIZE);
        memcpy(tmp_mkek, rd, MKEK_IV_SIZE + MKEK_KEY_SIZE);
    }
    else {
        memcpy(tmp_mkek, mkek, MKEK_SIZE);
    }
    *(uint32_t *) MKEK_CHECKSUM(tmp_mkek) = crc32c(MKEK_KEY(tmp_mkek), MKEK_KEY_SIZE);
    uint8_t tmp_mkek_pin[MKEK_SIZE];
    memcpy(tmp_mkek_pin, tmp_mkek, MKEK_SIZE);
    file_t *tf = search_file(EF_MKEK);
    if (!tf) {
        release_mkek(tmp_mkek);
        release_mkek(tmp_mkek_pin);
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    aes_encrypt_cfb_256(session_pin, MKEK_IV(tmp_mkek_pin), MKEK_KEY(tmp_mkek_pin), MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE);
    file_put_data(tf, tmp_mkek_pin, MKEK_SIZE);
    release_mkek(tmp_mkek_pin);
    low_flash_available();
    release_mkek(tmp_mkek);
    return PICOKEY_OK;
}

int mkek_encrypt(uint8_t *data, uint16_t len) {
    int r;
    uint8_t mkek[MKEK_SIZE + 4];
    if ((r = load_mkek(mkek)) != PICOKEY_OK) {
        return r;
    }
    r = aes_encrypt_cfb_256(MKEK_KEY(mkek), MKEK_IV(mkek), data, len);
    release_mkek(mkek);
    return r;
}

int mkek_decrypt(uint8_t *data, uint16_t len) {
    int r;
    uint8_t mkek[MKEK_SIZE + 4];
    if ((r = load_mkek(mkek)) != PICOKEY_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(MKEK_KEY(mkek), MKEK_IV(mkek), data, len);
    release_mkek(mkek);
    return r;
}
