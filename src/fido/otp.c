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
#include "files.h"
#include "random.h"
#include "version.h"
#include "asn1.h"

#define FIXED_SIZE          16
#define KEY_SIZE            16
#define UID_SIZE            6
#define KEY_SIZE_OATH       20
#define ACC_CODE_SIZE       6

#define CONFIG1_VALID       0x01
#define CONFIG2_VALID       0x02
#define CONFIG1_TOUCH       0x04
#define CONFIG2_TOUCH       0x08
#define CONFIG_LED_INV      0x10
#define CONFIG_STATUS_MASK  0x1f

static uint8_t config_seq = { 1 };

typedef struct otp_config {
    uint8_t fixed_data[FIXED_SIZE];
    uint8_t uid[UID_SIZE];
    uint8_t aes_key[KEY_SIZE];
    uint8_t acc_code[ACC_CODE_SIZE];
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
    uint8_t rfu[2];
    uint16_t crc;
} __attribute__((packed)) otp_config_t;

static const size_t otp_config_size = sizeof(otp_config_t);
uint16_t otp_status();

int otp_process_apdu();
int otp_unload();

const uint8_t otp_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

app_t *otp_select(app_t *a, const uint8_t *aid, uint8_t aid_len) {
    if (!memcmp(aid, otp_aid + 1, MIN(aid_len, otp_aid[0]))) {
        a->aid = otp_aid;
        a->process_apdu = otp_process_apdu;
        a->unload = otp_unload;
        if (file_has_data(search_dynamic_file(EF_OTP_SLOT1)) ||
            file_has_data(search_dynamic_file(EF_OTP_SLOT2))) {
            config_seq = 1;
        }
        else {
            config_seq = 0;
        }
        otp_status();
        apdu.ne = res_APDU_size;
        return a;
    }
    return NULL;
}

int otp_button_pressed(uint8_t slot) {
    printf("CB PRESSED slot %d\n", slot);
    return 0;
}

void __attribute__((constructor)) otp_ctor() {
    register_app(otp_select);
    button_pressed_cb = otp_button_pressed;
}

int otp_unload() {
    return CCID_OK;
}

uint16_t otp_status() {
    res_APDU_size = 0;
    res_APDU[1] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[2] = PICO_FIDO_VERSION_MINOR;
    res_APDU[3] = 0;
    res_APDU[4] = config_seq;
    res_APDU[5] = (CONFIG2_TOUCH | CONFIG1_TOUCH) |
                                (file_has_data(search_dynamic_file(EF_OTP_SLOT1)) ? CONFIG1_VALID :
                                 0x00) |
                                (file_has_data(search_dynamic_file(EF_OTP_SLOT2)) ? CONFIG2_VALID :
                                 0x00);
    res_APDU[6] = 0;
    return SW_OK();
}

int cmd_otp() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p2 != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (p1 == 0x01 || p1 == 0x03) { // Configure slot
        /*if (apdu.nc != otp_config_size + ACC_CODE_SIZE) {
            return SW_WRONG_LENGTH();
        }*/
        otp_config_t *odata = (otp_config_t *)apdu.data;
        if (odata->rfu[0] != 0 || odata->rfu[1] != 0) {
            return SW_WRONG_DATA();
        }
        file_t *ef = file_new(p1 == 0x01 ? EF_OTP_SLOT1 : EF_OTP_SLOT2);
        if (file_has_data(ef)) {
            otp_config_t *otpc = (otp_config_t *) file_get_data(ef);
            if (memcmp(otpc->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) != 0) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
        }
        for (int c = 0; c < otp_config_size; c++) {
            if (apdu.data[c] != 0) {
                flash_write_data_to_file(ef, apdu.data, otp_config_size);
                low_flash_available();
                config_seq++;
                return otp_status();
            }
        }
        // Delete slot
        delete_file(ef);
        if (!file_has_data(search_dynamic_file(EF_OTP_SLOT1)) &&
            !file_has_data(search_dynamic_file(EF_OTP_SLOT2))) {
            config_seq = 0;
        }
        return otp_status();
    }
    else if (p1 == 0x10) {
#ifndef ENABLE_EMULATION
        pico_get_unique_board_id_string((char *) res_APDU, 4);
#endif
        res_APDU_size = 4;
    }
    return SW_OK();
}

#define INS_OTP             0x01
#define INS_DELETE          0x02
#define INS_SET_CODE        0x03
#define INS_RESET           0x04
#define INS_LIST            0xa1
#define INS_CALCULATE       0xa2
#define INS_VALIDATE        0xa3
#define INS_CALC_ALL        0xa4
#define INS_SEND_REMAINING  0xa5

static const cmd_t cmds[] = {
    { INS_OTP, cmd_otp },
    { 0x00, 0x0 }
};

int otp_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
