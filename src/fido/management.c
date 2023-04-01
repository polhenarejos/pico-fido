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
#include "version.h"

int man_process_apdu();
int man_unload();

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};

app_t *man_select(app_t *a, const uint8_t *aid, uint8_t aid_len) {
    if (!memcmp(aid, man_aid + 1, MIN(aid_len, man_aid[0]))) {
        a->aid = man_aid;
        a->process_apdu = man_process_apdu;
        a->unload = man_unload;
        sprintf((char *)res_APDU, "%d.%d.0", PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
        res_APDU_size = strlen((char *)res_APDU);
        apdu.ne = res_APDU_size;
        return a;
    }
    return NULL;
}

void __attribute__((constructor)) man_ctor() {
    register_app(man_select);
}

int man_unload() {
    return CCID_OK;
}

int man_get_config() {
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0; // Overall length. Filled later
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = 0x02;
    res_APDU[res_APDU_size++] = 0x01 | 0x02 | 0x20;
    res_APDU[res_APDU_size++] = 0x02;
    res_APDU[res_APDU_size++] = 4;
#ifndef ENABLE_EMULATION
    pico_get_unique_board_id_string((char *) res_APDU + res_APDU_size, 4);
#endif
    res_APDU_size += 4;
    res_APDU[res_APDU_size++] = 0x03;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = 0x02;
    res_APDU[res_APDU_size++] = 0x01 | 0x02 | 0x20;
    res_APDU[res_APDU_size++] = 0x04;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = 0x05;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;
    res_APDU[res_APDU_size++] = 0x08;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x80;
    res_APDU[res_APDU_size++] = 0x0A;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[res_APDU_size++] = 0x0D;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[res_APDU_size++] = 0x0E;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[0] = res_APDU_size - 1;
    return 0;
}

int cmd_read_config() {
    man_get_config();
    return SW_OK();
}

#define INS_READ_CONFIG             0x1D

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { 0x00, 0x0 }
};

int man_process_apdu() {
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
