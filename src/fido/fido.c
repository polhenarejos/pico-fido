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

void init_fido() {
}

void __attribute__ ((constructor)) fido_ctor() {
    register_app(fido_select);
    fido_select(&apps[0]);
}

int fido_unload() {
    return CCID_OK;
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
