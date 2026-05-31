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

#include "picokeys.h"
#include "fido.h"
#include "ctap2_cbor.h"
#include "ctap.h"

extern char *rp_id, *user_name, *display_name;

int cbor_selection(void) {
    rp_id = user_name = display_name = NULL;
    int ret = wait_button_pressed() ;
    if (ret == 1) {
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
    else if (ret == 2) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    return CTAP2_OK;
}
