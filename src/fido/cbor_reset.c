
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

#include "file.h"
#include "fido.h"
#include "ctap.h"
#include "bsp/board.h"

extern void scan_all();

int cbor_reset() {
#if defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET==1
    if (board_millis() > 10000)
        return CTAP2_ERR_NOT_ALLOWED;
#endif
    if (wait_button_pressed() == true)
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    initialize_flash(true);
    init_fido();
    return 0;
}
