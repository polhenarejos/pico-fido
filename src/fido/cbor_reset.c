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
#include "file.h"
#include "fido.h"
#include "ctap2_cbor.h"
#include "ctap.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#endif
#include "fs/phy.h"
#include "files.h"

int cbor_reset(void) {
#ifndef ENABLE_EMULATION
#if defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET == 1
    if (!(phy_data.opts & PHY_OPT_DISABLE_POWER_RESET) && board_millis() > 10000) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
#endif
    if (wait_button_pressed() > 0) {
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
#endif
    file_initialize_flash(true);
    init_fido();
#ifdef DEFAULT_MCUV_NOT_REQUIRED
    set_opts(get_opts() | FIDO2_OPT_MCUV_NOTRQD);
#endif
#ifdef DEFAULT_PIN_POLICY
    file_t *ef_pin_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    if (ef_pin_policy) {
        uint8_t default_pin_policy[2] = { 0 };
        file_put_data(ef_pin_policy, default_pin_policy, sizeof(default_pin_policy));
        flash_commit();
    }
#endif
    return 0;
}
