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
#include "compat/esp_compat.h"
#endif
#include "fs/phy.h"
#include "files.h"

static bool fido_reset_should_clear(uint16_t fid) {
    uint8_t prefix = (uint8_t)(fid >> 8);

    switch (fid) {
        case EF_KEY_DEV:
        case EF_KEY_DEV_ENC:
        case EF_EE_DEV:
        case EF_EE_DEV_EA:
        case EF_VAULT_KEY:
        case EF_VAULT_LABEL:
        case EF_COUNTER:
        case EF_PIN:
        case EF_AUTHTOKEN:
        case EF_PAUTHTOKEN:
        case EF_MINPINLEN:
        case EF_PIN_COMPLEXITY_POLICY:
        case EF_DEV_STATE:
        case EF_OPTS:
        case EF_LARGEBLOB:
        case EF_PIN_ADMIN:
            return true;
        default:
            break;
    }

    // FIDO vault, credential, and resident-object records use these dynamic FID prefixes.
    return (prefix >= 0xc4 && prefix <= 0xc9) || prefix == 0xcf || (prefix >= 0xd0 && prefix <= 0xdc) || (prefix >= 0xe0 && prefix <= 0xe3);
}

typedef struct fido_reset_context {
    int ret;
} fido_reset_context_t;

static bool fido_reset_dynamic_file(file_t *file, void *ctx) {
    fido_reset_context_t *context = (fido_reset_context_t *)ctx;

    if (!fido_reset_should_clear(file->fid)) {
        return true;
    }
    context->ret = file_delete_no_commit(file);
    return context->ret == PICOKEYS_OK;
}

static int fido_reset_storage(void) {
    for (file_entry_t *entry = file_entries; entry != file_last; entry++) {
        if (fido_reset_should_clear(entry->file.fid) && flash_clear_file(&entry->file) != PICOKEYS_OK) {
            return PICOKEYS_EXEC_ERROR;
        }
    }

    fido_reset_context_t context = { .ret = PICOKEYS_OK };
    file_for_each_dynamic(fido_reset_dynamic_file, &context);
    if (context.ret != PICOKEYS_OK) {
        return context.ret;
    }

    flash_commit();
    return PICOKEYS_OK;
}

int cbor_reset(void) {
#ifndef ENABLE_EMULATION
#if defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET == 1
    if (!(phy_data.opts & PHY_OPT_DISABLE_POWER_RESET) && board_millis() > 10000) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
#endif
    int ret = wait_button_pressed();
    if (ret == 1) {
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
    else if (ret == 2) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
#endif
    if (fido_reset_storage() != PICOKEYS_OK) {
        return CTAP2_ERR_PROCESSING;
    }
    init_fido();
#ifdef DEFAULT_MCUV_NOT_REQUIRED
    set_opts(get_opts() | FIDO2_OPT_MCUV_NOTRQD);
#endif
#ifdef DEFAULT_PIN_POLICY
    file_t *ef_pin_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    if (ef_pin_policy) {
        uint8_t default_pin_policy[2] = { 0 };
        file_put_data(ef_pin_policy, CONST_BYTE_ARRAY(default_pin_policy, sizeof(default_pin_policy)));
        flash_commit();
    }
#endif
    return 0;
}
