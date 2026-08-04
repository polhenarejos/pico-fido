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
#include "object_authorization.h"
#include "object_provider.h"

static uint32_t fido_object_session_epoch = 1;

void fido_object_authorization_session_invalidate(void) {
    fido_object_session_epoch++;
    if (fido_object_session_epoch == 0) {
        fido_object_session_epoch = 1;
    }
}

uint32_t fido_object_authorization_session_epoch(void) {
    return fido_object_session_epoch;
}

int fido_object_authorization_context_build(const fido_object_authorization_evidence_t *evidence, bool internal_firmware, file_object_authorization_context_t *context) {
    if (!context) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint32_t facts = FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND;
    if (internal_firmware) {
        facts |= FILE_OBJECT_FACT_INTERNAL_FIRMWARE;
    }
    else if (evidence) {
        if (evidence->user_presence) {
            facts |= FILE_OBJECT_FACT_USER_PRESENCE;
        }
        if (evidence->user_verification) {
            facts |= FILE_OBJECT_FACT_USER_VERIFICATION;
        }
        if (evidence->pin_uv_auth) {
            facts |= FILE_OBJECT_FACT_APP_PIN | FILE_OBJECT_FACT_USER_VERIFICATION;
        }
    }

    context->facts = facts;
    context->session_epoch = fido_object_session_epoch;
    context->facts_epoch = fido_object_session_epoch;
    context->caller_namespace = FIDO_OBJECT_NAMESPACE;
    return PICOKEYS_OK;
}
