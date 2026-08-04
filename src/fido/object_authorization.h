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

#ifndef _OBJECT_AUTHORIZATION_H_
#define _OBJECT_AUTHORIZATION_H_

#include "object_policy.h"

typedef struct fido_object_authorization_evidence {
    bool user_presence;
    bool user_verification;
    bool pin_uv_auth;
} fido_object_authorization_evidence_t;

// Evidence must represent checks completed for the current CTAP operation, including token permission and RP binding.
int fido_object_authorization_context_build(const fido_object_authorization_evidence_t *evidence, bool internal_firmware, file_object_authorization_context_t *context);
void fido_object_authorization_session_invalidate(void);
uint32_t fido_object_authorization_session_epoch(void);

#endif // _OBJECT_AUTHORIZATION_H_
