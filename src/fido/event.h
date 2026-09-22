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

#ifndef _EVENT_H_
#define _EVENT_H_

#include <stdint.h>
#include <stdbool.h>
#include "byte_array.h"

typedef enum {
    OP_NONE = 0,
    OP_MC = 1,
    OP_GA = 2,
    OP_USER_PRESENCE = 3,
} event_op_t;

typedef enum {
    RC_NONE = 0,
    RC_OK = 1,
    RC_ERROR = 2,
} event_rc_t;

typedef enum {
    TLV_NONE = 0,
    TLV_RPID = 1,
    TLV_USER_NAME = 2,
    TLV_USER_DISPLAY_NAME = 3,
    TLV_ALGO = 4,
    TLV_AUTH_FLAGS = 5,
    TLV_ERROR = 6,
    TLV_CREDENTIAL_COUNT = 7,
    TLV_OPERATION = 8
} event_tlv_t;

typedef struct {
    event_tlv_t type;
    const_byte_array_t value;
} event_field_t;

int event_send(event_op_t op, event_rc_t rc, const event_field_t *fields, size_t fields_len);

#endif // _EVENT_H_
