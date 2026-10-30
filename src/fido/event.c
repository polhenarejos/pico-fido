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
#include "event.h"

#include <string.h>

#ifdef USB_ITF_CCID
#include "ccid/ccid.h"
#include "usb.h"
#endif

#if !defined(ENABLE_EMULATION) && defined(USB_ITF_CCID)
static bool event_append_tlv(byte_buffer_t *buffer, event_tlv_t type, const_byte_array_t value) {
    if (value.len > UINT8_MAX || (value.len > 0 && value.data == NULL) || buffer->len > buffer->capacity ||
        buffer->capacity - buffer->len < 2 || value.len > buffer->capacity - buffer->len - 2) {
        return false;
    }

    buffer->data[buffer->len++] = (uint8_t)type;
    buffer->data[buffer->len++] = (uint8_t)value.len;
    if (value.len > 0) {
        memcpy(buffer->data + buffer->len, value.data, value.len);
    }
    buffer->len += value.len;
    return true;
}

#endif

#ifdef USB_ITF_CCID
extern uint8_t enabled_usb_itf;
#endif

int event_send(event_op_t op, event_rc_t rc, const event_field_t *fields, size_t fields_len) {
#ifdef ENABLE_EMULATION
    (void)op;
    (void)rc;
    (void)fields;
    (void)fields_len;
    return PICOKEYS_ERR_FILE_NOT_FOUND;
#else
    if (fields_len > 0 && fields == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
#ifdef USB_ITF_CCID
    if (!(enabled_usb_itf & PHY_USB_ITF_WCID) || ITF_SC_WCID == ITF_INVALID) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint8_t event_data[USB_LL_BUF_SIZE] = { 0 };
    byte_buffer_t buffer = BYTE_BUFFER(event_data, sizeof(event_data));
    buffer.len = 3;
    buffer.data[0] = (uint8_t)op;
    buffer.data[1] = (uint8_t)rc;
    for (size_t i = 0; i < fields_len; i++) {
        if (!event_append_tlv(&buffer, fields[i].type, fields[i].value)) {
            return PICOKEYS_WRONG_LENGTH;
        }
    }
    buffer.data[2] = (uint8_t)buffer.len;
    return ccid_send_wcid_event(CONST_BYTE_ARRAY(buffer.data, buffer.len));
#else
    (void)op;
    (void)rc;
    (void)fields;
    (void)fields_len;
    return PICOKEYS_ERR_FILE_NOT_FOUND;
#endif
#endif
}
