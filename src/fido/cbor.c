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

#include <stdlib.h>
#include "pico/stdlib.h"
#include "ctap2_cbor.h"
#include "ctap.h"
#include "ctap_hid.h"
#include "fido.h"
#include "hsm.h"

const bool _btrue = true, _bfalse = false;

const uint8_t aaguid[16] = {0x89, 0xFB, 0x94, 0xB7, 0x06, 0xC9, 0x36, 0x73, 0x9B, 0x7E, 0x30, 0x52, 0x6D, 0x96, 0x81, 0x45}; // First 16 bytes of SHA256("Pico FIDO2")

int cbor_process(const uint8_t *data, size_t len) {
    if (scan_files() != CCID_OK)
        return -CTAP1_ERR_OTHER;
    if (len == 0)
        return -CTAP1_ERR_INVALID_LEN;
    driver_prepare_response();
    if (data[0] == CTAP_MAKE_CREDENTIAL)
        return cbor_make_credential(data + 1, len - 1);
    if (data[0] == CTAP_GET_INFO)
        return cbor_get_info();
    else if (data[0] == CTAP_RESET)
        return cbor_reset();
    else if (data[0] == CTAP_CLIENT_PIN)
        return cbor_client_pin(data+1, len-1);
    return -CTAP2_ERR_INVALID_CBOR;
}
