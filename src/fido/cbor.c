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

#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#endif
#include "hid/ctap_hid.h"
#include "ctap.h"
#include "fido.h"
#include "usb.h"
#include "apdu.h"

const bool _btrue = true, _bfalse = false;

int cbor_reset();
int cbor_get_info();
int cbor_make_credential(const uint8_t *data, size_t len);
int cbor_client_pin(const uint8_t *data, size_t len);
int cbor_get_assertion(const uint8_t *data, size_t len, bool next);
int cbor_get_next_assertion(const uint8_t *data, size_t len);
int cbor_selection();
int cbor_cred_mgmt(const uint8_t *data, size_t len);
int cbor_config(const uint8_t *data, size_t len);
int cbor_vendor(const uint8_t *data, size_t len);
int cbor_large_blobs(const uint8_t *data, size_t len);

const uint8_t aaguid[16] = {0x89, 0xFB, 0x94, 0xB7, 0x06, 0xC9, 0x36, 0x73, 0x9B, 0x7E, 0x30, 0x52, 0x6D, 0x96, 0x81, 0x45}; // First 16 bytes of SHA256("Pico FIDO2")

const uint8_t *cbor_data = NULL;
size_t cbor_len = 0;
uint8_t cmd = 0;

int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len) {
    if (len == 0 && cmd == CTAPHID_CBOR)
        return CTAP1_ERR_INVALID_LEN;
    if (len > 0)
        DEBUG_DATA(data+1,len-1);
    driver_prepare_response_hid();
    if (cmd == CTAPHID_CBOR) {
        if (data[0] == CTAP_MAKE_CREDENTIAL)
            return cbor_make_credential(data + 1, len - 1);
        if (data[0] == CTAP_GET_INFO)
            return cbor_get_info();
        else if (data[0] == CTAP_RESET)
            return cbor_reset();
        else if (data[0] == CTAP_CLIENT_PIN)
            return cbor_client_pin(data + 1, len - 1);
        else if (data[0] == CTAP_GET_ASSERTION)
            return cbor_get_assertion(data + 1, len - 1, false);
        else if (data[0] == CTAP_GET_NEXT_ASSERTION)
            return cbor_get_next_assertion(data + 1, len - 1);
        else if (data[0] == CTAP_SELECTION)
            return cbor_selection();
        else if (data[0] == CTAP_CREDENTIAL_MGMT || data[0] == 0x41)
            return cbor_cred_mgmt(data + 1, len - 1);
        else if (data[0] == CTAP_CONFIG)
            return cbor_config(data + 1, len - 1);
        else if (data[0] == CTAP_LARGE_BLOBS)
            return cbor_large_blobs(data + 1, len - 1);
    }
    else if (cmd == CTAP_VENDOR_CBOR) {
        return cbor_vendor(data, len);
    }
    return CTAP1_ERR_INVALID_CMD;
}

#ifndef ENABLE_EMULATION
void cbor_thread() {

    card_init_core1();
    while (1) {
        uint32_t m;
        queue_remove_blocking(&usb_to_card_q, &m);

        if (m == EV_EXIT) {

	        break;
	    }
        apdu.sw = cbor_parse(cmd, cbor_data, cbor_len);
        if (apdu.sw == 0)
            DEBUG_DATA(res_APDU + 1, res_APDU_size);

        finished_data_size = res_APDU_size+1;

        uint32_t flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
    }
}
#endif

int cbor_process(uint8_t last_cmd, const uint8_t *data, size_t len) {
    cbor_data = data;
    cbor_len = len;
    cmd = last_cmd;
    res_APDU = ctap_resp->init.data + 1;
    res_APDU_size = 0;
    return 1;
}
