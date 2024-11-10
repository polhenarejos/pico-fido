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

#include "fido.h"
#include "pico_keys.h"
#include "apdu.h"
#include "files.h"
#include "random.h"
#include "version.h"
#include "asn1.h"
#include "hid/ctap_hid.h"
#include "usb.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "bsp/board.h"
#endif
#include "mbedtls/aes.h"
#include "management.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#endif

#define FIXED_SIZE          16
#define KEY_SIZE            16
#define UID_SIZE            6
#define KEY_SIZE_OATH       20
#define ACC_CODE_SIZE       6

#define CONFIG1_VALID       0x01
#define CONFIG2_VALID       0x02
#define CONFIG1_TOUCH       0x04
#define CONFIG2_TOUCH       0x08
#define CONFIG_LED_INV      0x10
#define CONFIG_STATUS_MASK  0x1f

/* EXT Flags */
#define SERIAL_BTN_VISIBLE  0x01    // Serial number visible at startup (button press)
#define SERIAL_USB_VISIBLE  0x02    // Serial number visible in USB iSerial field
#define SERIAL_API_VISIBLE  0x04    // Serial number visible via API call
#define USE_NUMERIC_KEYPAD  0x08    // Use numeric keypad for digits
#define FAST_TRIG           0x10    // Use fast trig if only cfg1 set
#define ALLOW_UPDATE        0x20    // Allow update of existing configuration (selected flags + access code)
#define DORMANT             0x40    // Dormant config (woken up, flag removed, requires update flag)
#define LED_INV             0x80    // LED idle state is off rather than on
#define EXTFLAG_UPDATE_MASK (SERIAL_BTN_VISIBLE | SERIAL_USB_VISIBLE | SERIAL_API_VISIBLE | \
                             USE_NUMERIC_KEYPAD | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV)

/* TKT Flags */
#define TAB_FIRST       0x01    // Send TAB before first part
#define APPEND_TAB1     0x02    // Send TAB after first part
#define APPEND_TAB2     0x04    // Send TAB after second part
#define APPEND_DELAY1   0x08    // Add 0.5s delay after first part
#define APPEND_DELAY2   0x10    // Add 0.5s delay after second part
#define APPEND_CR       0x20    // Append CR as final character
#define OATH_HOTP       0x40    // OATH HOTP mode
#define CHAL_RESP       0x40    // Challenge-response enabled (both must be set)
#define PROTECT_CFG2    0x80    // Block update of config 2 unless config 2 is configured and has this bit set
#define TKTFLAG_UPDATE_MASK (TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_DELAY2 | \
                             APPEND_CR)

/* CFG Flags */
#define SEND_REF            0x01    // Send reference string (0..F) before data
#define PACING_10MS         0x04    // Add 10ms intra-key pacing
#define PACING_20MS         0x08    // Add 20ms intra-key pacing
#define STATIC_TICKET       0x20    // Static ticket generation
// Static
#define SHORT_TICKET        0x02    // Send truncated ticket (half length)
#define STRONG_PW1          0x10    // Strong password policy flag #1 (mixed case)
#define STRONG_PW2          0x40    // Strong password policy flag #2 (subtitute 0..7 to digits)
#define MAN_UPDATE          0x80    // Allow manual (local) update of static OTP
// Challenge (no keyboard)
#define HMAC_LT64           0x04    // Set when HMAC message is less than 64 bytes
#define CHAL_BTN_TRIG       0x08    // Challenge-response operation requires button press
#define CHAL_YUBICO         0x20    // Challenge-response enabled - Yubico OTP mode
#define CHAL_HMAC           0x22    // Challenge-response enabled - HMAC-SHA1
// OATH
#define OATH_HOTP8          0x02    // Generate 8 digits HOTP rather than 6 digits
#define OATH_FIXED_MODHEX1  0x10    // First byte in fixed part sent as modhex
#define OATH_FIXED_MODHEX2  0x40    // First two bytes in fixed part sent as modhex
#define OATH_FIXED_MODHEX   0x50    // Fixed part sent as modhex
#define OATH_FIXED_MASK     0x50    // Mask to get out fixed flags
#define CFGFLAG_UPDATE_MASK (PACING_10MS | PACING_20MS)

static uint8_t config_seq = { 1 };

PACK(
typedef struct otp_config {
    uint8_t fixed_data[FIXED_SIZE];
    uint8_t uid[UID_SIZE];
    uint8_t aes_key[KEY_SIZE];
    uint8_t acc_code[ACC_CODE_SIZE];
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
    uint8_t rfu[2];
    uint16_t crc;
}) otp_config_t;

#define otp_config_size sizeof(otp_config_t)
uint16_t otp_status();

int otp_process_apdu();
int otp_unload();

#ifndef ENABLE_EMULATION
extern int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
extern uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
int otp_hid_set_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
uint16_t otp_hid_get_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
#endif

const uint8_t otp_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

int otp_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_OTP)) {
        a->process_apdu = otp_process_apdu;
        a->unload = otp_unload;
        if (file_has_data(search_dynamic_file(EF_OTP_SLOT1)) ||
            file_has_data(search_dynamic_file(EF_OTP_SLOT2))) {
            config_seq = 1;
        }
        else {
            config_seq = 0;
        }
        otp_status();
        memmove(res_APDU, res_APDU + 1, 6);
        res_APDU_size = 6;
        apdu.ne = res_APDU_size;
        return PICOKEY_OK;
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

uint8_t modhex_tab[] =
{ 'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v' };
int encode_modhex(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t l = 0; l < len; l++) {
        *out++ = modhex_tab[in[l] >> 4];
        *out++ = modhex_tab[in[l] & 0xf];
    }
    return 0;
}
static bool scanned = false;
extern void scan_all();
void init_otp() {
    if (scanned == false) {
        scan_all();
        for (uint8_t i = 0; i < 2; i++) {
            file_t *ef = search_dynamic_file(EF_OTP_SLOT1 + i);
            uint8_t *data = file_get_data(ef);
            otp_config_t *otp_config = (otp_config_t *) data;
            if (file_has_data(ef) && !(otp_config->tkt_flags & OATH_HOTP) &&
                !(otp_config->cfg_flags & SHORT_TICKET || otp_config->cfg_flags & STATIC_TICKET)) {
                uint16_t counter = (data[otp_config_size] << 8) | data[otp_config_size + 1];
                if (++counter <= 0x7fff) {
                    uint8_t new_data[otp_config_size + 8];
                    memcpy(new_data, data, sizeof(new_data));
                    new_data[otp_config_size] = counter >> 8;
                    new_data[otp_config_size + 1] = counter & 0xff;
                    file_put_data(ef, new_data, sizeof(new_data));
                }
            }
        }
        scanned = true;
        low_flash_available();
    }
}
extern int calculate_oath(uint8_t truncate,
                          const uint8_t *key,
                          size_t key_len,
                          const uint8_t *chal,
                          size_t chal_len);

uint16_t calculate_crc(const uint8_t *data, size_t data_len) {
    uint16_t crc = 0xFFFF;
    for (size_t idx = 0; idx < data_len; idx++) {
        crc ^= data[idx];
        for (uint8_t i = 0; i < 8; i++) {
            uint16_t j = crc & 0x1;
            crc >>= 1;
            if (j == 1) {
                crc ^= 0x8408;
            }
        }
    }
    return crc & 0xFFFF;
}

#ifndef ENABLE_EMULATION
static uint8_t session_counter[2] = { 0 };
#endif
int otp_button_pressed(uint8_t slot) {
    init_otp();
    if (!cap_supported(CAP_OTP)) {
        return 3;
    }
#ifndef ENABLE_EMULATION
    file_t *ef = search_dynamic_file(slot == 1 ? EF_OTP_SLOT1 : EF_OTP_SLOT2);
    const uint8_t *data = file_get_data(ef);
    otp_config_t *otp_config = (otp_config_t *) data;
    if (file_has_data(ef) == false) {
        return 1;
    }
    if (otp_config->cfg_flags & CHAL_YUBICO && otp_config->tkt_flags & CHAL_RESP) {
        return 2;
    }
    if (otp_config->tkt_flags & OATH_HOTP) {
        uint8_t tmp_key[KEY_SIZE + 2];
        tmp_key[0] = 0x01;
        memcpy(tmp_key + 2, otp_config->aes_key, KEY_SIZE);
        uint64_t imf = 0;
        const uint8_t *p = data + otp_config_size;
        imf |= (uint64_t) *p++ << 56;
        imf |= (uint64_t) *p++ << 48;
        imf |= (uint64_t) *p++ << 40;
        imf |= (uint64_t) *p++ << 32;
        imf |= *p++ << 24;
        imf |= *p++ << 16;
        imf |= *p++ << 8;
        imf |= *p++;
        if (imf == 0) {
            imf = ((otp_config->uid[4] << 8) | otp_config->uid[5]) << 4;
        }
        uint8_t chal[8] =
        { imf >> 56, imf >> 48, imf >> 40, imf >> 32, imf >> 24, imf >> 16, imf >> 8, imf & 0xff };
        res_APDU_size = 0;
        int ret = calculate_oath(1, tmp_key, sizeof(tmp_key), chal, sizeof(chal));
        if (ret == PICOKEY_OK) {
            uint32_t base = otp_config->cfg_flags & OATH_HOTP8 ? 1e8 : 1e6;
            uint32_t number =
                (res_APDU[2] << 24) | (res_APDU[3] << 16) | (res_APDU[4] << 8) | res_APDU[5];
            number %= base;
            char number_str[9];
            if (otp_config->cfg_flags & OATH_HOTP8) {
                sprintf(number_str, "%08lu", (long unsigned int) number);
                add_keyboard_buffer((const uint8_t *) number_str, 8, true);
            }
            else {
                sprintf(number_str, "%06lu", (long unsigned int) number);
                add_keyboard_buffer((const uint8_t *) number_str, 6, true);
            }
            imf++;
            uint8_t new_chal[8] =
            { imf >> 56, imf >> 48, imf >> 40, imf >> 32, imf >> 24, imf >> 16, imf >> 8,
              imf & 0xff };
            uint8_t new_otp_config[otp_config_size + sizeof(new_chal)];
            memcpy(new_otp_config, otp_config, otp_config_size);
            memcpy(new_otp_config + otp_config_size, new_chal, sizeof(new_chal));
            file_put_data(ef, new_otp_config, sizeof(new_otp_config));
            low_flash_available();
        }
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer((const uint8_t *) "\r", 1);
        }
    }
    else if (otp_config->cfg_flags & SHORT_TICKET || otp_config->cfg_flags & STATIC_TICKET) {
        uint8_t fixed_size = FIXED_SIZE + UID_SIZE + KEY_SIZE;
        if (otp_config->cfg_flags & SHORT_TICKET) { // Not clear which is the purpose of SHORT_TICKET
            //fixed_size /= 2;
        }
        add_keyboard_buffer(otp_config->fixed_data, fixed_size, false);
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer((const uint8_t *) "\x28", 1);
        }
    }
    else {
        uint8_t otpk[22], *po = otpk;
        bool update_counter = false;
        uint16_t counter = (data[otp_config_size] << 8) | data[otp_config_size + 1], crc = 0;
        uint32_t ts = board_millis() / 1000;
        if (counter == 0) {
            update_counter = true;
            counter = 1;
        }
        memcpy(po, otp_config->fixed_data, 6);
        po += 6;
        memcpy(po, otp_config->uid, UID_SIZE);
        po += UID_SIZE;
        *po++ = counter & 0xff;
        *po++ = counter >> 8;
        ts >>= 3;
        *po++ = ts & 0xff;
        *po++ = ts >> 8;
        *po++ = ts >> 16;
        *po++ = session_counter[slot - 1];
        random_gen(NULL, po, 2);
        po += 2;
        crc = calculate_crc(otpk + 6, 14);
        *po++ = ~crc & 0xff;
        *po++ = ~crc >> 8;
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, otpk + 6, otpk + 6);
        mbedtls_aes_free(&ctx);
        uint8_t otp_out[44];
        encode_modhex(otpk, sizeof(otpk), otp_out);
        add_keyboard_buffer((const uint8_t *) otp_out, sizeof(otp_out), true);
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer((const uint8_t *) "\r", 1);
        }

        if (++session_counter[slot - 1] == 0) {
            if (++counter <= 0x7fff) {
                update_counter = true;
            }
        }
        if (update_counter == true) {
            uint8_t new_data[otp_config_size + 8];
            memcpy(new_data, data, sizeof(new_data));
            new_data[otp_config_size] = counter >> 8;
            new_data[otp_config_size + 1] = counter & 0xff;
            file_put_data(ef, new_data, sizeof(new_data));
            low_flash_available();
        }
    }
#else
    (void) slot;
#endif
    return 0;
}

INITIALIZER( otp_ctor ) {
    register_app(otp_select, otp_aid);
    button_pressed_cb = otp_button_pressed;
#ifndef ENABLE_EMULATION
    hid_set_report_cb = otp_hid_set_report_cb;
    hid_get_report_cb = otp_hid_get_report_cb;
#endif
}

int otp_unload() {
    return PICOKEY_OK;
}

uint16_t otp_status() {
    if (scanned == false) {
        scan_all();
        scanned = true;
    }
    res_APDU_size = 0;
    res_APDU[1] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[2] = PICO_FIDO_VERSION_MINOR;
    res_APDU[3] = 0;
    res_APDU[4] = config_seq;
    res_APDU[5] = (CONFIG2_TOUCH | CONFIG1_TOUCH) |
                  (file_has_data(search_dynamic_file(EF_OTP_SLOT1)) ? CONFIG1_VALID :
                   0x00) |
                  (file_has_data(search_dynamic_file(EF_OTP_SLOT2)) ? CONFIG2_VALID :
                   0x00);
    res_APDU[6] = 0;
    return SW_OK();
}

bool check_crc(const otp_config_t *data) {
    uint16_t crc = calculate_crc((const uint8_t *) data, otp_config_size);
    return crc == 0xF0B8;
}

int cmd_otp() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p2 != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (p1 == 0x01 || p1 == 0x03) { // Configure slot
        otp_config_t *odata = (otp_config_t *) apdu.data;
        file_t *ef = file_new(p1 == 0x01 ? EF_OTP_SLOT1 : EF_OTP_SLOT2);
        if (file_has_data(ef)) {
            otp_config_t *otpc = (otp_config_t *) file_get_data(ef);
            if (memcmp(otpc->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) != 0) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
        }
        for (int c = 0; c < otp_config_size; c++) {
            if (apdu.data[c] != 0) {
                if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
                    return SW_WRONG_DATA();
                }
                memset(apdu.data + otp_config_size, 0, 8); // Add 8 bytes extra
                file_put_data(ef, apdu.data, otp_config_size + 8);
                low_flash_available();
                config_seq++;
                return otp_status();
            }
        }
        // Delete slot
        delete_file(ef);
        if (!file_has_data(search_dynamic_file(EF_OTP_SLOT1)) &&
            !file_has_data(search_dynamic_file(EF_OTP_SLOT2))) {
            config_seq = 0;
        }
        return otp_status();
    }
    else if (p1 == 0x04 || p1 == 0x05) {
        otp_config_t *odata = (otp_config_t *) apdu.data;
        if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
            return SW_WRONG_DATA();
        }
        file_t *ef = search_dynamic_file(p1 == 0x04 ? EF_OTP_SLOT1 : EF_OTP_SLOT2);
        if (file_has_data(ef)) {
            otp_config_t *otpc = (otp_config_t *) file_get_data(ef);
            if (memcmp(otpc->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) != 0) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            memcpy(apdu.data, file_get_data(ef), FIXED_SIZE + UID_SIZE + KEY_SIZE);
            odata->fixed_size = otpc->fixed_size;
            odata->ext_flags = (otpc->ext_flags & ~EXTFLAG_UPDATE_MASK) |
                               (odata->ext_flags & EXTFLAG_UPDATE_MASK);
            odata->tkt_flags = (otpc->tkt_flags & ~TKTFLAG_UPDATE_MASK) |
                               (odata->tkt_flags & TKTFLAG_UPDATE_MASK);
            odata->cfg_flags = (otpc->cfg_flags & ~CFGFLAG_UPDATE_MASK) |
                               (odata->cfg_flags & CFGFLAG_UPDATE_MASK);
            file_put_data(ef, apdu.data, otp_config_size);
            low_flash_available();
        }
    }
    else if (p1 == 0x06) {
        uint8_t tmp[otp_config_size + 8];
        bool ef1_data = false;
        file_t *ef1 = file_new(EF_OTP_SLOT1);
        file_t *ef2 = file_new(EF_OTP_SLOT2);
        if (file_has_data(ef1)) {
            memcpy(tmp, file_get_data(ef1), file_get_size(ef1));
            ef1_data = true;
        }
        if (file_has_data(ef2)) {
            file_put_data(ef1, file_get_data(ef2), file_get_size(ef2));
        }
        else {
            delete_file(ef1);
        }
        if (ef1_data) {
            file_put_data(ef2, tmp, sizeof(tmp));
        }
        else {
            delete_file(ef2);
        }
        low_flash_available();
    }
    else if (p1 == 0x10) {
        memcpy(res_APDU, pico_serial.id, 4);
        res_APDU_size = 4;
    }
    else if (p1 == 0x13) {
        man_get_config();
    }
    else if (p1 == 0x30 || p1 == 0x38 || p1 == 0x20 || p1 == 0x28) {
        file_t *ef = search_dynamic_file(p1 == 0x30 || p1 == 0x20 ? EF_OTP_SLOT1 : EF_OTP_SLOT2);
        if (file_has_data(ef)) {
            otp_config_t *otp_config = (otp_config_t *) file_get_data(ef);
            if (!(otp_config->cfg_flags & CHAL_YUBICO && otp_config->tkt_flags & CHAL_RESP)) {
                return SW_WRONG_DATA();
            }
            int ret = 0;
            if (p1 == 0x30 || p1 == 0x38) {
                mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                                otp_config->aes_key,
                                KEY_SIZE,
                                apdu.data,
                                8,
                                res_APDU);
                if (ret == 0) {
                    res_APDU_size = 20;
                }
            }
            else if (p1 == 0x20 || p1 == 0x28) {
                uint8_t challenge[16];
                memcpy(challenge, apdu.data, 6);
                memcpy(challenge + 6, pico_serial_str, 10);
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
                ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge, res_APDU);
                mbedtls_aes_free(&ctx);
                if (ret == 0) {
                    res_APDU_size = 16;
                }
            }
        }
    }
    return SW_OK();
}

#define INS_OTP             0x01

static const cmd_t cmds[] = {
    { INS_OTP, cmd_otp },
    { 0x00, 0x0 }
};

int otp_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_OTP)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

#ifndef ENABLE_EMULATION

uint8_t otp_frame_rx[70] = {0};
uint8_t otp_frame_tx[70] = {0};
uint8_t otp_exp_seq = 0, otp_curr_seq = 0;
uint8_t otp_header[4] = {0};

extern uint16_t *get_send_buffer_size(uint8_t itf);

int otp_send_frame(uint8_t *frame, size_t frame_len) {
    uint16_t crc = calculate_crc(frame, frame_len);
    frame[frame_len] = ~crc & 0xff;
    frame[frame_len + 1] = ~crc >> 8;
    frame_len += 2;
    *get_send_buffer_size(ITF_KEYBOARD) = frame_len;
    otp_exp_seq = (frame_len / 7);
    if (frame_len % 7) {
        otp_exp_seq++;
    }
    otp_curr_seq = 0;
    return 0;
}

int otp_hid_set_report_cb(uint8_t itf,
                           uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer,
                           uint16_t bufsize)
{
    if (itf == ITF_KEYBOARD) {
        if (report_type == 3) {
            DEBUG_PAYLOAD(buffer, bufsize);
            if (buffer[7] == 0xFF) { // reset
                *get_send_buffer_size(ITF_KEYBOARD) = 0;
                otp_curr_seq = otp_exp_seq = 0;
                memset(otp_frame_tx, 0, sizeof(otp_frame_tx));
            }
            else if (buffer[7] & 0x80) { // a frame
                uint8_t rseq = buffer[7] & 0x1F;
                if (rseq < 10) {
                    if (rseq == 0) {
                        memset(otp_frame_rx, 0, sizeof(otp_frame_rx));
                    }
                    memcpy(otp_frame_rx + rseq * 7, buffer, 7);
                    if (rseq == 9) {
                        DEBUG_DATA(otp_frame_rx, sizeof(otp_frame_rx));
                        uint16_t residual_crc = calculate_crc(otp_frame_rx, 64), rcrc = (otp_frame_rx[66] << 8 | otp_frame_rx[65]);
                        uint8_t slot_id = otp_frame_rx[64];
                        if (residual_crc == rcrc) {
                            uint8_t hdr[5];
                            apdu.header = hdr;
                            apdu.data = otp_frame_rx;
                            apdu.nc = 64;
                            apdu.rdata = otp_frame_tx;
                            apdu.header[0] = 0;
                            apdu.header[1] = 0x01;
                            apdu.header[2] = slot_id;
                            apdu.header[3] = 0;
                            int ret = otp_process_apdu();
                            if (ret == 0x9000 && res_APDU_size > 0) {
                                otp_send_frame(apdu.rdata, apdu.rlen);
                            }
                        }
                        else {
                            printf("[OTP] Bad CRC!\n");
                        }
                    }
                }
            }
        }
        return 1;
    }
    return 0;
}

uint16_t otp_hid_get_report_cb(uint8_t itf,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer,
                               uint16_t reqlen) {
    // TODO not Implemented
    (void) itf;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;
    uint16_t send_buffer_size = *get_send_buffer_size(ITF_KEYBOARD);
    if (send_buffer_size > 0) {
        uint8_t seq = otp_curr_seq++;
        memset(buffer, 0, 8);
        memcpy(buffer, otp_frame_tx + 7 * seq, MIN(7, send_buffer_size));
        buffer[7] = 0x40 | seq;
        DEBUG_DATA(buffer, 8);
        *get_send_buffer_size(ITF_KEYBOARD) -= MIN(7, send_buffer_size);
    }
    else if (otp_curr_seq == otp_exp_seq && otp_exp_seq > 0) {
        memset(buffer, 0, 7);
        buffer[7] = 0x40;
        DEBUG_DATA(buffer,8);
        otp_curr_seq = otp_exp_seq = 0;
    }
    else {
        res_APDU = buffer;
        otp_status();
    }

    return reqlen;
}

#endif
