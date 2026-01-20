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

#ifndef _FILES_H_
#define _FILES_H_

#include "file.h"

#define EF_KEY_DEV      0xCC00
#define EF_KEY_DEV_ENC  0xCC01
#define EF_MKEK         0xCC0F
#define EF_EE_DEV       0xCE00
#define EF_EE_DEV_EA    0xCE01
#define EF_COUNTER      0xC000
#define EF_OPTS         0xC001
#define EF_PIN          0x1080
#define EF_AUTHTOKEN    0x1090
#define EF_PAUTHTOKEN   0x1091
#define EF_MINPINLEN    0x1100
#define EF_PIN_COMPLEXITY_POLICY 0x1102
#define EF_DEV_CONF     0x1122
#define EF_CRED         0xCF00 // Creds at 0xCF00 - 0xCFFF
#define EF_RP           0xD000 // RPs at 0xD000 - 0xD0FF
#define EF_LARGEBLOB    0x1101 // Large Blob Array
#define EF_OATH_CRED    0xBA00 // OATH Creds at 0xBA00 - 0xBAFE
#define EF_OATH_CODE    0xBAFF
#define EF_OTP_SLOT1    0xBB00
#define EF_OTP_SLOT2    0xBB01
#define EF_OTP_SLOT3    0xBB02
#define EF_OTP_SLOT4    0xBB03
#define EF_OTP_PIN      0x10A0 // Nitrokey OTP PIN

extern file_t *ef_keydev;
extern file_t *ef_certdev;
extern file_t *ef_counter;
extern file_t *ef_pin;
extern file_t *ef_authtoken;
extern file_t *ef_keydev_enc;
extern file_t *ef_largeblob;
extern file_t *ef_mkek;

#endif //_FILES_H_
