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

#ifndef _MANAGEMENT_H_
#define _MANAGEMENT_H_

#include <stdlib.h>
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif

#define TAG_USB_SUPPORTED 0x01
#define TAG_SERIAL 0x02
#define TAG_USB_ENABLED 0x03
#define TAG_FORM_FACTOR 0x04
#define TAG_VERSION 0x05
#define TAG_AUTO_EJECT_TIMEOUT 0x06
#define TAG_CHALRESP_TIMEOUT 0x07
#define TAG_DEVICE_FLAGS 0x08
#define TAG_APP_VERSIONS 0x09
#define TAG_CONFIG_LOCK 0x0A
#define TAG_UNLOCK 0x0B
#define TAG_REBOOT 0x0C
#define TAG_NFC_SUPPORTED 0x0D
#define TAG_NFC_ENABLED 0x0E

#define CAP_OTP 0x01
#define CAP_U2F 0x02
#define CAP_FIDO2 0x200
#define CAP_OATH 0x20
#define CAP_PIV 0x10
#define CAP_OPENPGP 0x08
#define CAP_HSMAUTH 0x100

#define FLAG_REMOTE_WAKEUP 0x40
#define FLAG_EJECT 0x80

extern bool cap_supported(uint16_t cap);
extern int man_get_config();

#endif //_MANAGEMENT_H
