"""
/*
 * This file is part of the Pico Fido distribution (https://github.com/polhenarejos/pico-fido).
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
"""

import pytest
from utils import *

INS_PUT = 0x01
INS_DELETE = 0x02
INS_SET_CODE = 0x03
INS_RESET = 0x04
INS_LIST = 0xa1
INS_CALCULATE = 0xa2
INS_VALIDATE = 0xa3
INS_CALC_ALL = 0xa4
INS_SEND_REMAINING = 0xa5

RESP_MORE_DATA = 0x61

TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_T_RESPONSE = 0x76
TAG_NO_RESPONSE = 0x77
TAG_PROPERTY = 0x78
TAG_VERSION = 0x79
TAG_IMF = 0x7a
TAG_ALGO = 0x7b
TAG_TOUCH_RESPONSE = 0x7c

TYPE_MASK = 0xf0
TYPE_HOTP = 0x10
TYPE_TOTP = 0x20

ALG_MASK = 0x0f
ALG_SHA1 = 0x01
ALG_SHA256 = 0x02

PROP_ALWAYS_INC = 0x01
PROP_REQUIRE_TOUCH = 0x02

## Based on tests on https://github.com/Yubico/ykneo-oath/blob/master/test/test/pkgYkneoOathTest/YkneoOathTest.java

def test_select_oath(select_oath):
    pass

def list_apdu(ccid_card):
    resp = send_apdu(ccid_card, INS_LIST, p1=0, p2=0)
    return resp

name_kaka = [ord('k'), ord('a'), ord('k'), ord('a')]
data_name = [TAG_NAME] + [len(name_kaka)] + name_kaka
data_key = [TAG_KEY, 0x16, 0x21, 0x06, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b]
data_chal = [TAG_CHALLENGE, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]

def test_life(reset_oath):
    data = data_name + data_key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=list(data))
    assert(len(resp) == 0)
    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, 5, 0x21] + name_kaka
    assert(resp == exp)

    data = data_name + data_chal
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=0, data=data)
    exp = [TAG_RESPONSE, 0x15, 0x06, 0xb3, 0x99, 0xbd, 0xfc, 0x9d, 0x05, 0xd1, 0x2a, 0xc4, 0x35, 0xc4, 0xc8, 0xd6, 0xcb, 0xd2, 0x47, 0xc4, 0x0a, 0x30, 0xf1]
    assert(resp == exp)

    data = data_name
    resp = send_apdu(reset_oath, INS_DELETE, p1=0, p2=0, data=data)
    resp = list_apdu(reset_oath)
    assert(len(resp) == 0)

