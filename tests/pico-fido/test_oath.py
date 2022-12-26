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
import hmac, hashlib

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

def test_overwrite(reset_oath):
    data = data_name + data_key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=list(data))
    assert(len(resp) == 0)
    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, 5, 0x21] + name_kaka
    assert(resp == exp)

    data = data_name + [TAG_CHALLENGE, 0x8] + list(bytes(b'\xff'*8))
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=0, data=data)
    exp = [TAG_RESPONSE, 0x15, 0x06, 0x79, 0x3e, 0x1b, 0xbd, 0xbf, 0xa7, 0x75, 0xa8, 0x63,0xcc, 0x80, 0x02, 0xce, 0xe4, 0xbd, 0x6c, 0xd7, 0xce, 0xb8, 0xcd]
    assert(resp == exp)

    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, 5, 0x21] + name_kaka
    assert(resp == exp)

    data = data_name + [TAG_CHALLENGE, 0x8] + list(bytes(b'\xff\x00'*4))
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=0, data=data)
    exp = [TAG_RESPONSE, 0x15, 0x06, 0x3b, 0x0e, 0x3c, 0x63, 0x1c, 0x01, 0x67, 0xb0, 0x93, 0xa5, 0xec, 0xb9, 0x09, 0x7d, 0x0b, 0x8e, 0x9a, 0xcc, 0x2f, 0x7f]
    assert(resp == exp)

def test_auth(reset_oath):
    key = list(bytes(b'kaka blahonga'))
    chal = [1,2,3,4,5,6,7,8]
    resp = [0x0c, 0x42, 0x8e, 0x9c, 0xba, 0xa3, 0xb3, 0xab, 0x18, 0x53, 0xd8, 0x79, 0xb9, 0xd2, 0x26, 0xf7, 0xce, 0xcc, 0x4a, 0x7a]
    data = [TAG_KEY, len(key)+1, ALG_SHA1 | TYPE_TOTP] + key + [TAG_CHALLENGE, len(chal)] + chal + [TAG_RESPONSE, len(resp)] + resp
    resp = send_apdu(reset_oath, INS_SET_CODE, p1=0, p2=0, data=data)

    reset_oath.connection.reconnect()
    aid = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01]
    resp = send_apdu(reset_oath, 0xA4, 0x04, 0x00, aid)
    assert(resp[15] == TAG_CHALLENGE)
    assert(resp[16] == 8)
    resp2 = hmac.digest(bytes(key), bytes(resp[17:17+8]), 'sha1')
    data = [TAG_RESPONSE, len(resp2)] + list(resp2) + [TAG_CHALLENGE, len(chal)] + chal
    resp = send_apdu(reset_oath, INS_VALIDATE, p1=0, p2=0, data=data)
    assert(resp[0] == TAG_RESPONSE)
    assert(resp[1] == 20)
    assert(resp[2:] == list(hmac.digest(bytes(key), bytes(chal), 'sha1')))

def test_bothoath(reset_oath):
    digits = 6
    tname = list(bytes(b'totp'))
    data = [TAG_NAME, len(tname)] + tname + [TAG_KEY, 9, TYPE_TOTP | ALG_SHA1, digits] + list(bytes(b'foo bar'))
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    data[2] = ord('h')
    data[8] = TYPE_HOTP | ALG_SHA1
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)

    hname = tname[:]
    hname[0] = ord('h')
    data = [TAG_CHALLENGE, 8, 0, 0, 0, 0, 0x02, 0xbc, 0xad, 0xc8]
    resp = send_apdu(reset_oath, INS_CALC_ALL, p1=0, p2=1, data=data)
    exp = [TAG_NAME, len(tname)] + tname + [TAG_T_RESPONSE, 5, digits, 0x3d, 0xc6, 0xbf, 0x3d] + [TAG_NAME, len(hname)] + hname + [TAG_NO_RESPONSE, 0x01, digits]
    assert(exp == resp)

    data = [TAG_NAME, len(hname)] + hname + [TAG_CHALLENGE]
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, digits, 0x17, 0xfa, 0x2d, 0x40]
    assert(resp == exp)

def test_imf_overwrite(reset_oath):
    key = list(bytes(b'kaka'))
    imf = [0xff, 0x00, 0xff, 0xff]
    name = list(bytes(b'kaka'))

    data = [TAG_NAME, len(name)] + name + [TAG_KEY, len(key)+2, ALG_SHA1 | TYPE_HOTP, 6] + key + [TAG_IMF, len(imf)] + imf
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    data = [TAG_NAME, len(name)] + name + [TAG_CHALLENGE]
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, 6, 0x45, 0xd9, 0x0f, 0x25]
    assert(exp == resp)
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, 6, 0x1b, 0xc5, 0x4a, 0x85]
    assert(exp == resp)

    data = [TAG_NAME, len(name)] + name + [TAG_KEY, len(key)+2, ALG_SHA1 | TYPE_HOTP, 6] + key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    data = [TAG_NAME, len(name)] + name + [TAG_CHALLENGE]
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, 6, 0x16, 0x53, 0x24, 0xdb]
    assert(exp == resp)
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, 6, 0x53, 0xed, 0x5e, 0xb2]
    assert(exp == resp)

def test_imf_more(reset_oath):
    key = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
				0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30]
    imf = [0, 0, 0, 1]
    name = list(bytes(b'kaka'))

    data = [TAG_NAME, len(name)] + name + [TAG_KEY, len(key)+2, ALG_SHA1 | TYPE_HOTP, 6] + key + [TAG_IMF, len(imf)] + imf
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    data = [TAG_NAME, len(name)] + name + [TAG_CHALLENGE]
    resp = send_apdu(reset_oath, INS_CALCULATE, p1=0, p2=1, data=data)
    exp = [TAG_T_RESPONSE, 5, 6, 0x41, 0x39, 0x7e, 0xea]
    assert(exp == resp)

def test_delete(reset_oath):
    key = list(bytes(b'blahonga!'))
    firstname = list(bytes(b'one'))
    secondname = list(bytes(b'two'))
    thirdname = list(bytes(b'three'))
    type = ALG_SHA1 | TYPE_TOTP

    data = [TAG_NAME, len(firstname)] + firstname + [TAG_KEY, len(key)+2, type, 6] + key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    data = [TAG_NAME, len(secondname)] + secondname + [TAG_KEY, len(key)+2, type, 6] + key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, len(firstname)+1, type] + firstname + [TAG_NAME_LIST, len(secondname)+1, type] + secondname
    assert(exp == resp)

    data = [TAG_NAME, len(firstname)] + firstname
    resp = send_apdu(reset_oath, INS_DELETE, p1=0, p2=0, data=data)
    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, len(secondname)+1, type] + secondname
    assert(exp == resp)

    data = [TAG_NAME, len(thirdname)] + thirdname + [TAG_KEY, len(key)+2, type, 6] + key
    resp = send_apdu(reset_oath, INS_PUT, p1=0, p2=0, data=data)
    resp = list_apdu(reset_oath)
    exp = [TAG_NAME_LIST, len(thirdname)+1, type] + thirdname + [TAG_NAME_LIST, len(secondname)+1, type] + secondname
    assert(exp == resp)
