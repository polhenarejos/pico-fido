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


import os
import pytest
from fido2.ctap import CtapError
from fido2.client import ClientPin
from fido2.webauthn import UserVerificationRequirement
from fido2.utils import hmac_sha256

from utils import *

def test_lockout(device, resetdevice, client_pin):
    pin = "TestPin"
    client_pin.set_pin(pin)

    pin_token = client_pin.get_pin_token(pin)

    for i in range(1, 10):
        err = [CtapError.ERR.PIN_INVALID]
        if 3 <= i <= 7:
            err = [CtapError.ERR.PIN_AUTH_BLOCKED]
        elif i >= 8:
            err = [CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_INVALID]

        with pytest.raises(CtapError) as e:
            client_pin.get_pin_token("WrongPin")
        assert e.value.code == err or e.value.code in err

        attempts = 8 - i
        if i > 8:
            attempts = 0

        res = client_pin.get_pin_retries()
        assert res[0] == attempts

        if err == CtapError.ERR.PIN_AUTH_BLOCKED:
            device.reboot()
            client_pin = ClientPin(resetdevice.client()._backend.ctap2)

    with pytest.raises(CtapError) as e:
        device.doMC()

    device.reboot()
    client_pin = ClientPin(resetdevice.client()._backend.ctap2)

    with pytest.raises(CtapError) as e:
        client_pin.get_pin_token(pin)
    assert e.value.code == CtapError.ERR.PIN_BLOCKED

def test_send_zero_length_pin_auth(device):
    device.reset()
    with pytest.raises(CtapError) as e:
        reg = device.MC(pin_uv_param=b"")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

    with pytest.raises(CtapError) as e:
        reg = device.GA(pin_uv_param=b"")
    assert e.value.code in (CtapError.ERR.PIN_NOT_SET, CtapError.ERR.NO_CREDENTIALS)

def test_set_pin(device, client_pin):
    device.reset()
    client_pin.set_pin("TestPin")
    device.reset()

def test_set_pin_too_big(client_pin):
    with pytest.raises(CtapError) as e:
        client_pin.set_pin("A" * 64)
    assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

def test_get_pin_token_but_no_pin_set(resetdevice, client_pin):
    with pytest.raises(CtapError) as e:
        client_pin.get_pin_token("TestPin")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

def test_change_pin_but_no_pin_set(device, client_pin):
    with pytest.raises(CtapError) as e:
        client_pin.change_pin("TestPin", "1234")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

def test_setting_pin_and_get_info(device, client_pin, info):
    device.reset()
    client_pin.set_pin("TestPin")

    with pytest.raises(CtapError) as e:
        client_pin.set_pin("TestPin")

    assert info.options["clientPin"]

    pin_token = client_pin.get_pin_token("TestPin")

    res = client_pin.get_pin_retries()
    assert res[0] == 8

    device.reset()

PIN1 = "12345678"
PIN2 = "ABCDEF"

@pytest.fixture(scope="class", params=[PIN1])
def SetPinRes(request, device, client_pin):
    device.reset()

    pin = request.param

    client_pin.set_pin(pin)

    res = device.doMC(user_verification=UserVerificationRequirement.REQUIRED)
    return res


@pytest.fixture(scope="class")
def CPRes(request, device, client_pin):
    res = client_pin.ctap.client_pin(2, ClientPin.CMD.GET_KEY_AGREEMENT)
    return res


@pytest.fixture(scope="class")
def MCPinRes(device):
    res = device.doMC(user_verification=UserVerificationRequirement.REQUIRED)
    return res


@pytest.fixture(scope="class")
def GAPinRes(device, MCPinRes):
    res = device.doGA()
    return res

def test_pin(CPRes):
    pass

def test_set_pin_twice(device, client_pin):
    """ Setting pin when a pin is already set should result in error NotAllowed. """
    with pytest.raises(CtapError) as e:
        client_pin.set_pin('1234')
        client_pin.set_pin('1234')

    assert e.value.code == CtapError.ERR.NOT_ALLOWED


def test_get_key_agreement_fields(CPRes):
    key = CPRes[1]
    assert "Is public key" and key[1] == 2
    assert "Is P256" and key[-1] == 1
    assert "Is ALG_ECDH_ES_HKDF_256" and key[3] == -25

    assert "Right key" and len(key[-3]) == 32 and isinstance(key[-3], bytes)

def test_verify_flag(device, SetPinRes):
    reg = device.doMC(user_verification=UserVerificationRequirement.REQUIRED)['res'].attestation_object
    assert reg.auth_data.flags & (1 << 2)

def test_get_no_pin_auth(device):

    reg = device.doMC()['res'].attestation_object
    allow_list = [
        {"type": "public-key", "id": reg.auth_data.credential_data.credential_id}
    ]
    auth = device.GA(allow_list=allow_list)['res']
    assert not (auth.auth_data.flags & (1 << 2))

    with pytest.raises(CtapError) as e:
        reg = device.MC()

    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

def test_zero_length_pin_auth(device):
    with pytest.raises(CtapError) as e:
        reg = device.MC(pin_uv_param=b"")
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        reg = device.GA(pin_uv_param=b"")
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

def test_make_credential_no_pin(device):
    with pytest.raises(CtapError) as e:
        reg = device.MC()
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED

def test_get_assertion_no_pin(device):
    with pytest.raises(CtapError) as e:
        reg = device.GA()
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

def test_change_pin(device, client_pin):
    device.reset()
    client_pin.set_pin(PIN1)
    client_pin.change_pin(PIN1, PIN2)

    pin_token = client_pin.get_pin_token(pin=PIN2)
    cdh = os.urandom(32)
    pin_auth = hmac_sha256(pin_token, cdh)[:32]

    reg = device.MC(pin_uv_param=pin_auth, pin_uv_protocol=2, client_data_hash=cdh)['res']

    pin_token = client_pin.get_pin_token(pin=PIN2)
    pin_auth = hmac_sha256(pin_token, cdh)[:32]
    auth = device.GA(pin_uv_param=pin_auth, pin_uv_protocol=2, client_data_hash=cdh, allow_list=[{
                    "type": "public-key",
                    "id": reg.auth_data.credential_data.credential_id,
                }])['res']

    assert reg.auth_data.flags & (1 << 2)
    assert auth.auth_data.flags & (1 << 2)

    verify(reg, auth, client_data_hash=cdh)

def test_pin_attempts(device, client_pin):
    # Flip 1 bit
    pin = PIN1
    device.reset()
    client_pin.set_pin(pin)
    pin_wrong = list(pin)
    c = pin[len(pin) // 2]

    pin_wrong[len(pin) // 2] = chr(ord(c) ^ 1)
    pin_wrong = "".join(pin_wrong)

    for i in range(1, 3):
        with pytest.raises(CtapError) as e:
            pin_token = client_pin.get_pin_token(pin=pin_wrong)
        assert e.value.code == CtapError.ERR.PIN_INVALID

        print("Check there is %d pin attempts left" % (8 - i))
        res = client_pin.get_pin_retries()
        assert res[0] == (8 - i)

    for i in range(1, 3):
        with pytest.raises(CtapError) as e:
            client_pin.get_pin_token(pin_wrong)
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

    device.reboot()
    client_pin = ClientPin(device.client()._backend.ctap2)

    pin_token = client_pin.get_pin_token(pin=pin)
    cdh = os.urandom(32)
    pin_auth = hmac_sha256(pin_token, cdh)[:32]

    reg = device.MC(pin_uv_param=pin_auth, pin_uv_protocol=2, client_data_hash=cdh)['res']

    res = client_pin.get_pin_retries()
    assert res[0] == (8)
