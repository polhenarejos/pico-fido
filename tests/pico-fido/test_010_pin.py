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
import hashlib
import pytest
from fido2.ctap import CtapError
from fido2.client import ClientPin
from fido2.ctap2.pin import ClientPin as CtapClientPin, PinProtocolV1, PinProtocolV2
from fido2.webauthn import UserVerificationRequirement
from fido2.hid import CTAPHID
from fido2.utils import hmac_sha256

from utils import *

def _pad_pin_unchecked(pin):
    # Bypass python-fido2's local PIN policy check so firmware sees this edge case.
    pin_padded = pin.encode().ljust(64, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
    return pin_padded

def _raw_set_pin(client_pin, pin):
    key_agreement, shared_secret = client_pin._get_shared_secret()
    pin_enc = client_pin.protocol.encrypt(shared_secret, _pad_pin_unchecked(pin))
    pin_uv_param = client_pin.protocol.authenticate(shared_secret, pin_enc)
    return client_pin.ctap.client_pin(
        client_pin.protocol.VERSION,
        ClientPin.CMD.SET_PIN,
        key_agreement=key_agreement,
        new_pin_enc=pin_enc,
        pin_uv_param=pin_uv_param,
    )

def _raw_change_pin(client_pin, old_pin, new_pin):
    key_agreement, shared_secret = client_pin._get_shared_secret()
    pin_hash_enc = client_pin.protocol.encrypt(
        shared_secret,
        hashlib.sha256(old_pin.encode()).digest()[:16],
    )
    new_pin_enc = client_pin.protocol.encrypt(shared_secret, _pad_pin_unchecked(new_pin))
    pin_uv_param = client_pin.protocol.authenticate(
        shared_secret,
        new_pin_enc + pin_hash_enc,
    )
    return client_pin.ctap.client_pin(
        client_pin.protocol.VERSION,
        ClientPin.CMD.CHANGE_PIN,
        key_agreement=key_agreement,
        pin_hash_enc=pin_hash_enc,
        new_pin_enc=new_pin_enc,
        pin_uv_param=pin_uv_param,
    )

def test_lockout(device):
    if getattr(device.dev.descriptor, "serial_number", None) != "AAAAAA":
        pytest.skip("PIN lockout changes persistent state; use the disposable emulator")

    pin = "TestPin"
    device.reset()
    client_pin = ClientPin(device.client()._backend.ctap2)

    try:
        client_pin.set_pin(pin)

        for i in range(1, 4):
            expected_error = CtapError.ERR.PIN_AUTH_BLOCKED if i == 3 else CtapError.ERR.PIN_INVALID

            with pytest.raises(CtapError) as e:
                client_pin.get_pin_token("WrongPin")
            assert e.value.code == expected_error
            assert client_pin.get_pin_retries()[0] == 8 - i

        for attempt_pin in ("WrongPin", pin):
            with pytest.raises(CtapError) as e:
                client_pin.get_pin_token(attempt_pin)
            assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
            assert client_pin.get_pin_retries()[0] == 5

        device.send_data(CTAPHID.INIT, os.urandom(8))

        for attempt_pin in ("WrongPin", pin):
            with pytest.raises(CtapError) as e:
                client_pin.get_pin_token(attempt_pin)
            assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
            assert client_pin.get_pin_retries()[0] == 5

        with pytest.raises(CtapError) as e:
            _raw_change_pin(client_pin, pin, "NewPin")
        assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
        assert client_pin.get_pin_retries()[0] == 5

        device.reset()
        client_pin = ClientPin(device.client()._backend.ctap2)
        client_pin.set_pin("NewPin")
        assert client_pin.get_pin_token("NewPin")
    finally:
        device.reset()

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

def test_set_pin_too_short_multibyte_codepoints(device, client_pin):
    device.reset()
    try:
        with pytest.raises(CtapError) as e:
            _raw_set_pin(client_pin, "\u20ac" * 3)
        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
    finally:
        device.reset()

def test_get_pin_token_but_no_pin_set(resetdevice, client_pin):
    with pytest.raises(CtapError) as e:
        client_pin.get_pin_token("TestPin")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

@pytest.mark.parametrize("protocol_type", [PinProtocolV1, PinProtocolV2])
def test_get_pin_token_rejects_oversized_pin_hash(device, protocol_type):
    device.reset()
    try:
        ctap = device.client()._backend.ctap2
        client_pin = CtapClientPin(ctap, protocol_type())
        client_pin.set_pin("TestPin")
        retries = client_pin.get_pin_retries()[0]
        key_agreement, shared_secret = client_pin._get_shared_secret()
        pin_hash_enc = client_pin.protocol.encrypt(shared_secret, b"\x00" * 80)

        with pytest.raises(CtapError) as error:
            client_pin.ctap.client_pin(
                client_pin.protocol.VERSION,
                CtapClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
                key_agreement=key_agreement,
                pin_hash_enc=pin_hash_enc,
            )

        assert error.value.code == CtapError.ERR.INVALID_PARAMETER
        assert client_pin.get_pin_retries()[0] == retries
    finally:
        device.reset()

def test_get_pin_retries_but_no_pin_set(resetdevice, client_pin):
    assert client_pin.get_pin_retries() == (8, None)

def test_change_pin_but_no_pin_set(device, client_pin):
    with pytest.raises(CtapError) as e:
        client_pin.change_pin("TestPin", "1234")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET

def test_setting_pin_and_get_info(device, client_pin):
    device.reset()
    client_pin.set_pin("TestPin")

    with pytest.raises(CtapError) as e:
        client_pin.set_pin("TestPin")

    assert device.client()._backend.ctap2.get_info().options["clientPin"]

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

def test_change_pin_too_short_multibyte_codepoints(device, client_pin):
    device.reset()
    client_pin.set_pin(PIN1)

    try:
        with pytest.raises(CtapError) as e:
            _raw_change_pin(client_pin, PIN1, "\u20ac" * 3)

        assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
    finally:
        device.reset()
