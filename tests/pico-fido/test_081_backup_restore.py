import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CTAPHID


PIN = "12345678"
RESTORE = 0x02
ENCRYPTED_KEY_SIZE = 12 + 32 + 16


@pytest.fixture
def emulator_device(device):
    if getattr(device.dev.descriptor, "serial_number", None) != "AAAAAA":
        pytest.skip("Backup restore changes persistent key state; use the disposable emulator")
    device.reset()
    yield device
    device.reset()


def _restore(device, encrypted_key, pin=None, pin_auth_param=None):
    params = {1: encrypted_key}
    request = {1: RESTORE, 2: params}
    if pin is not None:
        protocol, token = pin
        request[3] = protocol.VERSION
        if pin_auth_param is None:
            pin_auth_param = protocol.authenticate(
                token,
                b"\xff" * 32 + b"\x0d" + bytes([RESTORE]) + cbor.encode(params),
            )
        request[4] = pin_auth_param
    try:
        return device.dev.call(CTAPHID.VENDOR_FIRST + 1, b"\x01" + cbor.encode(request))
    except CtapError as error:
        return bytes([error.code])


def test_restore_requires_pin_auth_and_rejects_bad_lengths(emulator_device):
    device = emulator_device
    credential = device.doMC()["res"].attestation_object.auth_data.credential_data.credential_id
    client_pin = ClientPin(device.client()._backend.ctap2)
    client_pin.set_pin(PIN)
    encrypted_key = bytes(ENCRYPTED_KEY_SIZE)

    assert _restore(device, encrypted_key)[0] == CtapError.ERR.PUAT_REQUIRED

    protocol = PinProtocolV2()
    token = client_pin.get_pin_token(PIN, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    assert _restore(device, encrypted_key, (protocol, token), bytes(32))[0] == CtapError.ERR.PIN_AUTH_INVALID

    token = client_pin.get_pin_token(PIN, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL)
    assert _restore(device, encrypted_key, (protocol, token))[0] == CtapError.ERR.PIN_AUTH_INVALID

    for length in (0, ENCRYPTED_KEY_SIZE - 1, ENCRYPTED_KEY_SIZE + 1):
        assert _restore(device, bytes(length))[0] == CtapError.ERR.INVALID_PARAMETER

    device.doGA(allow_list=[{"id": credential, "type": "public-key"}])


@pytest.mark.parametrize("pin_enabled", [False, True])
def test_restore_accepts_a_backup_sized_payload(emulator_device, pin_enabled):
    device = emulator_device
    pin = None
    if pin_enabled:
        client_pin = ClientPin(device.client()._backend.ctap2)
        client_pin.set_pin(PIN)
        token = client_pin.get_pin_token(
            PIN,
            permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG,
        )
        pin = (PinProtocolV2(), token)

    response = _restore(device, bytes(ENCRYPTED_KEY_SIZE), pin)
    assert response[0] == 0
