"""Credential metadata vendor configuration tests."""

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import Config
from fido2.ctap2.pin import ClientPin, PinProtocolV2


PIN = "12345678"
CONFIG_CREDENTIAL_EXPIRE = 0x0004E532E1FEB2FD
CONFIG_CREDENTIAL_REVOKE = 0x0005961ECBA040F9


def _vendor_config(device, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG):
    ctap = device.client()._backend.ctap2
    token = ClientPin(ctap).get_pin_token(
        PIN,
        permissions=permissions,
    )
    return Config(ctap, PinProtocolV2(), token)


def _set_pin_and_reset(device):
    device.reset()
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)


def test_get_info_advertises_credential_metadata_commands(info):
    commands = info[0x15]
    assert CONFIG_CREDENTIAL_EXPIRE in commands
    assert CONFIG_CREDENTIAL_REVOKE in commands


def test_revoke_requires_a_credential_slot(device):
    _set_pin_and_reset(device)

    with pytest.raises(CtapError) as error:
        _vendor_config(device)._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {0x01: CONFIG_CREDENTIAL_REVOKE},
        )
    assert error.value.code == CtapError.ERR.INVALID_PARAMETER


def test_revoke_rejects_an_expiration_parameter(device):
    _set_pin_and_reset(device)

    with pytest.raises(CtapError) as error:
        _vendor_config(device)._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {
                0x01: CONFIG_CREDENTIAL_REVOKE,
                0x02: b"\x00\x00\x00\x00",
                0x03: 0,
            },
        )
    assert error.value.code == CtapError.ERR.INVALID_PARAMETER


def test_revoke_missing_resident_credential_returns_no_credentials(device):
    _set_pin_and_reset(device)

    with pytest.raises(CtapError) as error:
        _vendor_config(device)._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {0x01: CONFIG_CREDENTIAL_REVOKE, 0x03: 0},
        )
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.parametrize(
    "expiration",
    [None, b"", b"\x00" * 3, b"\x00" * 5],
)
def test_expire_requires_a_four_byte_timestamp(device, expiration):
    _set_pin_and_reset(device)
    params = {0x01: CONFIG_CREDENTIAL_EXPIRE, 0x03: 0}
    if expiration is not None:
        params[0x02] = expiration

    with pytest.raises(CtapError) as error:
        _vendor_config(device)._call(Config.CMD.VENDOR_PROTOTYPE, params)
    assert error.value.code == CtapError.ERR.INVALID_PARAMETER


def test_vendor_config_rejects_a_token_without_authenticator_config_permission(device):
    _set_pin_and_reset(device)

    with pytest.raises(CtapError) as error:
        _vendor_config(device, ClientPin.PERMISSION.MAKE_CREDENTIAL)._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {0x01: CONFIG_CREDENTIAL_REVOKE, 0x03: 0},
        )
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_revoke_resident_credential_blocks_assertion(device):
    _set_pin_and_reset(device)
    rp = {"id": "credential-metadata.example", "name": "Credential Metadata"}
    registration = device.doMC(rp=rp, rk=True)["res"].attestation_object
    credential_id = registration.auth_data.credential_data.credential_id

    device.doGA(
        rp_id=rp["id"],
        allow_list=[{"id": credential_id, "type": "public-key"}],
    )
    _vendor_config(device)._call(
        Config.CMD.VENDOR_PROTOTYPE,
        {
            0x01: CONFIG_CREDENTIAL_REVOKE,
            0x03: 0,
        },
    )

    with pytest.raises(CtapError) as error:
        device.doGA(
            rp_id=rp["id"],
            allow_list=[{"id": credential_id, "type": "public-key"}],
        )
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS

    with pytest.raises(CtapError) as error:
        device.doGA(rp_id=rp["id"])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
