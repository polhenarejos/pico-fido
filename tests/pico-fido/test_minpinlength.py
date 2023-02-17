import pytest
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import UserVerificationRequirement
from fido2.ctap import CtapError
from fido2.ctap2.pin import PinProtocolV2, ClientPin
from fido2.ctap2 import Config

PIN='12345678'
MINPINLENGTH=6

@pytest.fixture(scope="function")
def MCMinPin(device):
    res = device.doMC(rk=True, extensions={'minPinLength': True})['res'].attestation_object
    return res

@pytest.fixture(scope="function")
def SetMinPin(device):
    device.reset()
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)
    cfg = FidoConfig(device)
    cfg.set_min_pin_length(MINPINLENGTH,rp_ids=['example.com'])

@pytest.fixture(scope="function")
def SetMinPinWrongRpid(device):
    device.reset()
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)
    cfg = FidoConfig(device)
    cfg.set_min_pin_length(MINPINLENGTH,rp_ids=['notanexample.com'])

def PinToken(device):
    return ClientPin(device.client()._backend.ctap2).get_pin_token(PIN, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.AUTHENTICATOR_CFG)

def FidoConfig(device):
    pt = PinToken(device)
    pin_protocol = PinProtocolV2()
    return Config(device.client()._backend.ctap2, pin_protocol, pt)

def test_supports_minpin(info):
    assert info.extensions
    assert 'minPinLength' in info.extensions
    assert info.options
    assert 'setMinPINLength' in info.options
    assert info.options['setMinPINLength'] is True

def test_minpin(SetMinPin, MCMinPin):
    assert MCMinPin.auth_data.extensions
    assert "minPinLength" in MCMinPin.auth_data.extensions
    assert MCMinPin.auth_data.extensions['minPinLength'] == MINPINLENGTH

def test_minpin_bad_rpid(SetMinPinWrongRpid, MCMinPin):
    assert not MCMinPin.auth_data.extensions
    assert "minPinLength" not in MCMinPin.auth_data.extensions

def test_setminpin(device, SetMinPin, MCMinPin):
    cfg = FidoConfig(device)
    cfg.set_min_pin_length(MINPINLENGTH+2,rp_ids=['example.com'])
    res = device.doMC(rk=True, extensions={'minPinLength': True})['res'].attestation_object
    assert res.auth_data.extensions
    assert "minPinLength" in res.auth_data.extensions
    assert res.auth_data.extensions['minPinLength'] == MINPINLENGTH+2

def test_no_setminpin(device, SetMinPin, MCMinPin):
    cfg = FidoConfig(device)
    with pytest.raises(CtapError) as e:
        cfg.set_min_pin_length(MINPINLENGTH-2,rp_ids=['example.com'])
    assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION

def test_setminpin_check_force(device, SetMinPin, MCMinPin):
    cfg = FidoConfig(device)
    cfg.set_min_pin_length(len(PIN)+1,rp_ids=['example.com'])
    info = device.client()._backend.ctap2.get_info()
    assert info.force_pin_change == True

@pytest.mark.parametrize(
    "force", [True, False]
)
def test_setminpin_set_forcee(device, SetMinPin, MCMinPin, force):
    cfg = FidoConfig(device)
    cfg.set_min_pin_length(MINPINLENGTH,rp_ids=['example.com'],force_change_pin=force)
    info = device.client()._backend.ctap2.get_info()
    assert info.force_pin_change == force
