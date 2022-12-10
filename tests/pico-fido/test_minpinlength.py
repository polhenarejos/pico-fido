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

def PinToken(device):
    return ClientPin(device.client()._backend.ctap2).get_pin_token(PIN, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.AUTHENTICATOR_CFG)

def FidoConfig(device):
    pt = PinToken(device)
    pin_protocol = PinProtocolV2()
    return Config(device.client()._backend.ctap2, pin_protocol, pt)

def test_minpin(MCMinPin, SetMinPin):
    assert MCMinPin.auth_data.extensions
    assert "minPinLength" in MCMinPin.auth_data.extensions
    assert MCMinPin.auth_data.extensions['minPinLength'] == MINPINLENGTH
