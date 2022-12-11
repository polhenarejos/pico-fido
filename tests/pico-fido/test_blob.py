import pytest
from fido2.ctap import CtapError
from fido2.ctap2.pin import PinProtocolV2, ClientPin
from utils import verify
import os

PIN='12345678'
SMALL_BLOB=b"A"*32

@pytest.fixture(scope="function")
def MCCredBlob(device):
    res = device.doMC(extensions={'credBlob': SMALL_BLOB})['res'].attestation_object
    return res

@pytest.fixture(scope="function")
def GACredBlob(device, MCCredBlob):
    res = device.doGA(allow_list=[
            {"id": MCCredBlob.auth_data.credential_data.credential_id, "type": "public-key"}
        ], extensions={'getCredBlob': True})

    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCCredBlob, a, res['req']['client_data'].hash)
    return assertions[0]

def test_supports_credblob(info):
    assert info.extensions
    assert 'credBlob' in info.extensions
    assert info.max_cred_blob_length
    assert info.max_cred_blob_length > 0

def test_mc_credblob(MCCredBlob):
    assert MCCredBlob.auth_data.extensions
    assert "credBlob" in MCCredBlob.auth_data.extensions
    assert MCCredBlob.auth_data.extensions['credBlob'] is True

def test_ga_credblob(GACredBlob):
    assert GACredBlob.auth_data.extensions
    assert "credBlob" in GACredBlob.auth_data.extensions
    assert GACredBlob.auth_data.extensions['credBlob'] == SMALL_BLOB

def test_wrong_credblob(device, info):
    device.reset()
    cdh = os.urandom(32)
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)
    pin_token = ClientPin(device.client()._backend.ctap2).get_pin_token(PIN, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    protocol = PinProtocolV2()
    MC = device.MC(
        client_data_hash=cdh,
        extensions={'credBlob': b'A'*(info.max_cred_blob_length+1)},
        pin_uv_protocol=protocol.VERSION,
        pin_uv_param=protocol.authenticate(pin_token, cdh)
        )['res']

    assert MC.auth_data.extensions
    assert "credBlob" in MC.auth_data.extensions
    assert MC.auth_data.extensions['credBlob'] is False

    res = device.doGA(allow_list=[
            {"id": MC.auth_data.credential_data.credential_id, "type": "public-key"}
        ], extensions={'getCredBlob': True})

    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MC, a, res['req']['client_data'].hash)

    assert assertions[0].auth_data.extensions
    assert "credBlob" in assertions[0].auth_data.extensions
    assert len(assertions[0].auth_data.extensions['credBlob']) == 0
