import pytest
from fido2.ctap import CtapError
from fido2.ctap2.pin import PinProtocolV2, ClientPin
from utils import verify
import os

PIN='12345678'
SMALL_BLOB=b"A"*32
LARGE_BLOB=b"B"*1024

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

@pytest.fixture(scope="function")
def MCLBK(device):
    res = device.doMC(
        rk=True,
        extensions={'largeBlob':{'support':'required'}}
        )['res']
    return res

@pytest.fixture(scope="function")
def GALBRead(device, MCLBK):
    res = device.doGA(
        allow_list=[
            {"id": MCLBK.attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ],extensions={'largeBlob':{'read': True}}
        )
    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCLBK.attestation_object, a, res['req']['client_data'].hash)
    return res['res']

@pytest.fixture(scope="function")
def GALBReadLBK(GALBRead):
    return GALBRead.get_assertions()[0]

@pytest.fixture(scope="function")
def GALBReadLB(GALBRead):
    return GALBRead.get_response(0)

@pytest.fixture(scope="function")
def GALBWrite(device, MCLBK):
    res = device.doGA(
        allow_list=[
            {"id": MCLBK.attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ],extensions={'largeBlob':{'write': LARGE_BLOB}}
        )
    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCLBK.attestation_object, a, res['req']['client_data'].hash)
    return res['res'].get_response(0)

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

def test_supports_largeblobs(info):
    assert info.extensions
    assert 'largeBlobKey' in info.extensions
    assert 'largeBlobs' in info.options
    assert info.max_large_blob is None or (info.max_large_blob > 1024)

def test_get_largeblobkey_mc(MCLBK):
    assert 'supported' in MCLBK.extension_results
    assert MCLBK.extension_results['supported'] is True

def test_get_largeblobkey_ga(GALBReadLBK):
    assert GALBReadLBK.large_blob_key is not None

def test_get_largeblob_rw(GALBWrite, GALBReadLB):
    assert 'written' in GALBWrite.extension_results
    assert GALBWrite.extension_results['written'] is True

    assert 'blob' in GALBReadLB.extension_results
    assert GALBReadLB.extension_results['blob'] == LARGE_BLOB
