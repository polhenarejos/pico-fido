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
from fido2.ctap import CtapError
from fido2.ctap2.pin import PinProtocolV2, ClientPin
from fido2.utils import websafe_decode
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
    mc = device.doMC(
        rk=True,
        extensions={'largeBlob':{'support':'required'}}
        )
    res = mc['res']
    ext = mc['client_extension_results']
    return {'res': res, 'ext': ext}

@pytest.fixture(scope="function")
def GALBRead(device, MCLBK):
    res = device.doGA(
        allow_list=[
            {"id": MCLBK['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ],extensions={'largeBlob':{'read': True}}
        )
    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCLBK['res'].attestation_object, a, res['req']['client_data'].hash)
    return res['res']

@pytest.fixture(scope="function")
def GALBReadLBK(GALBRead):
    return GALBRead.get_assertions()[0]

@pytest.fixture(scope="function")
def GALBReadLB(GALBRead):
    print(GALBRead.get_response(0))
    return GALBRead.get_response(0)

@pytest.fixture(scope="function")
def GALBWrite(device, MCLBK):
    res = device.doGA(
        allow_list=[
            {"id": MCLBK['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ],extensions={'largeBlob':{'write': LARGE_BLOB}}
        )
    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCLBK['res'].attestation_object, a, res['req']['client_data'].hash)
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
    assert 'largeBlob' in MCLBK['ext']
    assert 'supported' in MCLBK['ext']['largeBlob']
    assert MCLBK['ext']['largeBlob']['supported'] is True

def test_get_largeblobkey_ga(GALBReadLBK):
    assert GALBReadLBK.large_blob_key is not None

def test_get_largeblob_rw(GALBWrite, GALBReadLB):
    assert 'largeBlob' in GALBWrite.client_extension_results
    assert 'written' in GALBWrite.client_extension_results['largeBlob']
    assert GALBWrite.client_extension_results['largeBlob']['written'] is True

    assert 'blob' in GALBReadLB.client_extension_results['largeBlob']
    assert websafe_decode(GALBReadLB.client_extension_results['largeBlob']['blob']) == LARGE_BLOB
