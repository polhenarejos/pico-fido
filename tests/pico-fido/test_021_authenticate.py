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


from fido2.client import CtapError
from fido2.cose import ES256, ES384, ES512, EdDSA
from utils import verify
import pytest

def test_authenticate(device):
    device.reset()
    REGRes,AUTData = device.register()

    credentials = [AUTData.credential_data]
    AUTRes = device.authenticate(credentials)

def test_assertion_auth_data(GARes):
    assert len(GARes['res'].get_response(0).authenticator_data) == 37

def test_Check_that_AT_flag_is_not_set(GARes):
    assert (GARes['res'].get_response(0).authenticator_data.flags & 0xF8) == 0

def test_that_user_credential_and_numberOfCredentials_are_not_present(device, MCRes):
    res = device.GA(allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ])
    assert res['res'].user == None
    assert res['res'].number_of_credentials == None

def test_empty_allowList(device):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=[])
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

@pytest.mark.parametrize(
    "alg", [ES256.ALGORITHM, ES384.ALGORITHM, ES512.ALGORITHM, EdDSA.ALGORITHM]
)
def test_algorithms(device, info, alg):
    if ({'alg': alg, 'type': 'public-key'} in info.algorithms):
        MCRes = device.doMC(key_params=[{"alg": alg, "type": "public-key"}])
        res = device.GA(allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ])
        verify(MCRes['res'].attestation_object, res['res'], res['req']['client_data_hash'])

def test_get_assertion_allow_list_filtering_and_buffering(device):
    """ Check that authenticator filters and stores items in allow list correctly """
    allow_list = []

    rp1 = {"id": "rp1.com", "name": "rp1.com"}
    rp2 = {"id": "rp2.com", "name": "rp2.com"}

    rp1_registrations = []
    rp2_registrations = []
    rp1_assertions = []
    rp2_assertions = []

    l1 = 4
    for i in range(0, l1):
        res = device.doMC(rp=rp1)['res'].attestation_object
        rp1_registrations.append(res)
        allow_list.append({
            "id": res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        })

    l2 = 6
    for i in range(0, l2):
        res = device.doMC(rp=rp2)['res'].attestation_object
        rp2_registrations.append(res)
        allow_list.append({
            "id": res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        })

    # CTAP 2.1: If allowlist is passed, only one (any) applicable
    # credential signs, and numberOfCredentials = None is returned.
    # <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#:~:text=If%20the%20allowList%20parameter%20is%20present%3A,Go%20to%20Step%2013>
    #
    # CTAP 2.0: Expects the authenticator to return the total number
    # even when allowlist is passed (and hence keep the credential IDs
    # cached.

    # Should authenticate to all credentials matching rp1
    rp1_assertions = device.doGA(rp_id=rp1['id'], allow_list=allow_list)['res'].get_assertions()

    # Should authenticate to all credentials matching rp2
    rp2_assertions = device.doGA(rp_id=rp2['id'], allow_list=allow_list)['res'].get_assertions()

    counts = (
        len(rp1_assertions),
        len(rp2_assertions)
    )

    assert counts in [(1, 1), (l1, l2)]

def test_corrupt_credId(device, MCRes):
    # apply bit flip
    badid = list(MCRes['res'].attestation_object.auth_data.credential_data.credential_id[:])
    badid[len(badid) // 2] = badid[len(badid) // 2] ^ 1
    badid = bytes(badid)

    allow_list = [{"id": badid, "type": "public-key"}]

    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=allow_list)['res']
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

def test_mismatched_rp(device, GARes):
    rp_id = device.rp()['id']
    rp_id += ".com"

    with pytest.raises(CtapError) as e:
        device.doGA(rp_id=rp_id)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

def test_missing_rp(device):
    with pytest.raises(CtapError) as e:
        device.doGA(rp_id=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_rp(device):
    with pytest.raises(CtapError) as e:
        device.doGA(rp_id={"id": {"type": "wrong"}})

def test_missing_cdh(device):
    with pytest.raises(CtapError) as e:
        device.GA(client_data_hash=None)
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_cdh(device):
    with pytest.raises(CtapError) as e:
        device.GA(client_data_hash={"type": "wrong"})

def test_bad_allow_list(device):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list={"type": "wrong"})

def test_bad_allow_list_item(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=["wrong"] + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
        )

def test_unknown_option(device, MCRes):
    device.GA(options={"unknown": True}, allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ])

def test_option_uv(device, info, GARes):
    if "uv" in info.options:
        if info.options["uv"]:
            res = device.doGA(options={"uv": True})['res']
            assert res.auth_data.flags & (1 << 2)

def test_option_up(device, info, GARes):
    if "up" in info.options:
        if info.options["up"]:
            res = device.doGA(options={"up": True})['res']
            assert res.auth_data.flags & (1 << 0)

def test_allow_list_fake_item(device, MCRes):
    device.doGA(allow_list=[{"type": "rot13", "id": b"1234"}]
            + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ],
    )

def test_allow_list_missing_field(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=[{"id": b"1234"}] + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
        )

def test_allow_list_field_wrong_type(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=[{"type": b"public-key", "id": b"1234"}]
                + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
        )

def test_allow_list_id_wrong_type(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=[{"type": "public-key", "id": 42}]
                + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
        )

def test_allow_list_missing_id(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.doGA(allow_list=[{"type": "public-key"}] + [
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ]
        )

def test_user_presence_option_false(device, MCRes):
    res = device.GA(options={"up": False}, allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ])

def test_credential_resets(device, MCRes, GARes):
    device.reset()
    with pytest.raises(CtapError) as e:
        new_auth = device.doGA()
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
