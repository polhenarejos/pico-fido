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
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.utils import hmac_sha256
from fido2.ctap2.pin import PinProtocolV2
from fido2.webauthn import UserVerificationRequirement
from utils import *

salt1 = b"\xa5" * 32
salt2 = b"\x96" * 32
salt3 = b"\x03" * 32
salt4 = b"\x5a" * 16
salt5 = b"\x96" * 64


@pytest.fixture(scope="class")
def MCHmacSecret(resetdevice):
    res = resetdevice.doMC(extensions={"hmacCreateSecret": True},rk=True)
    return res['res'].attestation_object

@pytest.fixture(scope="class")
def hmac(resetdevice):
    return HmacSecretExtension(resetdevice.client()._backend.ctap2, pin_protocol=PinProtocolV2())

def test_hmac_secret_make_credential(MCHmacSecret):
    assert MCHmacSecret.auth_data.extensions
    assert "hmac-secret" in MCHmacSecret.auth_data.extensions
    assert MCHmacSecret.auth_data.extensions["hmac-secret"] == True

def test_hmac_secret_info(info):
    assert "hmac-secret" in info.extensions

def test_fake_extension(device):
    device.doMC(extensions={"tetris": True})


@pytest.mark.parametrize("salts", [(salt1,), (salt1, salt2)])
def test_hmac_secret_entropy(device, MCHmacSecret, hmac, salts
):
    hout = {'salt1':salts[0]}
    if (len(salts) > 1):
        hout['salt2'] = salts[1]

    auth = device.doGA(extensions={"hmacGetSecret": hout})['res'].get_response(0)
    ext = auth.extension_results
    assert ext
    assert "hmacGetSecret" in ext
    assert len(auth.authenticator_data.extensions['hmac-secret']) == len(salts) * 32 + 16

    #print(shannon_entropy(auth.authenticator_data.extensions['hmac-secret']))
    if len(salts) == 1:
        assert shannon_entropy(auth.authenticator_data.extensions['hmac-secret']) > 4.5
        assert shannon_entropy(ext["hmacGetSecret"]['output1']) > 4.5
    if len(salts) == 2:
        assert shannon_entropy(auth.authenticator_data.extensions['hmac-secret']) > 5.4
        assert shannon_entropy(ext["hmacGetSecret"]['output1']) > 4.5
        assert shannon_entropy(ext["hmacGetSecret"]['output2']) > 4.5

def get_output(device, MCHmacSecret, hmac, salts):
    hout = {'salt1':salts[0]}
    if (len(salts) > 1):
        hout['salt2'] = salts[1]

    auth = device.doGA(extensions={"hmacGetSecret": hout})['res'].get_response(0)

    ext = auth.extension_results
    assert ext
    assert "hmacGetSecret" in ext
    assert len(auth.authenticator_data.extensions['hmac-secret']) == len(salts) * 32 + 16

    if len(salts) == 2:
        return ext["hmacGetSecret"]['output1'], ext["hmacGetSecret"]['output2']
    else:
        return ext["hmacGetSecret"]['output1']

def test_hmac_secret_sanity(device, MCHmacSecret, hmac):
    output1 = get_output(device, MCHmacSecret, hmac, (salt1,))
    output12 = get_output(
        device, MCHmacSecret, hmac, (salt1, salt2)
    )
    output21 = get_output(
        device, MCHmacSecret, hmac, (salt2, salt1)
    )

    assert output12[0] == output1
    assert output21[1] == output1
    assert output21[0] == output12[1]
    assert output12[0] != output12[1]

def test_missing_keyAgreement(device, hmac):
    hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salt3}})

    with pytest.raises(CtapError):
        device.GA(extensions={"hmac-secret": {2: hout[2], 3: hout[3]}})

def test_missing_saltAuth(device, hmac):
    hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salt3}})

    with pytest.raises(CtapError) as e:
        device.GA(extensions={"hmac-secret": {1: hout[1], 2: hout[2]}})
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_missing_saltEnc(device, hmac):
    hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salt3}})

    with pytest.raises(CtapError) as e:
        device.GA(extensions={"hmac-secret": {1: hout[1], 3: hout[3]}})
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_auth(device, hmac, MCHmacSecret):

    hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salt3}})
    bad_auth = list(hout[3][:])
    bad_auth[len(bad_auth) // 2] = bad_auth[len(bad_auth) // 2] ^ 1
    bad_auth = bytes(bad_auth)

    with pytest.raises(CtapError) as e:
        device.GA(extensions={"hmac-secret": {1: hout[1], 2: hout[2], 3: bad_auth, 4: 2}})
    assert e.value.code == CtapError.ERR.EXTENSION_FIRST

@pytest.mark.parametrize("salts", [(salt4,), (salt4, salt5)])
def test_invalid_salt_length(device, hmac, salts):
    with pytest.raises(ValueError) as e:
        if (len(salts) == 2):
            hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0],"salt2":salts[1]}})
        else:
            hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0]}})

        device.doGA(extensions={"hmacGetSecret": hout})

@pytest.mark.parametrize("salts", [(salt1,), (salt1, salt2)])
def test_get_next_assertion_has_extension(
    device, hmac, salts
):
    """ Check that get_next_assertion properly returns extension information for multiple accounts. """
    if (len(salts) == 2):
        hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0],"salt2":salts[1]}})
    else:
        hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0]}})
    accounts = 3
    regs = []
    auths = []
    rp = {"id": f"example_salts_{len(salts)}.org", "name": "ExampleRP_2"}
    fixed_users = [generate_random_user() for _ in range(accounts)]
    for i in range(accounts):
        res = device.doMC(extensions={"hmacCreateSecret": True},
            rk=True,
            rp=rp,
            user=fixed_users[i])['res'].attestation_object
        regs.append(res)

    hout = {'salt1':salts[0]}
    if (len(salts) > 1):
        hout['salt2'] = salts[1]

    ga = device.doGA(extensions={"hmacGetSecret": hout}, rp_id=rp['id'])
    auths = ga['res'].get_assertions()

    for x in auths:
        assert x.auth_data.flags & (1 << 7)  # has extension
        ext = x.auth_data.extensions
        assert ext
        assert "hmac-secret" in ext
        assert isinstance(ext["hmac-secret"], bytes)
        assert len(ext["hmac-secret"]) == len(salts) * 32 + 16
        key = hmac.process_get_output(x)



def test_hmac_secret_different_with_uv(device, MCHmacSecret, hmac):
    salts = [salt1]
    if (len(salts) == 2):
        hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0],"salt2":salts[1]}})
    else:
        hout = hmac.process_get_input({"hmacGetSecret":{"salt1":salts[0]}})

    auth_no_uv = device.GA(extensions={"hmac-secret": hout})['res']
    assert (auth_no_uv.auth_data.flags & (1 << 2)) == 0

    ext_no_uv = auth_no_uv.auth_data.extensions
    assert ext_no_uv
    assert "hmac-secret" in ext_no_uv
    assert isinstance(ext_no_uv["hmac-secret"], bytes)
    assert len(ext_no_uv["hmac-secret"]) == len(salts) * 32 + 16

    # Now get same auth with UV
    hout = {'salt1':salts[0]}
    if (len(salts) > 1):
        hout['salt2'] = salts[1]
    auth_uv = device.doGA(extensions={"hmacGetSecret": hout}, user_verification=UserVerificationRequirement.REQUIRED)['res'].get_response(0)

    assert auth_uv.authenticator_data.flags & (1 << 2)
    ext_uv = auth_uv.extension_results
    assert ext_uv
    assert "hmacGetSecret" in ext_uv
    assert len(ext_uv["hmacGetSecret"]) == len(salts)

    # Now see if the hmac-secrets are different
    assert ext_no_uv["hmac-secret"][:32] != ext_uv["hmacGetSecret"]['output1']
