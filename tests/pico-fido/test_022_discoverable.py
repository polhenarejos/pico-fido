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
import pytest
import random
from utils import *

@pytest.mark.parametrize("do_reboot", [False, True])
def test_user_info_returned_when_using_allowlist(device, MCRes_DC, GARes_DC, do_reboot):
    assert "id" in GARes_DC['res'].user.keys()

    allow_list = [
        {
            "id": MCRes_DC['res'].attestation_object.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    if do_reboot:
        device.reboot()

    ga_res = device.GA(allow_list=allow_list)['res']

    assert MCRes_DC["req"]["user"]["id"] == ga_res.user["id"]

def test_with_allow_list_after_reset(device, MCRes_DC, GARes_DC):
    assert "id" in GARes_DC['res'].user.keys()

    allow_list = [
        {
            "id": MCRes_DC['res'].attestation_object.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    ga_res = device.GA(allow_list=allow_list)['res']

    assert MCRes_DC["req"]["user"]["id"] == ga_res.user["id"]

    device.reset()

    # It returns a silent authentication
    ga_res = device.doGA(allow_list=allow_list)



def test_resident_key(MCRes_DC, info):
    pass

def test_resident_key_auth(MCRes_DC, GARes_DC):
    pass

def test_user_info_returned(device, MCRes_DC, GARes_DC):
    assert "id" in GARes_DC['res'].user.keys()
    assert (
        MCRes_DC['res'].attestation_object.auth_data.credential_data.credential_id
        == GARes_DC['res'].credential["id"]
    )
    assert MCRes_DC["req"]["user"]["id"] == GARes_DC['res'].user["id"]
    if not GARes_DC['res'].number_of_credentials:
        assert "id" in GARes_DC['res'].user.keys() and len(GARes_DC['res'].user.keys()) == 1
    else:
        assert MCRes_DC["req"]["user"] == GARes_DC['res'].user


def test_multiple_rk_nodisplay(device, MCRes_DC):
    auths = []
    regs = []
    # Use unique RP to not collide with other credentials
    rp = {"id": "example.com", "name": "Example"}
    for i in range(0, 3):
        res = device.doMC(rp=rp, rk=True, user=generate_random_user())
        regs.append(res)
        # time.sleep(2)

    res = device.doGA(rp_id=rp['id'])['res']
    auths = res.get_assertions()

    assert len(regs) == 3
    assert len(regs) == len(auths)

    for x in auths:
        for y in ("name", "displayName", "id"):
            if y not in x.user.keys():
                print("FAIL: %s was not in user: " % y, x.user)


def test_rk_maximum_size_nodisplay(device):
    """
    Check the lengths of the fields according to the FIDO2 spec
    https://github.com/solokeys/solo/issues/158#issue-426613303
    https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
    """
    device.reset()
    user_max = generate_user_maximum()
    resMC = device.doMC(user=user_max, rk=True)
    resGA = device.doGA()['res']
    auths = resGA.get_assertions()

    user_max_GA = auths[0]

    for y in ("name", "displayName", "id"):
        if (y in user_max_GA):
            assert user_max_GA.user[y] == user_max[y]


def test_rk_maximum_list_capacity_per_rp_nodisplay(info, device, MCRes_DC):
    """
    Test maximum returned capacity of the RK for the given RP
    """
    device.reset()
    # Try to determine from get_info, or default to 19.
    RK_CAPACITY_PER_RP = info.max_creds_in_list
    if not RK_CAPACITY_PER_RP:
        RK_CAPACITY_PER_RP = 19

    users = []

    def get_user():
        user = generate_user_maximum()
        users.append(user)
        return user

    # Use unique RP to not collide with other credentials from other tests.
    rp = {"id": "example.com", "name": "Example"}

    # req = FidoRequest(MCRes_DC, options=None, user=get_user(), rp = rp)
    # res = device.sendGA(*req.toGA())
    current_credentials_count = 0

    auths = []
    regs = [MCRes_DC]
    RK_to_generate = RK_CAPACITY_PER_RP - current_credentials_count
    for i in range(RK_to_generate):
        res = device.doMC(user=get_user(), rp=rp, rk=True)['res'].attestation_object
        regs.append(res)

    res = device.GA(rp_id = rp['id'])['res']
    assert res.number_of_credentials == RK_CAPACITY_PER_RP

    auths.append(res)
    for i in range(RK_CAPACITY_PER_RP - 1):
        auths.append(device.GNA())

    with pytest.raises(CtapError) as e:
        device.GNA()

    auths = auths[::-1][-RK_to_generate:]
    regs = regs[-RK_to_generate:]
    users = users[-RK_to_generate:]

    assert len(auths) == len(users)

    for x, u in zip(auths, users):
        for y in ("name", "displayName", "id"):
            assert y in x.user.keys()
            assert x.user[y] == u[y]

    assert len(auths) == len(regs)


def test_rk_with_allowlist_of_different_rp(resetdevice):
    """
    Test that a rk credential is not found when using an allowList item for a different RP
    """

    rk_rp = {"id": "rk-cred.org", "name": "Example"}
    rk_res = resetdevice.MC(rp = rk_rp, options={"rk":True})['res']

    server_rp = {"id": "server-cred.com", "name": "Example"}
    server_res = resetdevice.MC(rp = server_rp, options={"rk":True})['res']

    allow_list_with_different_rp_cred = [
        {
            "id": server_res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]


    with pytest.raises(CtapError) as e:
        res = resetdevice.GA(rp_id = rk_rp['id'], allow_list = allow_list_with_different_rp_cred)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_same_userId_overwrites_rk(resetdevice):
    """
    A make credential request with a UserId & Rp that is the same as an existing one should overwrite.
    """
    rp = {"id": "overwrite.org", "name": "Example"}
    user = generate_random_user()

    mc_res1 = resetdevice.MC(rp = rp, options={"rk":True}, user = user)

    # Should overwrite the first credential.
    mc_res2 = resetdevice.MC(rp = rp, options={"rk":True}, user = user)

    ga_res = resetdevice.GA(rp_id=rp['id'])['res']

    # If there's only one credential, this is None
    assert ga_res.number_of_credentials == None


def test_larger_icon_than_128(device):
    """
    Test it works if we give an icon value larger than 128 bytes
    """
    rp = {"id": "overwrite.org", "name": "Example"}
    user = generate_random_user()
    user['icon'] = 'https://www.w3.org/TR/webauthn/?icon=' + ("A" * 128)

    device.MC(rp = rp, options={"rk":True}, user = user)


def test_returned_credential(device):
    """
    Test that when two rk credentials put in allow_list,
    only 1 will get returned.
    """
    device.reset()

    regs = []
    allow_list = []
    for i in range(0, 2):
        res = device.doMC(rk=True, user = {
            "id": b'123456' + bytes([i]), "name": f'Test User {i}', "displayName": f'Test User display {i}'
        })['res'].attestation_object
        regs.append(res)
        allow_list.append({"id": res.auth_data.credential_data.credential_id[:], "type": "public-key"})


    ga_res = device.GA(allow_list=allow_list,options={'up':False})['res']

    # No other credentials should be returned
    with pytest.raises(CtapError) as e:
        device.GNA()

    # the returned credential should have user id in it
    #print(ga_res)
    #assert 'id' in ga_res.user and len(ga_res.user["id"]) > 0
