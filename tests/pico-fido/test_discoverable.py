from fido2.client import CtapError
from fido2.cose import ES256
import pytest
import secrets
import random
import string

def generate_random_user():
    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = random.randint(1, 64)
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = "User name"
    icon = "https://www.w3.org/TR/webauthn/"
    display_name = "Displayed " + name

    return {"id": user_id, "name": name, "icon": icon, "displayName": display_name}

counter = 1
def generate_user_maximum():
    """
    Generate RK with the maximum lengths of the fields, according to the minimal requirements of the FIDO2 spec
    """
    global counter

    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = 64
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(64))

    name = f"{counter}: {name}"
    icon = "https://www.w3.org/TR/webauthn/" + "A" * 128
    display_name = "Displayed " + name

    name = name[:64]
    display_name = display_name[:64]
    icon = icon[:128]

    counter += 1

    return {"id": user_id, "name": name, "icon": icon, "displayName": display_name}


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

    with pytest.raises(CtapError) as e:
        ga_res = device.doGA(allow_list=allow_list)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS



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
    rp = {"id": f"unique-{random.random()}.com", "name": "Example"}
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
    print(auths)
    for y in ("name", "displayName", "id"):
        if (y in user_max_GA):
            assert user_max_GA.user[y] == user_max[y]


def test_rk_maximum_list_capacity_per_rp_nodisplay(info, device, MCRes_DC):
    """
    Test maximum returned capacity of the RK for the given RP
    """

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
    rp = {"id": f"unique-{random.random()}.com", "name": "Example"}

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
    rk_res = resetdevice.doMC(rp = rk_rp, rk=True)['res'].attestation_object

    server_rp = {"id": "server-cred.com", "name": "Example"}
    server_res = resetdevice.doMC(rp = server_rp, rk=True)['res'].attestation_object

    allow_list_with_different_rp_cred = [
        {
            "id": server_res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]


    with pytest.raises(CtapError) as e:
        res = resetdevice.doGA(rp_id = rk_rp['id'], allow_list = allow_list_with_different_rp_cred)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_same_userId_overwrites_rk(resetdevice):
    """
    A make credential request with a UserId & Rp that is the same as an existing one should overwrite.
    """
    rp = {"id": "overwrite.org", "name": "Example"}
    user = generate_random_user()

    mc_res1 = resetdevice.doMC(rp = rp, rk=True, user = user)

    # Should overwrite the first credential.
    mc_res2 = resetdevice.doMC(rp = rp, rk=True, user = user)

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

    device.doMC(rp = rp, rk=True, user = user)


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


    print('allow_list: ' , allow_list)
    ga_res = device.GA(allow_list=allow_list)['res']
    print(ga_res)

    # No other credentials should be returned
    with pytest.raises(CtapError) as e:
        device.GNA()

    # the returned credential should have user id in it
    print(ga_res)
    assert 'id' in ga_res.user and len(ga_res.user["id"]) > 0
