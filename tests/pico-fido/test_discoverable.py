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
    assert "id" in GARes_DC.user.keys()

    allow_list = [
        {
            "id": MCRes_DC.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    if do_reboot:
        device.reboot()

    ga_res = device.GA(allow_list=allow_list)

    assert device.user()["id"] == ga_res.user["id"]

def test_with_allow_list_after_reset(device, MCRes_DC, GARes_DC):
    assert "id" in GARes_DC.user.keys()

    allow_list = [
        {
            "id": MCRes_DC.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    ga_res = device.GA(allow_list=allow_list)

    assert device.user()["id"] == ga_res.user["id"]

    device.reset()

    with pytest.raises(CtapError) as e:
        ga_res = device.doGA(allow_list=allow_list)
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS



def test_resident_key(MCRes_DC, info):
    pass

def test_resident_key_auth(MCRes_DC, GARes_DC):
    pass

def test_user_info_returned(device, MCRes_DC, GARes_DC):
    assert "id" in GARes_DC.user.keys()
    assert (
        MCRes_DC.auth_data.credential_data.credential_id
        == GARes_DC.credential["id"]
    )
    assert device.user()["id"] == GARes_DC.user["id"]
    if not GARes_DC.number_of_credentials:
        assert "id" in GARes_DC.user.keys() and len(GARes_DC.user.keys()) == 1
    else:
        assert device.user() == GARes_DC.user


def test_multiple_rk_nodisplay(device, MCRes_DC):
    auths = []
    regs = []
    # Use unique RP to not collide with other credentials
    rp = {"id": f"unique-{random.random()}.com", "name": "Example"}
    for i in range(0, 3):
        res = device.doMC(rp=rp, rk=True, user=generate_random_user())
        regs.append(res)
        # time.sleep(2)

    res = device.doGA(rp_id=rp['id'])
    auths = res.get_assertions()

    assert len(regs) == 3
    assert len(regs) == len(auths)

    for x in auths:
        for y in ("name", "displayName", "id"):
            if y not in x.user.keys():
                print("FAIL: %s was not in user: " % y, x.user)


def test_rk_maximum_size_nodisplay(device, MCRes_DC):
    """
    Check the lengths of the fields according to the FIDO2 spec
    https://github.com/solokeys/solo/issues/158#issue-426613303
    https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
    """
    auths = []
    user_max = generate_user_maximum()
    print(user_max)
    resMC = device.doMC(user=user_max)
    resGA = device.doGA()
    auths = resGA.get_assertions()

    user_max_GA = auths[0]

    for y in ("name", "displayName", "id"):
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
        req = FidoRequest(MCRes_DC, user=get_user(), rp = rp)
        res = device.sendMC(*req.toMC())
        regs.append(res)

    req = FidoRequest(MCRes_DC, options=None, user=generate_user_maximum(), rp = rp)
    res = device.sendGA(*req.toGA())
    assert res.number_of_credentials == RK_CAPACITY_PER_RP

    auths.append(res)
    for i in range(RK_CAPACITY_PER_RP - 1):
        auths.append(device.ctap2.get_next_assertion())

    with pytest.raises(CtapError) as e:
        device.ctap2.get_next_assertion()

    auths = auths[::-1][-RK_to_generate:]
    regs = regs[-RK_to_generate:]
    users = users[-RK_to_generate:]

    assert len(auths) == len(users)

    if MCRes_DC.request.pin_protocol:
        for x, u in zip(auths, users):
            for y in ("name", "icon", "displayName", "id"):
                assert y in x.user.keys()
                assert x.user[y] == u[y]

    assert len(auths) == len(regs)
    for x, y in zip(regs, auths):
        verify(x, y, req.cdh)


def test_rk_with_allowlist_of_different_rp(resetDevice):
    """
    Test that a rk credential is not found when using an allowList item for a different RP
    """

    rk_rp = {"id": "rk-cred.org", "name": "Example"}
    rk_req = FidoRequest(rp = rk_rp, options={"rk": True})
    rk_res = resetDevice.sendMC(*rk_req.toMC())

    server_rp = {"id": "server-cred.com", "name": "Example"}
    server_req = FidoRequest(rp = server_rp)
    server_res = resetDevice.sendMC(*server_req.toMC())

    allow_list_with_different_rp_cred = [
        {
            "id": server_res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    test_req = FidoRequest(rp = rk_rp, allow_list = allow_list_with_different_rp_cred)

    with pytest.raises(CtapError) as e:
        res = resetDevice.sendGA(*test_req.toGA())
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_same_userId_overwrites_rk(resetDevice):
    """
    A make credential request with a UserId & Rp that is the same as an existing one should overwrite.
    """
    rp = {"id": "overwrite.org", "name": "Example"}
    user = generate_user()

    req = FidoRequest(rp = rp, options={"rk": True}, user = user)
    mc_res1 = resetDevice.sendMC(*req.toMC())

    # Should overwrite the first credential.
    mc_res2 = resetDevice.sendMC(*req.toMC())

    ga_res = resetDevice.sendGA(*req.toGA())

    # If there's only one credential, this is None
    assert ga_res.number_of_credentials == None

    verify(mc_res2, ga_res, req.cdh)

def test_larger_icon_than_128(device):
    """
    Test it works if we give an icon value larger than 128 bytes
    """
    rp = {"id": "overwrite.org", "name": "Example"}
    user = generate_user()
    user['icon'] = 'https://www.w3.org/TR/webauthn/?icon=' + ("A" * 128)

    req = FidoRequest(rp = rp, options={"rk": True}, user = user)
    device.sendMC(*req.toMC())


def test_returned_credential(device):
    """
    Test that when two rk credentials put in allow_list,
    only 1 will get returned.
    """
    device.reset()
    pin = '12345'
    device.client.pin_protocol.set_pin(pin)
    req = FidoRequest(pin = pin, options={"rk": True})

    regs = []
    allow_list = []
    for i in range(0, 2):
        req = FidoRequest(req, user = {
            "id": b'123456' + bytes([i]), "name": f'Test User {i}', "displayName": f'Test User display {i}'
        })
        res = device.sendMC(*req.toMC())
        setattr(res, "request", req)
        regs.append(res)
        allow_list.append({"id": res.auth_data.credential_data.credential_id[:], "type": "public-key"})


    print('allow_list: ' , allow_list)
    ga_req = FidoRequest(pin = pin, allow_list=allow_list)
    ga_res = device.sendGA(*ga_req.toGA())

    # No other credentials should be returned
    with pytest.raises(CtapError) as e:
        device.ctap2.get_next_assertion()

    # the returned credential should have user id in it
    print(ga_res)
    assert 'id' in ga_res.user and len(ga_res.user["id"]) > 0
