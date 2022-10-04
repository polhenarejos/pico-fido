import pytest
import time
import random
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement
from fido2.utils import sha256, hmac_sha256
from fido2.ctap2.pin import PinProtocolV2
from binascii import hexlify
from utils import generate_random_user

PIN = "12345678"


@pytest.fixture(params=[PIN], scope = 'function')
def PinToken(request, device, client_pin):
    #device.reboot()
    device.reset()
    pin = request.param
    client_pin.set_pin(pin)
    return client_pin.get_pin_token(pin)


@pytest.fixture(scope = 'function')
def MC_RK_Res(device, PinToken):
    rp = {"id": "ssh:", "name": "Bate Goiko"}
    device.doMC(rp=rp, rk=True)

    rp = {"id": "xakcop.com", "name": "John Doe"}
    device.doMC(rp=rp, rk=True)


@pytest.fixture(scope = 'function')
def CredMgmt(device, PinToken):
    pin_protocol = PinProtocolV2()
    return CredentialManagement(device.client()._backend.ctap2, pin_protocol, PinToken)


def _test_enumeration(CredMgmt, rp_map):
    "Enumerate credentials using BFS"
    res = CredMgmt.enumerate_rps()
    assert len(rp_map.keys()) == len(res)

    for rp in res:
        creds = CredMgmt.enumerate_creds(sha256(rp[3]["id"]))
        assert len(creds) == rp_map[rp[3]["id"].decode()]


def _test_enumeration_interleaved(CredMgmt, rp_map):
    "Enumerate credentials using DFS"
    first_rp = CredMgmt.enumerate_rps_begin()
    assert len(rp_map.keys()) == first_rp[CredentialManagement.RESULT.TOTAL_RPS]

    rk_count = 1
    first_rk = CredMgmt.enumerate_creds_begin(sha256(first_rp[3]["id"]))
    for i in range(1, first_rk[CredentialManagement.RESULT.TOTAL_CREDENTIALS]):
        c = CredMgmt.enumerate_creds_next()
        rk_count += 1

    assert rk_count == rp_map[first_rp[3]["id"].decode()]

    for i in range(1, first_rp[CredentialManagement.RESULT.TOTAL_RPS]):
        next_rp = CredMgmt.enumerate_rps_next()

        rk_count = 1
        first_rk = CredMgmt.enumerate_creds_begin(
            sha256(next_rp[3]["id"])
        )
        for i in range(1, first_rk[CredentialManagement.RESULT.TOTAL_CREDENTIALS]):
            c = CredMgmt.enumerate_creds_next()
            rk_count += 1

        assert rk_count == rp_map[next_rp[3]["id"].decode()]


def CredMgmtWrongPinAuth(device, pin_token):
    pin_protocol = PinProtocolV2()
    wrong_pt = bytearray(pin_token)
    wrong_pt[0] = (wrong_pt[0] + 1) % 256
    return CredentialManagement(device.client()._backend.ctap2, pin_protocol, bytes(wrong_pt))


def assert_cred_response_has_all_fields(cred_res):
    for i in (
        CredentialManagement.RESULT.USER,
        CredentialManagement.RESULT.CREDENTIAL_ID,
        CredentialManagement.RESULT.PUBLIC_KEY,
        CredentialManagement.RESULT.TOTAL_CREDENTIALS,
        CredentialManagement.RESULT.CRED_PROTECT,
    ):
        assert i in cred_res


def test_get_info(info):
    assert "credMgmt" in info.options
    assert info.options["credMgmt"] == True
    assert 0x7 in info
    assert info[0x7] > 1
    assert 0x8 in info
    assert info[0x8] > 1

def test_get_metadata(CredMgmt, MC_RK_Res):
    metadata = CredMgmt.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
    assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] >= 48

def test_enumerate_rps(CredMgmt, MC_RK_Res):
    res = CredMgmt.enumerate_rps()
    assert len(res) == 2
    assert res[0][CredentialManagement.RESULT.RP]["id"] == b"ssh:"
    assert res[0][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"ssh:")
    # Solo doesn't store rpId with the exception of "ssh:"
    assert res[1][CredentialManagement.RESULT.RP]["id"] == b"xakcop.com"
    assert res[1][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"xakcop.com")

def test_enumarate_creds(CredMgmt, MC_RK_Res):
    res = CredMgmt.enumerate_creds(sha256(b"ssh:"))
    assert len(res) == 1
    assert_cred_response_has_all_fields(res[0])
    res = CredMgmt.enumerate_creds(sha256(b"xakcop.com"))
    assert len(res) == 1
    assert_cred_response_has_all_fields(res[0])
    res = CredMgmt.enumerate_creds(sha256(b"missing.com"))
    assert not res

def test_get_metadata_wrong_pinauth(device, MC_RK_Res, PinToken):
    cmd = lambda credMgmt: credMgmt.get_metadata()
    _test_wrong_pinauth(device, cmd, PinToken)

def test_rpbegin_wrong_pinauth(device, MC_RK_Res, PinToken):
    cmd = lambda credMgmt: credMgmt.enumerate_rps_begin()
    _test_wrong_pinauth(device, cmd, PinToken)

def test_rkbegin_wrong_pinauth(device, MC_RK_Res, PinToken):
    cmd = lambda credMgmt: credMgmt.enumerate_creds_begin(sha256(b"ssh:"))
    _test_wrong_pinauth(device, cmd, PinToken)

def test_rpnext_without_rpbegin(device, CredMgmt, MC_RK_Res):
    CredMgmt.enumerate_creds_begin(sha256(b"ssh:"))
    with pytest.raises(CtapError) as e:
        CredMgmt.enumerate_rps_next()
    assert e.value.code == CtapError.ERR.NOT_ALLOWED

def test_rknext_without_rkbegin(device, CredMgmt, MC_RK_Res):
    CredMgmt.enumerate_rps_begin()
    with pytest.raises(CtapError) as e:
        CredMgmt.enumerate_creds_next()
    assert e.value.code == CtapError.ERR.NOT_ALLOWED

def test_delete(device, PinToken, CredMgmt):

    # create a new RK
    rp = {"id": "example_3.com", "name": "John Doe 2"}
    reg = device.doMC(rp=rp, rk=True)['res'].attestation_object

    # make sure it works
    auth = device.doGA(rp_id=rp['id'])

    # get the ID from enumeration
    creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
    for cred in creds:
        if cred[7]["id"] == reg.auth_data.credential_data.credential_id:
            break

    # delete it
    cred = {"id": cred[7]["id"], "type": "public-key"}
    CredMgmt.delete_cred(cred)

    # make sure it doesn't work
    with pytest.raises(CtapError) as e:
        auth = device.doGA(rp_id=rp['id'])
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS

def test_add_delete(device, PinToken, CredMgmt):
    """ Delete a credential in the 'middle' and ensure other credentials are not affected. """

    rp = {"id": "example_4.com", "name": "John Doe 3"}
    regs = []

    # create 3 new RK's
    for i in range(0, 3):
        reg = device.doMC(rp=rp, rk=True, user=generate_random_user())['res'].attestation_object
        regs.append(reg)

    # Check they all enumerate
    res = CredMgmt.enumerate_creds(regs[1].auth_data.rp_id_hash)
    assert len(res) == 3

    # delete the middle one
    creds = CredMgmt.enumerate_creds(reg.auth_data.rp_id_hash)
    for cred in creds:
        if cred[7]["id"] == regs[1].auth_data.credential_data.credential_id:
            break

    assert cred[7]["id"] == regs[1].auth_data.credential_data.credential_id

    cred = {"id": cred[7]["id"], "type": "public-key"}
    CredMgmt.delete_cred(cred)

    # Check one less enumerates
    res = CredMgmt.enumerate_creds(regs[0].auth_data.rp_id_hash)
    assert len(res) == 2

def test_multiple_creds_per_multiple_rps(
    device, PinToken, CredMgmt, MC_RK_Res
):
    res = CredMgmt.enumerate_rps()
    assert len(res) == 2

    new_rps = [
        {"id": "new_example_1.com", "name": "Example-3-creds"},
        {"id": "new_example_2.com", "name": "Example-3-creds"},
        {"id": "new_example_3.com", "name": "Example-3-creds"},
    ]

    # create 3 new credentials per RP
    for rp in new_rps:
        for i in range(0, 3):
            reg = device.doMC(rp=rp, rk=True, user=generate_random_user())

    res = CredMgmt.enumerate_rps()
    assert len(res) == 5

    for rp in res:
        if rp[3]["id"][:12] == "new_example_":
            creds = CredMgmt.enumerate_creds(sha256(rp[3]["id"].encode("utf8")))
            assert len(creds) == 3

@pytest.mark.parametrize(
    "enumeration_test", [_test_enumeration, _test_enumeration_interleaved]
)
def test_multiple_enumeration(
    device, PinToken, MC_RK_Res, CredMgmt, enumeration_test
):
    """ Test enumerate still works after different commands """

    res = CredMgmt.enumerate_rps()

    expected_enumeration = {"xakcop.com": 1, "ssh:": 1}

    enumeration_test(CredMgmt, expected_enumeration)

    new_rps = [
        {"id": "example-2.com", "name": "Example-2-creds", "count": 2},
        {"id": "example-1.com", "name": "Example-1-creds", "count": 1},
        {"id": "example-5.com", "name": "Example-5-creds", "count": 5},
    ]

    # create 3 new credentials per RP
    for rp in new_rps:
        for i in range(0, rp["count"]):
            reg = device.doMC(rp={"id": rp["id"], "name": rp["name"]}, rk=True, user=generate_random_user())

        # Now expect creds from this RP
        expected_enumeration[rp["id"]] = rp["count"]

    enumeration_test(CredMgmt, expected_enumeration)
    enumeration_test(CredMgmt, expected_enumeration)

    metadata = CredMgmt.get_metadata()

    enumeration_test(CredMgmt, expected_enumeration)
    enumeration_test(CredMgmt, expected_enumeration)

@pytest.mark.parametrize(
    "enumeration_test", [_test_enumeration, _test_enumeration_interleaved]
)
def test_multiple_enumeration_with_deletions(
    device, PinToken, MC_RK_Res, CredMgmt, enumeration_test
):
    """ Create each credential in random order.  Test enumerate still works after randomly deleting each credential"""

    res = CredMgmt.enumerate_rps()

    expected_enumeration = {"xakcop.com": 1, "ssh:": 1}

    enumeration_test(CredMgmt, expected_enumeration)

    new_rps = [
        {"id": "example-1.com", "name": "Example-1-creds"},
        {"id": "example-2.com", "name": "Example-2-creds"},
        {"id": "example-2.com", "name": "Example-2-creds"},
        {"id": "example-3.com", "name": "Example-3-creds"},
        {"id": "example-3.com", "name": "Example-3-creds"},
        {"id": "example-3.com", "name": "Example-3-creds"},
    ]
    random.shuffle(new_rps)

    # create new credentials per RP in random order
    for rp in new_rps:
        device.doMC(rp=rp, rk=True, user=generate_random_user())

        if rp["id"] not in expected_enumeration:
            expected_enumeration[rp["id"]] = 1
        else:
            expected_enumeration[rp["id"]] += 1

        enumeration_test(CredMgmt, expected_enumeration)

    total_creds = len(new_rps)

    while total_creds != 0:
        rp = random.choice(list(expected_enumeration.keys()))

        num = expected_enumeration[rp]

        index = 0 if num == 1 else random.randint(0, num - 1)
        cred = CredMgmt.enumerate_creds(sha256(rp.encode("utf8")))[index]

        # print('Delete %d index (%d total) cred of %s' % (index, expected_enumeration[rp], rp))
        CredMgmt.delete_cred({"id": cred[7]["id"], "type": "public-key"})

        expected_enumeration[rp] -= 1
        if expected_enumeration[rp] == 0:
            del expected_enumeration[rp]

        if len(list(expected_enumeration.keys())) == 0:
            break

        enumeration_test(CredMgmt, expected_enumeration)

def _test_wrong_pinauth(device, cmd, PinToken):

    credMgmt = CredMgmtWrongPinAuth(device, PinToken)

    for i in range(2):
        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        cmd(credMgmt)
    assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

    #device.reboot()
    credMgmt = CredMgmtWrongPinAuth(device, PinToken)

    for i in range(2):
        time.sleep(0.2)
        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        cmd(credMgmt)
    assert e.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

    #device.reboot()
    credMgmt = CredMgmtWrongPinAuth(device, PinToken)

    for i in range(1):
        time.sleep(0.2)
        with pytest.raises(CtapError) as e:
            cmd(credMgmt)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID

    with pytest.raises(CtapError) as e:
        cmd(credMgmt)
    assert e.value.code == CtapError.ERR.PIN_BLOCKED
