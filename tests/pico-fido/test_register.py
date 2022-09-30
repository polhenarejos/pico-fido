from fido2.client import CtapError
import pytest


def test_register(device):
    device.reset()
    REGRes,AUTData = device.register()

def test_make_credential(device, MCRes):
    pass

def test_attestation_format(device, MCRes):
        assert MCRes.fmt in ["packed", "tpm", "android-key", "adroid-safetynet"]

def test_authdata_length(device, MCRes):
    assert len(MCRes.auth_data) >= 77

def test_missing_cdh(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.MC(client_data_hash=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_cdh(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.MC(client_data_hash=b'\xff')

def test_missing_user(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.MC(user=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_user_user(device, MCRes):
    with pytest.raises(CtapError) as e:
        device.MC(user=b"12345678")

def test_missing_rp(device, MCRes):
    req = FidoRequest(MCRes, rp=None)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_rp(device, MCRes):
    req = FidoRequest(MCRes, rp=b"1234abcdef")

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_missing_pubKeyCredParams(device, MCRes):
    req = FidoRequest(MCRes, key_params=None)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_pubKeyCredParams(device, MCRes):
    req = FidoRequest(MCRes, key_params=b"1234a")

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_excludeList(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=8)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_extensions(device, MCRes):
    req = FidoRequest(MCRes, extensions=8)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_options(device, MCRes):
    req = FidoRequest(MCRes, options=8)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_rp_name(device, MCRes):
    req = FidoRequest(MCRes, rp={"id": "test.org", "name": 8, "icon": "icon"})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_rp_id(device, MCRes):
    req = FidoRequest(MCRes, rp={"id": 8, "name": "name", "icon": "icon"})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_rp_icon(device, MCRes):
    req = FidoRequest(MCRes, rp={"id": "test.org", "name": "name", "icon": 8})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_user_name(device, MCRes):
    req = FidoRequest(MCRes, user={"id": b"user_id", "name": 8})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_user_id(device, MCRes):
    req = FidoRequest(MCRes, user={"id": "user_id", "name": "name"})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_user_displayName(device, MCRes):
    req = FidoRequest(
        MCRes, user={"id": "user_id", "name": "name", "displayName": 8}
    )

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_user_icon(device, MCRes):
    req = FidoRequest(MCRes, user={"id": "user_id", "name": "name", "icon": 8})

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_pubKeyCredParams(device, MCRes):
    req = FidoRequest(MCRes, key_params=["wrong"])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_missing_pubKeyCredParams_type(device, MCRes):
    req = FidoRequest(MCRes, key_params=[{"alg": ES256.ALGORITHM}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_missing_pubKeyCredParams_alg(device, MCRes):
    req = FidoRequest(MCRes, key_params=[{"type": "public-key"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code in [
        CtapError.ERR.MISSING_PARAMETER,
        CtapError.ERR.UNSUPPORTED_ALGORITHM,
    ]

def test_bad_type_pubKeyCredParams_alg(device, MCRes):
    req = FidoRequest(MCRes, key_params=[{"alg": "7", "type": "public-key"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_unsupported_algorithm(device, MCRes):
    req = FidoRequest(MCRes, key_params=[{"alg": 1337, "type": "public-key"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM

def test_exclude_list(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=[{"id": b"1234", "type": "rot13"}])

    device.sendMC(*req.toMC())

def test_exclude_list2(device, MCRes):
    req = FidoRequest(
        MCRes,
        exclude_list=[{"id": b"1234", "type": "mangoPapayaCoconutNotAPublicKey"}],
    )

    device.sendMC(*req.toMC())

def test_bad_type_exclude_list(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=["1234"])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_missing_exclude_list_type(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=[{"id": b"1234"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_missing_exclude_list_id(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=[{"type": "public-key"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_exclude_list_id(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=[{"type": "public-key", "id": "1234"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_bad_type_exclude_list_type(device, MCRes):
    req = FidoRequest(MCRes, exclude_list=[{"type": b"public-key", "id": b"1234"}])

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

def test_exclude_list_excluded(device, MCRes, GARes):
    req = FidoRequest(MCRes, exclude_list=GARes.request.allow_list)

    with pytest.raises(CtapError) as e:
        device.sendMC(*req.toMC())

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

def test_unknown_option(device, MCRes):
    req = FidoRequest(MCRes, options={"unknown": False})
    print("MC", req.toMC())
    device.sendMC(*req.toMC())

def test_eddsa(device):
    mc_req = FidoRequest(
        key_params=[{"type": "public-key", "alg": EdDSA.ALGORITHM}]
    )
    try:
        mc_res = device.sendMC(*mc_req.toMC())
    except CtapError as e:
        if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
            print("ed25519 is not supported.  Skip this test.")
            return

    setattr(mc_res, "request", mc_req)

    allow_list = [
        {
            "id": mc_res.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    ga_req = FidoRequest(allow_list=allow_list)
    ga_res = device.sendGA(*ga_req.toGA())
    setattr(ga_res, "request", ga_req)

    try:
        verify(mc_res, ga_res)
    except:
        # Print out extra details on failure
        from binascii import hexlify

        print("authdata", hexlify(ga_res.auth_data))
        print("cdh", hexlify(ga_res.request.cdh))
        print("sig", hexlify(ga_res.signature))
        from fido2.ctap2 import AttestedCredentialData

        credential_data = AttestedCredentialData(mc_res.auth_data.credential_data)
        print("public key:", hexlify(credential_data.public_key[-2]))
        verify(mc_res, ga_res)
