from fido2.client import CtapError
from fido2.cose import ES256
import pytest


def test_register(device):
    device.reset()
    REGRes,AUTData = device.register()

def test_make_credential():
    pass

def test_attestation_format(MCRes):
        assert MCRes.fmt in ["packed", "tpm", "android-key", "adroid-safetynet"]

def test_authdata_length(MCRes):
    assert len(MCRes.auth_data) >= 77

def test_missing_cdh(device):
    with pytest.raises(CtapError) as e:
        device.MC(client_data_hash=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_cdh(device):
    with pytest.raises(CtapError) as e:
        device.MC(client_data_hash=b'\xff')

def test_missing_user(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_user_user(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user=b"12345678")

def test_missing_rp(device):
    with pytest.raises(CtapError) as e:
        device.MC(rp=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_rp(device):
    with pytest.raises(CtapError) as e:
        device.MC(rp=b"12345678")

def test_missing_pubKeyCredParams(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=None)

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_bad_type_pubKeyCredParams(device):
    with pytest.raises(CtapError) as e:
        device.MC(key_params=b"12345678")

def test_bad_type_excludeList(device):
    with pytest.raises(CtapError) as e:
        device.MC(exclude_list=8)

def test_bad_type_extensions(device):
    with pytest.raises(CtapError) as e:
        device.MC(extensions=8)

def test_bad_type_options(device):
    with pytest.raises(CtapError) as e:
        device.MC(options=8)

def test_bad_type_rp_name(device):
    with pytest.raises(CtapError) as e:
        device.doMC(rp={"id": "test.org", "name": 8, "icon": "icon"})

def test_bad_type_rp_id(device):
    with pytest.raises(CtapError) as e:
        device.doMC(rp={"id": 8, "name": "name", "icon": "icon"})

def test_bad_type_rp_icon(device):
    with pytest.raises(CtapError) as e:
        device.doMC(rp={"id": "test.org", "name": "name", "icon": 8})

def test_bad_type_user_name(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user={"id": b"user_id", "name": 8})

def test_bad_type_user_id(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user={"id": "user_id", "name": "name"})

def test_bad_type_user_displayName(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user={"id": "user_id", "name": "name", "displayName": 8})

def test_bad_type_user_icon(device):
    with pytest.raises(CtapError) as e:
        device.doMC(user={"id": "user_id", "name": "name", "icon": 8})

def test_bad_type_pubKeyCredParams(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=["wrong"])

def test_missing_pubKeyCredParams_type(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=[{"alg": ES256.ALGORITHM}])

    assert e.value.code == CtapError.ERR.MISSING_PARAMETER

def test_missing_pubKeyCredParams_alg(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=[{"type": "public-key"}])

    assert e.value.code in [
        CtapError.ERR.MISSING_PARAMETER,
        CtapError.ERR.UNSUPPORTED_ALGORITHM,
    ]

def test_bad_type_pubKeyCredParams_alg(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=[{"alg": "7", "type": "public-key"}])

def test_unsupported_algorithm(device):
    with pytest.raises(CtapError) as e:
        device.doMC(key_params=[{"alg": 1337, "type": "public-key"}])

    assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM

def test_exclude_list(resetdevice):
    resetdevice.doMC(exclude_list=[{"id": b"1234", "type": "rot13"}])

def test_exclude_list2(resetdevice):
    resetdevice.doMC(exclude_list=[{"id": b"1234", "type": "mangoPapayaCoconutNotAPublicKey"}])

def test_bad_type_exclude_list(device):
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=["1234"])

def test_missing_exclude_list_type(device):
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=[{"id": b"1234"}])

def test_missing_exclude_list_id(device):
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=[{"type": "public-key"}])

def test_bad_type_exclude_list_id(device):
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=[{"type": "public-key", "id": "1234"}])

def test_bad_type_exclude_list_type(device):
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=[{"type": b"public-key", "id": b"1234"}])

def test_exclude_list_excluded(device):
    res = device.doMC().attestation_object
    with pytest.raises(CtapError) as e:
        device.doMC(exclude_list=[
            {"id": res.auth_data.credential_data.credential_id, "type": "public-key"}
        ])

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

def test_unknown_option(resetdevice):
    resetdevice.MC(options={"unknown": False})
