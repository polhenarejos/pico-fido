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


import os
import struct
import pytest
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.utils import sha256
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from utils import *

PS_ALG_ES256 = -7
PS_ALG_ESP256 = -9
PS_ALG_ESP256_SPLIT_ARKG = -65539
ARKG_KTY = -65537
ARKG_P256_ALG = -65700
FIDO2_ALG_ECDH_ES = -25

RP_ID = "previewsign.example.com"
RP_ID_HASH = sha256(RP_ID.encode())
RP = {"id": RP_ID, "name": "previewSign Test RP"}
USER = {"id": b"ps_test_user", "name": "psuser", "displayName": "PS User"}
KEY_PARAMS = [{"type": "public-key", "alg": PS_ALG_ES256}]

es256_outer_cred_id = None
es256_inner_cred_id = None
es256_inner_pub_key = None
arkg_outer_cred_id = None
arkg_inner_cred_id = None
arkg_seed_key = None


def parse_inner_auth_data(raw):
    """Parse authData bytes into a dict with rpIdHash, flags, counter,
    and optionally attested credential data and extensions."""
    result = {}
    idx = 0
    result["rp_id_hash"] = raw[idx:idx + 32]
    idx += 32
    result["flags"] = raw[idx]
    idx += 1
    result["counter"] = struct.unpack(">I", raw[idx:idx + 4])[0]
    idx += 4

    if result["flags"] & 0x40:
        result["aaguid"] = raw[idx:idx + 16]
        idx += 16
        cred_id_len = struct.unpack(">H", raw[idx:idx + 2])[0]
        idx += 2
        result["credential_id"] = raw[idx:idx + cred_id_len]
        idx += cred_id_len
        cose_data, remaining = cbor.decode_from(raw[idx:])
        result["cose_key"] = cose_data
        idx += len(raw[idx:]) - len(remaining)

    if result["flags"] & 0x80:
        ext_data, remaining = cbor.decode_from(raw[idx:])
        result["extensions"] = ext_data
        idx += len(raw[idx:]) - len(remaining)

    return result


def extract_inner_attestation(att_resp):
    """Extract inner attestation object from MC unsigned extension outputs.
    Returns (inner_cred_id, parsed_inner_auth, att_obj_bytes)."""
    unsigned_ext = None
    try:
        unsigned_ext = att_resp[6]
    except (KeyError, IndexError, TypeError):
        pass
    if not unsigned_ext:
        return None, None, None

    ps_unsigned = unsigned_ext.get("previewSign", {}) if isinstance(unsigned_ext, dict) else {}
    att_obj_bytes = ps_unsigned.get(7)
    if not att_obj_bytes:
        return None, None, None

    inner_att = cbor.decode(att_obj_bytes)
    inner_auth_bytes = inner_att.get(2)
    if not inner_auth_bytes:
        return None, None, att_obj_bytes

    parsed = parse_inner_auth_data(inner_auth_bytes)
    return parsed.get("credential_id"), parsed, att_obj_bytes


def ec_pubkey_from_cose(cose):
    """Convert a COSE ES256 key dict to a cryptography EC public key."""
    x = cose.get(-2) if isinstance(cose, dict) else cose[-2]
    y = cose.get(-3) if isinstance(cose, dict) else cose[-3]
    point = b"\x04" + x + y
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def test_previewsign_info(device):
    ctap2 = device.client()._backend.ctap2
    info = ctap2.get_info()
    assert "previewSign" in info.extensions


def test_previewsign_es256_make_credential(device):
    global es256_outer_cred_id, es256_inner_cred_id, es256_inner_pub_key
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "es256user", "displayName": "ES256 User"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ES256], 4: 1}},
    )["res"]

    auth = att_resp.auth_data
    es256_outer_cred_id = auth.credential_data.credential_id
    assert es256_outer_cred_id is not None

    ext = auth.extensions
    assert ext is not None
    ps_val = ext.get("previewSign")
    assert isinstance(ps_val, dict)
    assert ps_val.get(3) == PS_ALG_ES256
    assert ps_val.get(4) == 1

    es256_inner_cred_id, parsed, _ = extract_inner_attestation(att_resp)
    assert es256_inner_cred_id is not None
    assert es256_inner_cred_id != es256_outer_cred_id

    es256_inner_pub_key = parsed.get("cose_key")
    assert es256_inner_pub_key is not None
    assert es256_inner_pub_key.get(1) == 2
    assert es256_inner_pub_key.get(-1) == 1


def test_previewsign_es256_sign(device):
    assert es256_outer_cred_id is not None
    assert es256_inner_cred_id is not None
    assert es256_inner_pub_key is not None

    payload = os.urandom(100)
    ga_resp = device.GA(
        rp_id=RP_ID,
        allow_list=[{"type": "public-key", "id": es256_outer_cred_id}],
        extensions={"previewSign": {2: es256_inner_cred_id, 6: payload}},
    )["res"]
    ga_ext = ga_resp.auth_data.extensions
    assert ga_ext is not None
    ps_out = ga_ext.get("previewSign")
    assert isinstance(ps_out, dict)
    sig = ps_out.get(6)
    assert sig is not None and len(sig) > 0

    pub = ec_pubkey_from_cose(es256_inner_pub_key)
    pub.verify(sig, payload, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("size", [1, 64, 200])
def test_previewsign_es256_sign_various_sizes(device, size):
    assert es256_outer_cred_id is not None
    assert es256_inner_cred_id is not None
    assert es256_inner_pub_key is not None

    payload = os.urandom(size)
    ga_resp = device.GA(
        rp_id=RP_ID,
        allow_list=[{"type": "public-key", "id": es256_outer_cred_id}],
        extensions={"previewSign": {2: es256_inner_cred_id, 6: payload}},
    )["res"]
    sig = ga_resp.auth_data.extensions.get("previewSign", {}).get(6)
    assert sig is not None

    pub = ec_pubkey_from_cose(es256_inner_pub_key)
    pub.verify(sig, payload, ec.ECDSA(hashes.SHA256()))


def test_previewsign_arkg_make_credential(device):
    global arkg_outer_cred_id, arkg_inner_cred_id, arkg_seed_key
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "arkguser", "displayName": "ARKG User"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ESP256_SPLIT_ARKG], 4: 1}},
    )["res"]

    auth = att_resp.auth_data
    arkg_outer_cred_id = auth.credential_data.credential_id
    outer_aaguid = auth.credential_data.aaguid

    ext = auth.extensions
    assert ext is not None
    ps_signed = ext.get("previewSign")
    assert isinstance(ps_signed, dict)
    assert ps_signed.get(3) == PS_ALG_ESP256_SPLIT_ARKG
    assert ps_signed.get(4) == 1

    arkg_inner_cred_id, parsed, att_obj_bytes = extract_inner_attestation(att_resp)
    assert att_obj_bytes is not None
    assert arkg_inner_cred_id is not None
    assert arkg_inner_cred_id != arkg_outer_cred_id

    assert parsed["rp_id_hash"] == RP_ID_HASH
    assert parsed["flags"] == 0xC1
    assert parsed["counter"] == 0

    inner_aaguid = parsed.get("aaguid")
    assert inner_aaguid == outer_aaguid

    inner_ext = parsed.get("extensions")
    assert inner_ext is not None
    assert "previewSign" in inner_ext
    assert isinstance(inner_ext["previewSign"], dict)
    assert 4 in inner_ext["previewSign"]


def test_previewsign_arkg_cose_key_structure(device):
    assert arkg_inner_cred_id is not None

    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "arkgkey", "displayName": "ARKG Key"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ESP256_SPLIT_ARKG], 4: 1}},
    )["res"]
    _, parsed, _ = extract_inner_attestation(att_resp)
    assert parsed is not None

    cose_key_data = parsed.get("cose_key")
    assert cose_key_data is not None

    seed_key = CoseKey.parse(cose_key_data)
    assert seed_key.get(1) == ARKG_KTY
    assert seed_key.get(3) == ARKG_P256_ALG

    pk_bl = seed_key.get(-1)
    assert isinstance(pk_bl, dict)
    assert pk_bl.get(1) == 2
    assert pk_bl.get(3) == PS_ALG_ES256
    assert pk_bl.get(-1) == 1

    pk_kem = seed_key.get(-2)
    assert isinstance(pk_kem, dict)
    assert pk_kem.get(1) == 2
    assert pk_kem.get(3) == FIDO2_ALG_ECDH_ES
    assert pk_kem.get(-1) == 1

    assert seed_key.get(-3) == PS_ALG_ESP256


def test_previewsign_arkg_sign_verify(device):
    global arkg_seed_key
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "arkgsign", "displayName": "ARKG Sign"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ESP256_SPLIT_ARKG], 4: 1}},
    )["res"]

    outer_cred_id = att_resp.auth_data.credential_data.credential_id
    inner_cred_id, parsed, _ = extract_inner_attestation(att_resp)
    assert inner_cred_id is not None

    cose_key_data = parsed.get("cose_key")
    arkg_seed_key = CoseKey.parse(cose_key_data)

    ikm = os.urandom(32)
    ctx = b"test-arkg-ctx"
    pk_derived, additional_args = arkg_seed_key.derive_public_key(ikm, ctx)

    kh = additional_args.get(-1)
    assert kh is not None and len(kh) == 81

    tbs = sha256(b"ARKG test payload")
    additional_args_cbor = cbor.encode(additional_args)

    ga_resp = device.GA(
        rp_id=RP_ID,
        allow_list=[{"type": "public-key", "id": outer_cred_id}],
        extensions={"previewSign": {2: inner_cred_id, 6: tbs, 7: additional_args_cbor}},
    )["res"]

    ga_ext = ga_resp.auth_data.extensions
    assert ga_ext is not None
    arkg_sig = ga_ext.get("previewSign", {}).get(6)
    assert arkg_sig is not None and len(arkg_sig) > 0

    pk_ec = ec_pubkey_from_cose(pk_derived)
    pk_ec.verify(arkg_sig, tbs, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_previewsign_unsupported_algorithm(device):
    with pytest.raises(CtapError) as e:
        device.MC(
            rp=RP,
            user={"id": os.urandom(16), "name": "erruser", "displayName": "Err"},
            key_params=KEY_PARAMS,
            extensions={"previewSign": {3: [-999], 4: 1}},
        )
    assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


@pytest.mark.parametrize("bad_flags", [2, 3, 4, 6, 7])
def test_previewsign_invalid_flags(device, bad_flags):
    with pytest.raises(CtapError) as e:
        device.MC(
            rp=RP,
            user={"id": os.urandom(16), "name": "erruser", "displayName": "Err"},
            key_params=KEY_PARAMS,
            extensions={"previewSign": {3: [PS_ALG_ES256], 4: bad_flags}},
        )
    assert e.value.code == CtapError.ERR.INVALID_OPTION


def test_previewsign_missing_key_handle(device):
    assert es256_outer_cred_id is not None
    with pytest.raises(CtapError) as e:
        device.GA(
            rp_id=RP_ID,
            allow_list=[{"type": "public-key", "id": es256_outer_cred_id}],
            extensions={"previewSign": {6: b"test-tbs"}},
        )
    assert e.value.code == CtapError.ERR.INVALID_OPTION


def test_previewsign_arkg_missing_additional_args(device):
    assert arkg_outer_cred_id is not None
    assert arkg_inner_cred_id is not None
    with pytest.raises(CtapError) as e:
        device.GA(
            rp_id=RP_ID,
            allow_list=[{"type": "public-key", "id": arkg_outer_cred_id}],
            extensions={"previewSign": {2: arkg_inner_cred_id, 6: sha256(b"test")}},
        )
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER


def test_previewsign_arkg_wrong_alg(device):
    assert arkg_outer_cred_id is not None
    assert arkg_inner_cred_id is not None
    assert arkg_seed_key is not None

    ikm = os.urandom(32)
    ctx = b"wrong-alg-ctx"
    _pk, additional_args = arkg_seed_key.derive_public_key(ikm, ctx)
    bad_args = dict(additional_args)
    bad_args[3] = -7
    bad_args_cbor = cbor.encode(bad_args)

    with pytest.raises(CtapError) as e:
        device.GA(
            rp_id=RP_ID,
            allow_list=[{"type": "public-key", "id": arkg_outer_cred_id}],
            extensions={"previewSign": {2: arkg_inner_cred_id, 6: sha256(b"test"), 7: bad_args_cbor}},
        )
    assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL


def test_previewsign_arkg_corrupt_key_handle(device):
    """Corrupt key handle must return CTAP error (HMAC integrity check)."""
    assert arkg_seed_key is not None

    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "corruptuser", "displayName": "Corrupt"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ESP256_SPLIT_ARKG], 4: 1}},
    )["res"]
    outer_cred_id = att_resp.auth_data.credential_data.credential_id
    inner_cred_id, parsed, _ = extract_inner_attestation(att_resp)
    seed_key = CoseKey.parse(parsed.get("cose_key"))

    ikm = os.urandom(32)
    ctx = b"corrupt-kh-ctx"
    pk_derived, additional_args = seed_key.derive_public_key(ikm, ctx)
    kh = bytearray(additional_args[-1])
    for i in range(16):
        kh[i] ^= 0xFF
    corrupted_args = dict(additional_args)
    corrupted_args[-1] = bytes(kh)
    tbs = sha256(b"corrupt-test")

    with pytest.raises(CtapError) as e:
        device.GA(
            rp_id=RP_ID,
            allow_list=[{"type": "public-key", "id": outer_cred_id}],
            extensions={"previewSign": {2: inner_cred_id, 6: tbs, 7: cbor.encode(corrupted_args)}},
        )
    assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL


@pytest.mark.parametrize("valid_flags", [0, 1, 5])
def test_previewsign_valid_flags(device, valid_flags):
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "flaguser", "displayName": "Flags"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ES256], 4: valid_flags}},
    )["res"]
    assert att_resp.auth_data.credential_data is not None


def test_previewsign_different_credentials_different_inner_ids(device):
    inner_ids = []
    for i in range(2):
        att_resp = device.MC(
            rp=RP,
            user={"id": os.urandom(16), "name": f"detuser{i}", "displayName": f"Det {i}"},
            key_params=KEY_PARAMS,
            extensions={"previewSign": {3: [PS_ALG_ES256], 4: 1}},
        )["res"]
        inner_cred_id, _, _ = extract_inner_attestation(att_resp)
        assert inner_cred_id is not None
        inner_ids.append(inner_cred_id)
    assert inner_ids[0] != inner_ids[1]


def test_previewsign_standard_sig_valid_alongside(device):
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "dualuser", "displayName": "Dual"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ES256], 4: 1}},
    )["res"]
    outer_cred_id = att_resp.auth_data.credential_data.credential_id
    outer_pub_key = att_resp.auth_data.credential_data.public_key
    inner_cred_id, _, _ = extract_inner_attestation(att_resp)
    assert inner_cred_id is not None

    cdh = sha256(os.urandom(32))
    ga_resp = device.GA(
        rp_id=RP_ID,
        client_data_hash=cdh,
        allow_list=[{"type": "public-key", "id": outer_cred_id}],
        extensions={"previewSign": {2: inner_cred_id, 6: b"test-payload"}},
    )["res"]
    std_sig = ga_resp.signature
    assert std_sig is not None and len(std_sig) > 0

    signed_data = bytes(ga_resp.auth_data) + cdh
    outer_pub = ec_pubkey_from_cose(outer_pub_key)
    outer_pub.verify(std_sig, signed_data, ec.ECDSA(hashes.SHA256()))



def test_previewsign_flags_default_up(device):
    """When key 4 (flags) is omitted, default should be UP (1)."""
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "defaultup", "displayName": "Default UP"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ES256]}},
    )["res"]

    ext = att_resp.auth_data.extensions
    assert ext is not None
    ps_val = ext.get("previewSign")
    assert isinstance(ps_val, dict)
    assert ps_val.get(4) == 1  # default should be UP


def test_previewsign_flags_explicit_zero(device):
    """When key 4 is explicitly set to 0, it should remain 0."""
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "zerof", "displayName": "Zero Flags"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ES256], 4: 0}},
    )["res"]

    ext = att_resp.auth_data.extensions
    ps_val = ext.get("previewSign")
    assert ps_val.get(4) == 0


def test_previewsign_arkg_invalid_params_returns_error(device):
    """ARKG with missing key handle should return CTAP error, not empty sig."""
    att_resp = device.MC(
        rp=RP,
        user={"id": os.urandom(16), "name": "badarkguser", "displayName": "Bad ARKG"},
        key_params=KEY_PARAMS,
        extensions={"previewSign": {3: [PS_ALG_ESP256_SPLIT_ARKG], 4: 1}},
    )["res"]
    outer_cred_id = att_resp.auth_data.credential_data.credential_id
    inner_cred_id, _, _ = extract_inner_attestation(att_resp)

    tbs = sha256(b"bad-arkg-test")
    # additional_args with alg but no key handle or context
    bad_args_cbor = cbor.encode({3: PS_ALG_ESP256_SPLIT_ARKG})

    with pytest.raises(CtapError) as e:
        device.GA(
            rp_id=RP_ID,
            allow_list=[{"type": "public-key", "id": outer_cred_id}],
            extensions={"previewSign": {2: inner_cred_id, 6: tbs, 7: bad_args_cbor}},
        )
    assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL
