"""
Run this test against externally managed emulator instances in three phases:

1. PICO_FIDO_COMPAT_PHASE=create with the legacy firmware.
2. PICO_FIDO_COMPAT_PHASE=upgrade with the current firmware on the same flash.
3. PICO_FIDO_COMPAT_PHASE=restart after restarting the current firmware.

Use tests/run-test-041-compatibility.sh to automate all three phases.
"""

import hashlib
import hmac
import os
import pickle
import time
from pathlib import Path

import pytest
from fido2.cose import CoseKey
from fido2.ctap2 import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2

from conftest import Device
from utils import send_apdu


PIN = "12345678"
STATE_DIR = Path(os.environ.get("PICO_FIDO_COMPAT_DIR", "/tmp/pico-fido-object-compatibility"))
STATE_FILE = STATE_DIR / "credentials.pickle"
OATH_AID = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
OATH_INS_PUT = 0x01
OATH_INS_RESET = 0x04
OATH_INS_LIST = 0xa1
OATH_INS_CALCULATE = 0xa2
OATH_TAG_NAME = 0x71
OATH_TAG_NAME_LIST = 0x72
OATH_TAG_KEY = 0x73
OATH_TAG_CHALLENGE = 0x74
OATH_TAG_RESPONSE = 0x75
OATH_TOTP_SHA1 = 0x21
OATH_DIGITS = 6
OATH_CHALLENGE = b"\x00\x00\x00\x00\x00\x00\x00\x01"
LEGACY_OATH_NAME = b"legacy-oath"
LEGACY_OATH_KEY = b"legacy-oath-secret"
CONTAINER_OATH_NAME = b"container-oath"
CONTAINER_OATH_KEY = b"container-oath-secret"


def credential_management(device: Device) -> CredentialManagement:
    ctap2 = device.client()._backend.ctap2
    token = ClientPin(ctap2).get_pin_token(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap2, PinProtocolV2(), token)


def assert_credential(device: Device, rp: dict, credential_id: bytes, public_key: dict) -> None:
    response = device.GA(
        rp_id=rp["id"],
        allow_list=[{"id": credential_id, "type": "public-key"}],
    )
    response["res"].verify(response["req"]["client_data_hash"], CoseKey.parse(public_key))


def assert_enumerated_public_key(management: CredentialManagement, rp: dict, public_key: dict) -> None:
    rp_id_hash = hashlib.sha256(rp["id"].encode()).digest()
    credentials = management.enumerate_creds(rp_id_hash)
    assert len(credentials) == 1
    assert dict(credentials[0][CredentialManagement.RESULT.PUBLIC_KEY]) == public_key


def assert_enumerated_rps(management: CredentialManagement, state: dict) -> None:
    records = {
        record[CredentialManagement.RESULT.RP]["id"]: record[CredentialManagement.RESULT.RP_ID_HASH]
        for record in management.enumerate_rps()
    }
    assert records == {
        state["rp"]["id"]: hashlib.sha256(state["rp"]["id"].encode()).digest(),
        state["new_rp"]["id"]: hashlib.sha256(state["new_rp"]["id"].encode()).digest(),
    }


def oath_select(card) -> None:
    send_apdu(card, 0xA4, p1=0x04, p2=0x00, data=OATH_AID)


def oath_put(card, name: bytes, key: bytes) -> None:
    data = [OATH_TAG_NAME, len(name)] + list(name)
    data += [OATH_TAG_KEY, len(key) + 2, OATH_TOTP_SHA1, OATH_DIGITS] + list(key)
    assert send_apdu(card, OATH_INS_PUT, p1=0, p2=0, data=data) == []


def oath_assert_calculation(card, name: bytes, key: bytes) -> None:
    data = [OATH_TAG_NAME, len(name)] + list(name)
    data += [OATH_TAG_CHALLENGE, len(OATH_CHALLENGE)] + list(OATH_CHALLENGE)
    response = send_apdu(card, OATH_INS_CALCULATE, p1=0, p2=0, data=data)
    expected = [OATH_TAG_RESPONSE, hashlib.sha1().digest_size + 1, OATH_DIGITS]
    expected += list(hmac.digest(key, OATH_CHALLENGE, "sha1"))
    assert response == expected


def oath_assert_list(card, credentials: list[tuple[bytes, bytes]]) -> None:
    expected = []
    for name, _ in credentials:
        expected += [OATH_TAG_NAME_LIST, len(name) + 1, OATH_TOTP_SHA1] + list(name)
    assert send_apdu(card, OATH_INS_LIST, p1=0, p2=0) == expected


def create_legacy_state(card) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    device = Device()
    device.reset()
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)

    rp = {"id": "legacy-container-compat.example", "name": "Legacy Compatibility"}
    user = {"id": b"legacy-user", "name": "legacy", "displayName": "Legacy User"}
    registration = device.doMC(rp=rp, user=user, rk=True)["res"].attestation_object
    credential_data = registration.auth_data.credential_data

    assert_credential(device, rp, credential_data.credential_id, dict(credential_data.public_key))
    with STATE_FILE.open("wb") as output:
        pickle.dump(
            {
                "credential_id": credential_data.credential_id,
                "public_key": dict(credential_data.public_key),
                "rp": rp,
                "user": user,
            },
            output,
        )

    oath_select(card)
    send_apdu(card, OATH_INS_RESET, p1=0xde, p2=0xad)
    oath_put(card, LEGACY_OATH_NAME, LEGACY_OATH_KEY)
    oath_assert_list(card, [(LEGACY_OATH_NAME, LEGACY_OATH_KEY)])
    oath_assert_calculation(card, LEGACY_OATH_NAME, LEGACY_OATH_KEY)

    time.sleep(3)


def verify_upgrade(card) -> None:
    with STATE_FILE.open("rb") as source:
        state = pickle.load(source)

    device = Device()
    management = credential_management(device)
    assert_credential(device, state["rp"], state["credential_id"], state["public_key"])
    management = credential_management(device)
    assert_enumerated_public_key(management, state["rp"], state["public_key"])

    new_rp = {"id": "container-compat.example", "name": "Container Compatibility"}
    new_user = {"id": b"container-user", "name": "container", "displayName": "Container User"}
    registration = device.doMC(rp=new_rp, user=new_user, rk=True)["res"].attestation_object
    credential_data = registration.auth_data.credential_data

    assert_credential(device, new_rp, credential_data.credential_id, dict(credential_data.public_key))
    management = credential_management(device)
    assert_enumerated_public_key(management, new_rp, dict(credential_data.public_key))

    state.update(
        {
            "new_credential_id": credential_data.credential_id,
            "new_public_key": dict(credential_data.public_key),
            "new_rp": new_rp,
            "new_user": new_user,
        }
    )
    with STATE_FILE.open("wb") as output:
        pickle.dump(state, output)

    management = credential_management(device)
    assert_enumerated_rps(management, state)

    oath_select(card)
    oath_assert_list(card, [(LEGACY_OATH_NAME, LEGACY_OATH_KEY)])
    oath_assert_calculation(card, LEGACY_OATH_NAME, LEGACY_OATH_KEY)
    oath_put(card, CONTAINER_OATH_NAME, CONTAINER_OATH_KEY)
    credentials = [
        (LEGACY_OATH_NAME, LEGACY_OATH_KEY),
        (CONTAINER_OATH_NAME, CONTAINER_OATH_KEY),
    ]
    oath_assert_list(card, credentials)
    for name, key in credentials:
        oath_assert_calculation(card, name, key)

    time.sleep(3)


def verify_restart(card) -> None:
    with STATE_FILE.open("rb") as source:
        state = pickle.load(source)

    device = Device()
    # The device key is PIN-protected after a process restart.
    credential_management(device)
    for prefix in ("", "new_"):
        assert_credential(device, state[f"{prefix}rp"], state[f"{prefix}credential_id"], state[f"{prefix}public_key"])

    management = credential_management(device)
    for prefix in ("", "new_"):
        assert_enumerated_public_key(management, state[f"{prefix}rp"], state[f"{prefix}public_key"])
    management = credential_management(device)
    assert_enumerated_rps(management, state)

    oath_select(card)
    credentials = [
        (LEGACY_OATH_NAME, LEGACY_OATH_KEY),
        (CONTAINER_OATH_NAME, CONTAINER_OATH_KEY),
    ]
    oath_assert_list(card, credentials)
    for name, key in credentials:
        oath_assert_calculation(card, name, key)


def test_legacy_and_container_records_survive_upgrade_and_restart(ccid_card) -> None:
    phase = os.environ.get("PICO_FIDO_COMPAT_PHASE")
    if phase == "create":
        create_legacy_state(ccid_card)
    elif phase == "upgrade":
        verify_upgrade(ccid_card)
    elif phase == "restart":
        verify_restart(ccid_card)
    else:
        pytest.skip("set PICO_FIDO_COMPAT_PHASE to create, upgrade, or restart")
