"""
Run this test against externally managed emulator instances in three phases:

1. PICO_FIDO_COMPAT_PHASE=create with the legacy firmware.
2. PICO_FIDO_COMPAT_PHASE=upgrade with the current firmware on the same flash.
3. PICO_FIDO_COMPAT_PHASE=restart after restarting the current firmware.

Use tests/run-test-041-compatibility.sh to automate all three phases.
"""

import hashlib
import os
import pickle
import time
from pathlib import Path

import pytest
from fido2.cose import CoseKey
from fido2.ctap2 import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2

from conftest import Device


PIN = "12345678"
STATE_DIR = Path(os.environ.get("PICO_FIDO_COMPAT_DIR", "/tmp/pico-fido-object-compatibility"))
STATE_FILE = STATE_DIR / "credentials.pickle"


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


def create_legacy_state() -> None:
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

    time.sleep(3)


def verify_upgrade() -> None:
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
    time.sleep(3)


def verify_restart() -> None:
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


def test_legacy_and_container_records_survive_upgrade_and_restart() -> None:
    phase = os.environ.get("PICO_FIDO_COMPAT_PHASE")
    if phase == "create":
        create_legacy_state()
    elif phase == "upgrade":
        verify_upgrade()
    elif phase == "restart":
        verify_restart()
    else:
        pytest.skip("set PICO_FIDO_COMPAT_PHASE to create, upgrade, or restart")
