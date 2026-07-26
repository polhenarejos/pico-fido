"""
Exercise silent credential authentication after a process restart.

Run the create and verify phases with tests/run-test-042-silent-authentication.sh
so both phases use the same flash image and the verify phase starts without the
PIN-derived device-key session in RAM.
"""

import os
import pickle
import time
from pathlib import Path

import pytest
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import AssertionResponse
from fido2.ctap2.pin import ClientPin

from conftest import Device


PIN = "12345678"
STATE_DIR = Path(os.environ.get("PICO_FIDO_SILENT_DIR", "/tmp/pico-fido-silent-authentication"))
STATE_FILE = STATE_DIR / "credentials.pickle"
SILENT_CREDENTIAL_ID = b"\x00\x01" * 8
SILENT_SIGNATURE = b"\x0b" * 64
AUTH_DATA_FLAG_UP = 0x01
AUTH_DATA_FLAG_UV = 0x04
CRED_PROTO_LEN = 4
CRED_IV_LEN = 12
CRED_TAG_LEN = 16
CRED_SILENT_TAG_LEN = 16
CRED_CIPHERTEXT_OFFSET = CRED_PROTO_LEN + CRED_IV_LEN


def create_credential(device: Device, rp: dict, user: dict, resident: bool) -> dict:
    registration = device.doMC(rp=rp, user=user, rk=resident)["res"].attestation_object
    credential_data = registration.auth_data.credential_data
    return {
        "credential_id": credential_data.credential_id,
        "public_key": dict(credential_data.public_key),
        "rp": rp,
        "user": user,
    }


def create_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    device = Device()
    device.reset()
    ClientPin(device.client()._backend.ctap2).set_pin(PIN)

    state = {
        "nonresident": create_credential(
            device,
            {"id": "silent-nonresident.example", "name": "Silent Nonresident"},
            {"id": b"silent-nonresident", "name": "nonresident", "displayName": "Silent Nonresident"},
            False,
        ),
        "resident": create_credential(
            device,
            {"id": "silent-resident.example", "name": "Silent Resident"},
            {"id": b"silent-resident", "name": "resident", "displayName": "Silent Resident"},
            True,
        ),
    }

    nonresident_id = state["nonresident"]["credential_id"]
    assert len(nonresident_id) > CRED_CIPHERTEXT_OFFSET + CRED_TAG_LEN + CRED_SILENT_TAG_LEN

    with STATE_FILE.open("wb") as output:
        pickle.dump(state, output)

    time.sleep(3)


def silent_assertion(device: Device, credential: dict) -> AssertionResponse:
    response = device.GA(
        rp_id=credential["rp"]["id"],
        options={"up": False},
        allow_list=[{"id": credential["credential_id"], "type": "public-key"}],
    )["res"]

    assert response.auth_data.flags & AUTH_DATA_FLAG_UP == 0
    assert response.auth_data.flags & AUTH_DATA_FLAG_UV == 0
    assert response.credential["id"] == SILENT_CREDENTIAL_ID
    assert response.signature == SILENT_SIGNATURE
    return response


def assert_silent_rejected(device: Device, rp_id: str, credential_id: bytes) -> None:
    with pytest.raises(CtapError) as error:
        device.GA(
            rp_id=rp_id,
            options={"up": False},
            allow_list=[{"id": credential_id, "type": "public-key"}],
        )

    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def verify_state() -> None:
    with STATE_FILE.open("rb") as source:
        state = pickle.load(source)

    device = Device()

    # These assertions must run before any PIN operation in this process.
    silent_assertion(device, state["nonresident"])
    silent_assertion(device, state["resident"])

    credential_id = state["nonresident"]["credential_id"]
    tamper_offsets = {
        "ciphertext": CRED_CIPHERTEXT_OFFSET,
        "aead_tag": -CRED_SILENT_TAG_LEN - 1,
        "silent_tag": -1,
    }
    for offset in tamper_offsets.values():
        corrupted = bytearray(credential_id)
        corrupted[offset] ^= 1
        assert_silent_rejected(device, state["nonresident"]["rp"]["id"], bytes(corrupted))

    assert_silent_rejected(device, "wrong-silent-rp.example", credential_id)

    resident_id = state["resident"]["credential_id"]
    corrupted_resident_id = bytearray(resident_id)
    corrupted_resident_id[-1] ^= 1
    assert_silent_rejected(device, state["resident"]["rp"]["id"], bytes(corrupted_resident_id))
    assert_silent_rejected(device, "wrong-silent-resident-rp.example", resident_id)

    # Unlock the device key and prove both credentials still produce real,
    # verifiable assertions after the tag-only checks.
    ClientPin(device.client()._backend.ctap2).get_pin_token(PIN)
    for credential in state.values():
        response = device.GA(
            rp_id=credential["rp"]["id"],
            allow_list=[{"id": credential["credential_id"], "type": "public-key"}],
        )
        assert response["res"].credential["id"] == credential["credential_id"]
        assert response["res"].signature != SILENT_SIGNATURE
        response["res"].verify(response["req"]["client_data_hash"], CoseKey.parse(credential["public_key"]))


def test_silent_authentication_survives_restart_without_pin() -> None:
    phase = os.environ.get("PICO_FIDO_SILENT_PHASE")
    if phase == "create":
        create_state()
    elif phase == "verify":
        verify_state()
    else:
        pytest.skip("set PICO_FIDO_SILENT_PHASE to create or verify")
