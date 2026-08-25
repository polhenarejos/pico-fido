import base64
import hashlib
import json
import os
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CTAPHID


VAULT_MAGIC = b"PKV1"
VAULT_ID_DOMAIN = b"PicoKeys Vault ID v1"
ENROLL_INFO = b"PicoKeys Vault enrollment v1"
VAULT_ID_BYTES = 32
VAULT_ENROLL_CHALLENGE_BYTES = 32
SERIAL_MAX = 16
SERIAL_LEN_OFFSET = 4 + VAULT_ID_BYTES + VAULT_ID_BYTES
SERIAL_OFFSET = SERIAL_LEN_OFFSET + 1
ALGORITHM_OFFSET = SERIAL_OFFSET + SERIAL_MAX
HEADER_LEN = ALGORITHM_OFFSET + 1
NONCE_BYTES = 12
LABEL_MAX = 64
ALGORITHMS = {1: "chachapoly", 2: "aesgcm", 3: "chachapoly+aesgcm", 4: "aesgcm+chachapoly"}
DEFAULT_ENROLLMENT = Path.home() / ".config" / "PicoKeys" / "vault" / "enrollment-35d3ddbcebc9-Test.json"
VAULT_STATUS = 0x01
VAULT_ENROLL_BEGIN = 0x02
VAULT_ENROLL_FINISH = 0x03
VAULT_EXPORT = 0x04
VAULT_IMPORT = 0x05
VAULT_UNENROLL = 0x06


def _vault_id(kvault):
    return hashlib.sha256(VAULT_ID_DOMAIN + kvault).digest()


def _derive_passphrase(passphrase, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024).derive(passphrase.encode())


def _create_enrollment(passphrase, kvault, private_key, label):
    salt = bytes(range(16))
    nonce = bytes(range(12))
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    plain = json.dumps({"version": 1, "kvault": base64.b64encode(kvault).decode(), "x448_private": base64.b64encode(private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode(), "label": label, "vault_id": _vault_id(kvault).hex()}, separators=(",", ":")).encode()
    ciphertext = AESGCM(_derive_passphrase(passphrase, salt)).encrypt(nonce, plain, b"PicoKeys Kvault envelope v1")
    return {"version": 1, "label": label, "vault_id": _vault_id(kvault).hex(), "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode(), "public_key": base64.b64encode(public_key).decode()}


def _open_enrollment(value, passphrase):
    salt = base64.b64decode(value["salt"])
    nonce = base64.b64decode(value["nonce"])
    plain = AESGCM(_derive_passphrase(passphrase, salt)).decrypt(nonce, base64.b64decode(value["ciphertext"]), b"PicoKeys Kvault envelope v1")
    return json.loads(plain)


def _enrollment_packet(certificate, private_key, device_public, challenge, kvault, label):
    certificate_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = ENROLL_INFO + challenge + certificate_public + device_public
    shared = private_key.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    label_bytes = label.encode()
    if len(label_bytes) > LABEL_MAX:
        raise ValueError("vault label is too long")
    plain = kvault + bytes([len(label_bytes)]) + label_bytes
    nonce = os.urandom(12)
    return struct.pack(">H", len(certificate)) + certificate + nonce + AESGCM(session_key).encrypt(nonce, plain, info)


def _aead(algorithm, key, encrypt, nonce, data, aad):
    cipher = ChaCha20Poly1305(key) if algorithm == 1 else AESGCM(key)
    if encrypt:
        return cipher.encrypt(nonce, data, aad)
    return cipher.decrypt(nonce, data, aad)


def _layer_algorithm(algorithm, index):
    if algorithm == 3:
        return (1, 2)[index]
    if algorithm == 4:
        return (2, 1)[index]
    return algorithm


def _layer_key(kvault, vault_id, credential_hash, algorithm, layer):
    info = ENROLL_INFO + credential_hash + bytes([algorithm, layer])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=vault_id, info=info).derive(kvault)


def _export_blob(kvault, credential_id, algorithm, serial=b"0123456789ABCDEF"):
    if algorithm not in ALGORITHMS or len(serial) > SERIAL_MAX:
        raise ValueError("invalid blob parameters")
    vault_id = _vault_id(kvault)
    credential_hash = hashlib.sha256(credential_id).digest()
    header = VAULT_MAGIC + vault_id + credential_hash + bytes([len(serial)]) + serial.ljust(SERIAL_MAX, b"\0") + bytes([algorithm])
    rp_id = "example.com"
    metadata = cbor.encode({1: rp_id, 2: hashlib.sha256(rp_id.encode()).digest(), 6: 0, 8: False})
    plain = cbor.encode({1: 1, 2: credential_id, 3: (1).to_bytes(32, "big"), 4: rp_id, 5: metadata, 6: credential_id})
    layers = 2 if algorithm >= 3 else 1
    nonces = b"".join(bytes([algorithm, layer]) + b"\0" * (NONCE_BYTES - 2) for layer in range(layers))
    encrypted = plain
    for layer in range(layers):
        encrypted = _aead(_layer_algorithm(algorithm, layer), _layer_key(kvault, vault_id, credential_hash, algorithm, layer), True, nonces[layer * NONCE_BYTES:(layer + 1) * NONCE_BYTES], encrypted, header)
    return header + nonces + encrypted


def _import_blob(kvault, blob):
    assert blob[:4] == VAULT_MAGIC
    algorithm = blob[ALGORITHM_OFFSET]
    assert algorithm in ALGORITHMS
    layers = 2 if algorithm >= 3 else 1
    vault_id = blob[4:4 + VAULT_ID_BYTES]
    credential_hash = blob[4 + VAULT_ID_BYTES:4 + 2 * VAULT_ID_BYTES]
    nonces = blob[HEADER_LEN:HEADER_LEN + layers * NONCE_BYTES]
    encrypted = blob[HEADER_LEN + layers * NONCE_BYTES:]
    for layer in range(layers - 1, -1, -1):
        encrypted = _aead(_layer_algorithm(algorithm, layer), _layer_key(kvault, vault_id, credential_hash, algorithm, layer), False, nonces[layer * NONCE_BYTES:(layer + 1) * NONCE_BYTES], encrypted, blob[:HEADER_LEN])
    return cbor.decode(encrypted)


def _vendor_call(device, subcommand, params=None, pin=None):
    arguments = {1: subcommand}
    raw_params = cbor.encode(params) if params is not None else b""
    if params is not None:
        arguments[2] = params
    if pin is not None:
        protocol, token = pin
        arguments[3] = protocol.VERSION
        arguments[4] = protocol.authenticate(token, b"\xff" * 32 + b"\x0d" + bytes([subcommand]) + raw_params)
    try:
        response = device.dev.call(CTAPHID.VENDOR_FIRST + 1, bytes([0x05]) + cbor.encode(arguments))
    except CtapError as error:
        return error.code, {}
    return response[0], cbor.decode(response[1:]) if len(response) > 1 else {}


def _live_device(request):
    return request.getfixturevalue("device")


def _live_pin(device):
    pin = os.environ.get("PICO_FIDO_VAULT_PIN") or "12345678"
    protocol = PinProtocolV2()
    client_pin = ClientPin(Ctap2(device.dev), protocol)
    try:
        token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG | ClientPin.PERMISSION.CREDENTIAL_MGMT)
    except Exception as error:
        if not isinstance(error, CtapError) or error.code != CtapError.ERR.PIN_NOT_SET:
            pytest.fail(f"live PIN unavailable: {error}")
        try:
            client_pin.set_pin(pin)
            token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG | ClientPin.PERMISSION.CREDENTIAL_MGMT)
        except Exception as setup_error:
            pytest.fail(f"could not initialize live PIN: {setup_error}")
    return protocol, token


def _live_enrollment(device):
    enrollment_json = os.environ.get("PICO_FIDO_VAULT_ENROLLMENT_JSON")
    if enrollment_json:
        try:
            value = json.loads(enrollment_json)
        except json.JSONDecodeError as error:
            pytest.fail(f"invalid PICO_FIDO_VAULT_ENROLLMENT_JSON: {error}")
    else:
        path = Path(os.environ.get("PICO_FIDO_VAULT_ENROLLMENT", str(DEFAULT_ENROLLMENT)))
        if not path.is_file():
            pytest.fail(f"enrollment JSON does not exist: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    passphrase = os.environ.get("PICO_FIDO_VAULT_PASSPHRASE") or "test"
    plain = _open_enrollment(value, passphrase)
    kvault = base64.b64decode(plain["kvault"])
    private_key = x448.X448PrivateKey.from_private_bytes(base64.b64decode(plain["x448_private"]))
    certificate = base64.b64decode(plain["certificate"])
    certificate_object = x509.load_der_x509_certificate(certificate)
    certificate_public = certificate_object.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert certificate_public == private_public
    assert _vault_id(kvault).hex() == plain["vault_id"]

    pin = _live_pin(device)
    code, response = _vendor_call(device, VAULT_ENROLL_BEGIN, pin=pin)
    assert code == 0, f"Vault enrollment begin failed: 0x{code:02x} {response!r}"
    device_public = response.get(1, b"")
    challenge = response.get(2, b"")
    assert len(device_public) == 56
    assert len(challenge) == VAULT_ENROLL_CHALLENGE_BYTES
    packet = _enrollment_packet(certificate, private_key, device_public, challenge, kvault, plain.get("label", ""))
    code, response = _vendor_call(device, VAULT_ENROLL_FINISH, {1: packet}, pin)
    if code != 0:
        try:
            san = certificate_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            certificate_sans = [name.value for name in san]
        except x509.ExtensionNotFound:
            certificate_sans = []
        device_serial = getattr(getattr(device.dev, "descriptor", None), "serial_number", None)
        pytest.fail(f"Vault enrollment finish failed: 0x{code:02x} {response!r}; device_serial={device_serial!r}; certificate_sans={certificate_sans!r}")
    assert response.get(1) == _vault_id(kvault)
    return pin


def test_vault_id_is_deterministic_and_256_bit():
    kvault = bytes(range(32))
    assert _vault_id(kvault) == _vault_id(kvault)
    assert len(_vault_id(kvault)) == VAULT_ID_BYTES
    assert _vault_id(kvault) != _vault_id(bytes(range(1, 33)))


def test_create_and_open_enrollment_json():
    value = _create_enrollment("correct horse", bytes(range(32)), x448.X448PrivateKey.generate(), "test vault")
    plain = _open_enrollment(value, "correct horse")
    assert plain["vault_id"] == value["vault_id"]
    assert plain["label"] == "test vault"
    assert len(base64.b64decode(plain["kvault"])) == 32


def test_wrong_enrollment_passphrase_is_rejected():
    value = _create_enrollment("correct horse", os.urandom(32), x448.X448PrivateKey.generate(), "")
    with pytest.raises(InvalidTag):
        _open_enrollment(value, "wrong horse")


def test_tampered_enrollment_json_is_rejected():
    value = _create_enrollment("secret", os.urandom(32), x448.X448PrivateKey.generate(), "")
    value["ciphertext"] = base64.b64encode(bytes([base64.b64decode(value["ciphertext"])[0] ^ 1]) + base64.b64decode(value["ciphertext"])[1:]).decode()
    with pytest.raises(InvalidTag):
        _open_enrollment(value, "secret")


@pytest.mark.parametrize("label", ["", "A" * LABEL_MAX])
def test_enrollment_packet_accepts_label_boundaries(label):
    private_key = x448.X448PrivateKey.generate()
    device_private = x448.X448PrivateKey.generate()
    packet = _enrollment_packet(b"certificate", private_key, device_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), bytes(range(32)), bytes(range(32)), label)
    assert int.from_bytes(packet[:2], "big") == len(b"certificate")
    assert packet[2 + len(b"certificate") + 12:]


def test_enrollment_packet_rejects_oversized_label_before_encryption():
    label = "A" * (LABEL_MAX + 1)
    with pytest.raises(ValueError):
        _enrollment_packet(b"certificate", x448.X448PrivateKey.generate(), x448.X448PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), bytes(32), bytes(32), label)


def test_enrollment_packet_tampering_fails_authentication():
    private_key = x448.X448PrivateKey.generate()
    device_private = x448.X448PrivateKey.generate()
    challenge = bytes(range(32))
    kvault = bytes(range(32))
    packet = _enrollment_packet(b"certificate", private_key, device_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), challenge, kvault, "label")
    packet = bytearray(packet)
    packet[-1] ^= 1
    certificate_len = int.from_bytes(packet[:2], "big")
    device_public = device_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    certificate_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = ENROLL_INFO + challenge + certificate_public + device_public
    shared = private_key.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    with pytest.raises(InvalidTag):
        AESGCM(session_key).decrypt(bytes(packet[2 + certificate_len:2 + certificate_len + 12]), bytes(packet[2 + certificate_len + 12:]), info)


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_export_import_roundtrip_for_every_algorithm(algorithm):
    kvault = bytes(range(32))
    credential_id = b"credential-id"
    blob = _export_blob(kvault, credential_id, algorithm)
    assert blob[:4] == VAULT_MAGIC
    assert blob[ALGORITHM_OFFSET] == algorithm
    assert blob[SERIAL_LEN_OFFSET] == SERIAL_MAX
    assert blob[SERIAL_OFFSET:SERIAL_OFFSET + SERIAL_MAX] == b"0123456789ABCDEF"
    plain = _import_blob(kvault, blob)
    assert plain[1] == 1
    assert plain[2] == credential_id
    assert hashlib.sha256(plain[6]).digest() == blob[4 + VAULT_ID_BYTES:4 + 2 * VAULT_ID_BYTES]
    metadata = cbor.decode(plain[5])
    assert metadata[1] == plain[4]
    assert metadata[2] == hashlib.sha256(plain[4].encode()).digest()


def test_blob_header_is_authenticated():
    blob = bytearray(_export_blob(bytes(range(32)), b"credential-id", 1))
    blob[SERIAL_OFFSET] ^= 1
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(32)), bytes(blob))


def test_blob_ciphertext_is_authenticated():
    blob = bytearray(_export_blob(bytes(range(32)), b"credential-id", 1))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(32)), bytes(blob))


def test_blob_wrong_vault_key_is_rejected():
    blob = _export_blob(bytes(range(32)), b"credential-id", 1)
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(1, 33)), blob)


@pytest.mark.parametrize("blob", [b"", b"PKV", b"PKV2" + b"\0" * HEADER_LEN, VAULT_MAGIC + b"\0" * (HEADER_LEN - 1)])
def test_malformed_blob_is_rejected(blob):
    with pytest.raises((AssertionError, IndexError, ValueError)):
        _import_blob(bytes(32), blob)


def test_blob_serial_length_is_bounded():
    with pytest.raises(ValueError):
        _export_blob(bytes(32), b"credential-id", 1, b"A" * (SERIAL_MAX + 1))


def test_blob_algorithm_is_bounded():
    with pytest.raises(ValueError):
        _export_blob(bytes(32), b"credential-id", 0)


@pytest.mark.vault_live
def test_live_vault_status_contract(request):
    device = _live_device(request)
    code, status = _vendor_call(device, VAULT_STATUS)
    assert code == 0
    assert isinstance(status.get(1, b""), bytes)
    assert len(status.get(1, b"")) in (0, VAULT_ID_BYTES)


@pytest.mark.vault_live
def test_live_vault_commands_require_pin(request):
    device = _live_device(request)
    for subcommand, params in ((VAULT_ENROLL_BEGIN, None), (VAULT_EXPORT, {1: b"credential-id"}), (VAULT_IMPORT, {1: b"blob"}), (VAULT_UNENROLL, None)):
        code, _ = _vendor_call(device, subcommand, params)
        assert code != 0


@pytest.mark.vault_live
def test_live_enrollment_begin_is_available_without_hardware_button(request):
    device = _live_device(request)
    pin = _live_pin(device)
    code, response = _vendor_call(device, VAULT_ENROLL_BEGIN, pin=pin)
    assert code == 0
    assert len(response.get(1, b"")) == 56
    assert len(response.get(2, b"")) == VAULT_ENROLL_CHALLENGE_BYTES
    code, _ = _vendor_call(device, VAULT_ENROLL_FINISH, {1: b"\0"}, pin)
    assert code != 0


@pytest.mark.vault_live
def test_live_enrollment_finish_rejects_malformed_packet(request):
    device = _live_device(request)
    pin = _live_pin(device)
    code, _ = _vendor_call(device, VAULT_ENROLL_BEGIN, pin=pin)
    assert code == 0
    code, _ = _vendor_call(device, VAULT_ENROLL_FINISH, {1: b"\0"}, pin)
    assert code != 0


@pytest.mark.vault_live
def test_live_unknown_vault_subcommand_is_rejected(request):
    device = _live_device(request)
    code, _ = _vendor_call(device, 0x07)
    assert code != 0


@pytest.mark.vault_live
def test_live_export_import_roundtrip(request):
    device = _live_device(request)
    pin = _live_enrollment(device)
    rp_id = "vault-test-" + os.urandom(6).hex() + ".example"
    result = device.doMC(rp={"id": rp_id, "name": rp_id}, user={"id": os.urandom(16), "name": "vault-test", "displayName": "Vault Test"}, rk=True)
    credential_id = result["res"].attestation_object.auth_data.credential_data.credential_id
    pin = _live_pin(device)
    blobs = {}
    for algorithm in sorted(ALGORITHMS):
        code, response = _vendor_call(device, VAULT_EXPORT, {1: credential_id, 3: algorithm}, pin)
        assert code == 0, f"Vault export failed for algorithm {algorithm}: 0x{code:02x} {response!r}"
        blob = response[1]
        assert blob[ALGORITHM_OFFSET] == algorithm
        blobs[algorithm] = blob
    ctap2 = Ctap2(device.dev)
    credential_management = CredentialManagement(ctap2, pin[0], pin[1])
    descriptor = {"id": credential_id, "type": "public-key"}
    for algorithm in sorted(ALGORITHMS):
        credential_management.delete_cred(descriptor)
        code, _ = _vendor_call(device, VAULT_IMPORT, {1: blobs[algorithm]}, pin)
        assert code == 0, f"Vault import failed for algorithm {algorithm}: 0x{code:02x}"
        credentials = credential_management.enumerate_creds(hashlib.sha256(rp_id.encode()).digest())
        assert any((entry.get(CredentialManagement.RESULT.CREDENTIAL_ID) or {}).get("id") == credential_id for entry in credentials)
    credential_management.delete_cred(descriptor)


@pytest.mark.vault_live
@pytest.mark.vault_destructive
def test_live_unenroll_requires_explicit_opt_in(request):
    device = _live_device(request)
    is_emulation = getattr(getattr(device.dev, "descriptor", None), "serial_number", None) == "AAAAAA"
    if not is_emulation and os.environ.get("PICO_FIDO_VAULT_DESTRUCTIVE_TESTS") != "1":
        pytest.skip("set PICO_FIDO_VAULT_DESTRUCTIVE_TESTS=1 to erase the device vault")
    pin = _live_pin(device)
    code, _ = _vendor_call(device, VAULT_UNENROLL, pin=pin)
    assert code == 0
    code, status = _vendor_call(device, VAULT_STATUS)
    assert code == 0
    assert status.get(1, b"") == b""
