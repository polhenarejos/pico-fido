from fido2.attestation import FidoU2FAttestation

# Test U2F register works with FIDO2 auth
def test_ctap1_register(RegRes):
    pass

def test_ctap1_authenticate(RegRes, AuthRes):
    pass

def test_authenticate_ctap1_through_ctap2(device, RegRes):
    res = device.doGA(allow_list=[
            {"id": RegRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ])
    assert res['res'].get_response(0).credential_id == RegRes['res'].attestation_object.auth_data.credential_data.credential_id


# Test FIDO2 register works with U2F auth
def test_ctap1_authenticate_attestation(MCRes, device):
    key_handle = MCRes['res'].attestation_object.auth_data.credential_data.credential_id
    if len(key_handle) <= 255:
        res = device.doGA(ctap1=True,allow_list=[
            {"id": key_handle, "type": "public-key"}
        ])
    else:
        print("ctap2 credId is longer than 255 bytes, cannot use with U2F.")
