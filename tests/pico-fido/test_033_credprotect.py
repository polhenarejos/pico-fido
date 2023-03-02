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


import pytest
from fido2.ctap2.extensions import CredProtectExtension
from fido2.webauthn import UserVerificationRequirement
from fido2.ctap import CtapError

class CredProtect:
    UserVerificationOptional = 1
    UserVerificationOptionalWithCredentialId = 2
    UserVerificationRequired = 3

@pytest.fixture(scope="class")
def MCCredProtectOptional(resetdevice):
    res = resetdevice.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.OPTIONAL})['res'].attestation_object
    return res

@pytest.fixture(scope="class")
def MCCredProtectOptionalList(resetdevice):
    res = resetdevice.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.OPTIONAL_WITH_LIST})['res'].attestation_object
    return res

@pytest.fixture(scope="class")
def MCCredProtectRequired(resetdevice):
    res = resetdevice.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.REQUIRED})['res'].attestation_object
    return res


def test_credprotect_make_credential_1(MCCredProtectOptional):
    assert MCCredProtectOptional.auth_data.extensions
    assert "credProtect" in MCCredProtectOptional.auth_data.extensions
    assert MCCredProtectOptional.auth_data.extensions["credProtect"] == 1

def test_credprotect_make_credential_2(MCCredProtectOptionalList):
    assert MCCredProtectOptionalList.auth_data.extensions
    assert "credProtect" in MCCredProtectOptionalList.auth_data.extensions
    assert MCCredProtectOptionalList.auth_data.extensions["credProtect"] == 2

def test_credprotect_make_credential_3(MCCredProtectRequired):
    assert MCCredProtectRequired.auth_data.extensions
    assert "credProtect" in MCCredProtectRequired.auth_data.extensions
    assert MCCredProtectRequired.auth_data.extensions["credProtect"] == 3

def test_credprotect_optional_excluded(device, MCCredProtectOptional):
    """ CredProtectOptional Cred should be visible to be excluded with no UV """
    exclude_list = [
        {
            "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    with pytest.raises(CtapError) as e:
        device.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.OPTIONAL}, exclude_list=exclude_list)

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

def test_credprotect_optional_list_excluded(device, MCCredProtectOptionalList):
    """ CredProtectOptionalList Cred should be visible to be excluded with no UV """
    exclude_list = [
        {
            "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    with pytest.raises(CtapError) as e:
        device.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.OPTIONAL_WITH_LIST}, exclude_list=exclude_list)

    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

def test_credprotect_required_not_excluded_with_no_uv(device, MCCredProtectRequired):
    """ CredProtectRequired Cred should NOT be visible to be excluded with no UV """
    exclude_list = [
        {
            "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        }
    ]

    # works
    device.doMC(rk=True, extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.REQUIRED}, exclude_list=exclude_list)

def test_credprotect_optional_works_with_no_allowList_no_uv(device, MCCredProtectOptional):

    # works
    res = device.doGA()['res'].get_assertions()[0]

    # If there's only one credential, this is None
    assert res.number_of_credentials == None

def test_credprotect_optional_and_list_works_no_uv(device, MCCredProtectOptional, MCCredProtectOptionalList, MCCredProtectRequired):
    allow_list = [
        {
            "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
        {
            "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
        {
            "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
    ]
    # works
    res1 = device.doGA(allow_list=allow_list)['res'].get_assertions()[0]
    assert res1.number_of_credentials in (None, 2)

    results = device.doGA(allow_list=allow_list)['res'].get_assertions()

    # the required credProtect is not returned.
    for res in results:
        assert res.credential["id"] != MCCredProtectRequired.auth_data.credential_data.credential_id[:]

def test_hmac_secret_and_credProtect_make_credential(resetdevice, MCCredProtectOptional
):

    res = resetdevice.doMC(extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.OPTIONAL, 'hmacCreateSecret': True})['res'].attestation_object

    for ext in ["credProtect", "hmac-secret"]:
        assert res.auth_data.extensions
        assert ext in res.auth_data.extensions
        assert res.auth_data.extensions[ext] == True


def test_credprotect_all_with_uv(device, MCCredProtectOptional, MCCredProtectOptionalList, MCCredProtectRequired, client_pin):
    allow_list = [
        {
            "id": MCCredProtectOptional.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
        {
            "id": MCCredProtectOptionalList.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
        {
            "id": MCCredProtectRequired.auth_data.credential_data.credential_id[:],
            "type": "public-key",
        },
    ]

    pin = "12345678"

    client_pin.set_pin(pin)

    res1 = device.doGA(user_verification=UserVerificationRequirement.REQUIRED, allow_list=allow_list)['res'].get_assertions()[0]

    assert res1.number_of_credentials in (None, 3)

