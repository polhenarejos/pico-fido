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
import pytest
from fido2.client import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV2


PIN = "12345678"


def test_getinfo(device):
    pass


def test_get_info_version(info):
    assert "FIDO_2_0" in info.versions


def test_get_info_ctap_23_fields_are_well_formed(device, info):
    assert "FIDO_2_3" in info.versions
    assert info.enc_cred_store_state is not None
    assert len(info.enc_cred_store_state) == 32  # AES-CBC IV || one ciphertext block

    refreshed_info = device.client()._backend.ctap2.get_info()
    assert refreshed_info.enc_cred_store_state is not None
    assert refreshed_info.enc_cred_store_state != info.enc_cred_store_state


def test_get_info_advertises_supported_config_subcommands(info):
    assert info.authenticator_config_commands is not None
    assert {0x01, 0x02, 0x03, 0xFF}.issubset(info.authenticator_config_commands)


def test_enc_cred_store_state_changes_with_resident_credentials(device):
    device.reset()
    ctap = device.client()._backend.ctap2
    client_pin = ClientPin(ctap)
    client_pin.set_pin(PIN)
    persistent_token = client_pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT,
    )
    make_credential_token = client_pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
    )
    before = ctap.get_info().get_cred_store_state(persistent_token)

    client_data_hash = os.urandom(32)
    device.MC(
        client_data_hash=client_data_hash,
        options={"rk": True},
        pin_uv_protocol=PinProtocolV2.VERSION,
        pin_uv_param=PinProtocolV2().authenticate(
            make_credential_token, client_data_hash
        ),
    )

    after = ctap.get_info().get_cred_store_state(persistent_token)
    assert before is not None
    assert after is not None
    assert len(before) == 16
    assert after != before


def test_Check_pin_protocols_field(info):
    if len(info.pin_uv_protocols):
        assert sum(info.pin_uv_protocols) > 0


def test_Check_options_field(info):
    for x in info.options:
        assert info.options[x] in [True, False]
