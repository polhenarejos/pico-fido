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
import os
from fido2.ctap1 import APDU, ApduError, Ctap1
from fido2.webauthn import CollectedClientData
from fido2.utils import sha256

def test_u2f_reg(RegRes):
    pass

def test_u2f_auth(RegRes, AuthRes):
    pass

def test_u2f_auth_check_only(device, RegRes):
    with pytest.raises(ApduError) as e:
        device.ctap1.authenticate(
            RegRes['req']['client_data'].hash,
            RegRes['res'].attestation_object.auth_data.rp_id_hash,
            RegRes['res'].attestation_object.auth_data.credential_data.credential_id,
            check_only=True,
        )
    assert e.value.code == APDU.USE_NOT_SATISFIED

def test_version(device):
    assert device.ctap1.get_version() == "U2F_V2"

def test_bad_ins(device):
    with pytest.raises(ApduError) as e:
        device.ctap1.send_apdu(0, 0, 0, 0, b"")
    assert e.value.code == 0x6D00

def test_bad_cla(device):
    with pytest.raises(ApduError) as e:
        device.ctap1.send_apdu(1, Ctap1.INS.VERSION, 0, 0, b"abc")
    assert e.value.code == 0x6E00

@pytest.mark.parametrize("iterations", (5,))
def test_u2f_it(device, iterations):
    lastc = 0

    regs = []

    cd = CollectedClientData.create(
                    type=CollectedClientData.TYPE.CREATE, origin=None, challenge=os.urandom(32)
                )
    cdh = cd.hash
    rih = sha256(device.rp()['id'].encode())

    for i in range(0, iterations):
        reg = device.ctap1.register(cdh, rih)
        auth = device.ctap1.authenticate(cdh, rih, reg.key_handle)
        auth.verify(rih, cdh, reg.public_key)

        regs.append(reg)
        # check endianness
        if lastc:
            assert (auth.counter - lastc) < 256
        lastc = auth.counter
        if lastc > 0x80000000:
            print("WARNING: counter is unusually high: %04x" % lastc)
            assert 0

    for reg in regs:
        auth = device.ctap1.authenticate(cdh, rih, reg.key_handle)

    device.reboot()

    for reg in regs:
        auth = device.ctap1.authenticate(cdh, rih, reg.key_handle)

    for reg in regs:
        with pytest.raises(ApduError) as e:
            auth = device.ctap1.authenticate(
                cdh, rih, reg.key_handle, check_only=True
            )
        assert e.value.code == APDU.USE_NOT_SATISFIED

def test_bad_key_handle(device, RegRes):
    kh = bytearray(RegRes['res'].attestation_object.auth_data.credential_data.credential_id)
    kh[0] = kh[0] ^ (0x40)

    with pytest.raises(ApduError) as e:
        device.ctap1.authenticate(
            RegRes['res'].client_data.hash, RegRes['res'].attestation_object.auth_data.rp_id_hash, kh, check_only=True
        )
    assert e.value.code == APDU.WRONG_DATA

    with pytest.raises(ApduError) as e:
        device.ctap1.authenticate(
           RegRes['res'].client_data.hash, RegRes['res'].attestation_object.auth_data.rp_id_hash, kh
        )
    assert e.value.code == APDU.WRONG_DATA

def test_bad_key_handle_length(device, RegRes):
    kh = bytearray(RegRes['res'].attestation_object.auth_data.credential_data.credential_id)

    with pytest.raises(ApduError) as e:
        device.ctap1.authenticate(
            RegRes['res'].client_data.hash, RegRes['res'].attestation_object.auth_data.rp_id_hash, kh[: len(kh) // 2]
        )
    assert e.value.code == APDU.WRONG_DATA

def test_incorrect_appid(device, RegRes):

    badid = bytearray(RegRes['res'].attestation_object.auth_data.rp_id_hash)
    badid[0] = badid[0] ^ (0x40)
    with pytest.raises(ApduError) as e:
        device.ctap1.authenticate(
            RegRes['res'].client_data.hash, badid, RegRes['res'].attestation_object.auth_data.credential_data.credential_id
        )
    assert e.value.code == APDU.WRONG_DATA
