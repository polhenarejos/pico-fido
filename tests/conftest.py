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


from http import client
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction, ClientError, _Ctap1ClientBackend
from fido2.attestation import FidoU2FAttestation
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server
from fido2.ctap import CtapError
from fido2.webauthn import CollectedClientData, AttestedCredentialData
from utils import *
from fido2.cose import ES256
import sys
import pytest
import os
import struct
from inputimeout import inputimeout


DEFAULT_PIN='12345678'


class Packet(object):
    def __init__(self, data):
        self.data = data

    def ToWireFormat(
        self,
    ):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)

class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return DEFAULT_PIN

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

class DeviceSelectCredential:
    def __init__(self, number):
        pass

    def __call__(self, status):
        pass

class Device():
    def __init__(self, origin="https://example.com", user_interaction=CliInteraction(),uv="discouraged",rp={"id": "example.com", "name": "Example RP"}, attestation="direct"):
        self.__user = None
        self.__set_client(origin=origin, user_interaction=user_interaction, uv=uv)
        self.__set_server(rp=rp, attestation=attestation)


    def __set_client(self, origin, user_interaction, uv):
        self.__uv = uv
        self.__dev = None
        self.__origin = origin
        self.__user_interaction = user_interaction

        # Locate a device
        self.__dev = next(CtapHidDevice.list_devices(), None)
        self.dev = self.__dev
        if self.__dev is not None:
            print("Use USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                self.__dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

        if not self.__dev:
            print("No FIDO device found")
            sys.exit(1)

        # Set up a FIDO 2 client using the origin https://example.com
        self.__client = Fido2Client(self.__dev, self.__origin, user_interaction=self.__user_interaction)

        # Prefer UV if supported and configured
        if self.__client.info.options.get("uv") or self.__client.info.options.get("pinUvAuthToken"):
            self.__uv = "preferred"
            print("Authenticator supports User Verification")

        self.__client1 = Fido2Client(self.__dev, self.__origin, user_interaction=self.__user_interaction)
        self.__client1._backend = _Ctap1ClientBackend(self.__dev, user_interaction=self.__user_interaction)
        self.ctap1 = self.__client1._backend.ctap1

    def __set_server(self, rp, attestation):
        self.__rp = rp
        self.__attestation = attestation
        self.__server = Fido2Server(self.__rp, attestation=self.__attestation)

    def client(self):
        return self.__client

    def user(self, user=None):
        if (self.__user is None):
            self.__user = {"id": b"user_id", "name": "A. User"}
        if (user is not None):
            self.__user = user
        return self.__user

    def rp(self, rp=None):
        if (self.__rp is None):
            self.__rp = {"id": "example.com", "name": "Example RP"}
        if (rp is not None):
            self.__rp = rp
        return self.__rp

    def send_data(self, cmd, data, timeout = 1.0, on_keepalive = None):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(timeout) as event:
            event.is_set()
            return self.dev.call(cmd, data, event, on_keepalive = on_keepalive)

    def cid(self):
        return self.dev._channel_id

    def set_cid(self, cid):
        self.dev._channel_id = int.from_bytes(cid, 'big')

    def recv_raw(self):
            with Timeout(1.0):
                r = self.dev._connection.read_packet()
            return r[4], r[7:]

    def send_raw(self, data, cid=None):
        if cid is None:
            cid = self.dev._channel_id.to_bytes(4, 'big')
        elif not isinstance(cid, bytes):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        data = cid + data
        l = len(data)
        if l != 64:
            pad = "\x00" * (64 - l)
            pad = struct.pack("%dB" % len(pad), *[ord(x) for x in pad])
            data = data + pad
        data = bytes(data)
        assert len(data) == 64
        self.dev._connection.write_packet(data)

    def reset(self):
        print("Resetting Authenticator...")
        try:
            self.__client._backend.ctap2.reset(on_keepalive=DeviceSelectCredential(1))
        except CtapError:
            # Some authenticators need a power cycle
            print("Need to power cycle authentictor to reset..")
            self.reboot()
            self.__client._backend.ctap2.reset(on_keepalive=DeviceSelectCredential(1))

    def reboot(self):
        print("Please reboot authenticator and hit enter")
        try:
            inputimeout(prompt='>>', timeout=5)
        except Exception:
            pass

        self.__set_client(self.__origin, self.__user_interaction, self.__uv)
        self.__set_server(rp=self.__rp, attestation=self.__attestation)

    def MC(self, client_data_hash=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, options=None, pin_uv_param=None, pin_uv_protocol=None, enterprise_attestation=None):
        client_data_hash = client_data_hash if client_data_hash is not Ellipsis else os.urandom(32)
        rp = rp if rp is not Ellipsis else self.__rp
        user = user if user is not Ellipsis else self.user()
        key_params = key_params if key_params is not Ellipsis else self.__server.allowed_algorithms
        att_obj = self.__client._backend.ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=key_params,
            exclude_list=exclude_list,
            extensions=extensions,
            options=options,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
            enterprise_attestation=enterprise_attestation
            )
        return {'res':att_obj,'req':{'client_data_hash':client_data_hash,
                        'rp':rp,
                        'user':user,
                        'key_params':key_params}}

    def doMC(self, client_data=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, rk=None, user_verification=None, enterprise_attestation=None, event=None, ctap1=False):
        client_data = client_data if client_data is not Ellipsis else CollectedClientData.create(
                    type=CollectedClientData.TYPE.CREATE, origin=self.__origin, challenge=os.urandom(32)
                )
        rp = rp if rp is not Ellipsis else self.__rp
        user = user if user is not Ellipsis else self.user()
        key_params = key_params if key_params is not Ellipsis else self.__server.allowed_algorithms
        if (ctap1 is True):
            client = self.__client1
        else:
            client = self.__client
        result = client._backend.do_make_credential(
            client_data=client_data,
            rp=rp,
            user=user,
            key_params=key_params,
            exclude_list=exclude_list,
            extensions=extensions,
            rk=rk,
            user_verification=user_verification,
            enterprise_attestation=enterprise_attestation,
            event=event
        )
        return {'res':result,'req':{'client_data':client_data,
                       'rp':rp,
                       'user':user,
                       'key_params':key_params}}

    def try_make_credential(self, options=None):
        if (options is None):
            options, _ = self.__server.register_begin(
            self.user(), user_verification=self.__uv, authenticator_attachment="cross-platform"
        )
        try:
            result = self.__client.make_credential(options["publicKey"])
        except ClientError as e:
            if (e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED):
                client_pin = ClientPin(self.__client._backend.ctap2)
                client_pin.set_pin(DEFAULT_PIN)
                result = self.__client.make_credential(options["publicKey"])
        return result

    def register(self, uv=None):
        # Prepare parameters for makeCredential
        create_options, state = self.__server.register_begin(
            self.user(), user_verification=uv or self.__uv, authenticator_attachment="cross-platform"
        )
        # Create a credential
        result = self.try_make_credential(create_options)

        # Complete registration
        auth_data = self.__server.register_complete(
            state, result.client_data, result.attestation_object
        )
        credentials = [auth_data.credential_data]

        print("New credential created!")

        print("CLIENT DATA:", result.client_data)
        print("ATTESTATION OBJECT:", result.attestation_object)
        print()
        print("CREDENTIAL DATA:", auth_data.credential_data)

        return (result, auth_data)

    def authenticate(self, credentials):
        # Prepare parameters for getAssertion
        request_options, state = self.__server.authenticate_begin(credentials, user_verification=self.__uv)

        # Authenticate the credential
        result = self.__client.get_assertion(request_options["publicKey"])

        # Only one cred in allowCredentials, only one response.
        result = result.get_response(0)

        # Complete authenticator
        self.__server.authenticate_complete(
            state,
            credentials,
            result.credential_id,
            result.client_data,
            result.authenticator_data,
            result.signature,
        )

        print("Credential authenticated!")

        print("CLIENT DATA:", result.client_data)
        print()
        print("AUTH DATA:", result.authenticator_data)

    def GA(self, rp_id=Ellipsis, client_data_hash=Ellipsis, allow_list=None, extensions=None, options=None, pin_uv_param=None, pin_uv_protocol=None):
        rp_id = rp_id if rp_id is not Ellipsis else self.__rp['id']
        client_data_hash = client_data_hash if client_data_hash is not Ellipsis else os.urandom(32)
        att_obj = self.__client._backend.ctap2.get_assertion(
        rp_id=rp_id,
        client_data_hash=client_data_hash,
        allow_list=allow_list,
        extensions=extensions,
        options=options,
        pin_uv_param=pin_uv_param,
        pin_uv_protocol=pin_uv_protocol
        )
        return {'res':att_obj,'req':{'rp_id':rp_id,
                        'client_data_hash':client_data_hash}}

    def GNA(self):
        return self.__client._backend.ctap2.get_next_assertion()

    def doGA(self, client_data=Ellipsis, rp_id=Ellipsis, allow_list=None, extensions=None, user_verification=None, event=None, ctap1=False, check_only=False):
        client_data = client_data if client_data is not Ellipsis else CollectedClientData.create(
                    type=CollectedClientData.TYPE.GET, origin=self.__origin, challenge=os.urandom(32)
                )
        rp_id = rp_id if rp_id is not Ellipsis else self.__rp['id']
        if (ctap1 is True):
            client = self.__client1
        else:
            client = self.__client
        try:
            result = client._backend.do_get_assertion(
                client_data=client_data,
                rp_id=rp_id,
                allow_list=allow_list,
                extensions=extensions,
                user_verification=user_verification,
                event=event
            )
        except ClientError as e:
            if (e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED):
                client_pin = ClientPin(self.__client._backend.ctap2)
                client_pin.set_pin(DEFAULT_PIN)
                result = client._backend.do_get_assertion(
                    client_data=client_data,
                    rp_id=rp_id,
                    allow_list=allow_list,
                    extensions=extensions,
                    user_verification=user_verification,
                    event=event
                )
            else:
                raise
        return {'res':result,'req':{'client_data':client_data,
                       'rp_id':rp_id}}


@pytest.fixture(scope="session")
def device():
    dev = Device()
    return dev

@pytest.fixture(scope="module")
def info(device):
    return device.client()._backend.info

@pytest.fixture(scope="module")
def MCRes(device, *args):
    return device.doMC(*args)

@pytest.fixture(scope="module")
def resetdevice(device):
    device.reset()
    return device

@pytest.fixture(scope="module")
def GARes(device, MCRes, *args):
    res = device.doGA(allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)

    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCRes['res'].attestation_object, a, res['req']['client_data'].hash)
    return res

@pytest.fixture(scope="module")
def MCRes_DC(device, *args):
    return device.doMC(rk=True, *args)

@pytest.fixture(scope="module")
def GARes_DC(device, MCRes_DC, *args):
    res = device.GA(allow_list=[
            {"id": MCRes_DC['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)
    verify(MCRes_DC['res'].attestation_object, res['res'], res['req']['client_data_hash'])

    return res

@pytest.fixture(scope="module")
def RegRes(resetdevice, *args):
    res = resetdevice.doMC(ctap1=True, *args)
    att = FidoU2FAttestation()
    att.verify(res['res'].attestation_object.att_stmt, res['res'].attestation_object.auth_data, res['req']['client_data'].hash)
    return res


@pytest.fixture(scope="module")
def AuthRes(device, RegRes, *args):
    res = device.doGA(ctap1=True, allow_list=[
            {"id": RegRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)
    aut_data = res['res'].get_response(0)
    m = aut_data.authenticator_data.rp_id_hash + aut_data.authenticator_data.flags.to_bytes(1, 'big') + aut_data.authenticator_data.counter.to_bytes(4, 'big') + aut_data.client_data.hash
    ES256(RegRes['res'].attestation_object.auth_data.credential_data.public_key).verify(m, aut_data.signature)
    return aut_data

@pytest.fixture(scope="class")
def client_pin(resetdevice):
    return ClientPin(resetdevice.client()._backend.ctap2)

@pytest.fixture(scope="class")
def ccid_card():
    cardtype = AnyCardType()
    try:
        # request card insertion
        cardrequest = CardRequest(timeout=10, cardType=cardtype)
        card = cardrequest.waitforcard()

        # connect to the card and perform a few transmits
        card.connection.connect()
        return card

    except CardRequestTimeoutException:
        print('time-out: no card inserted during last 10s')
    return None

@pytest.fixture(scope="class")
def select_oath(ccid_card):
    aid = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01]
    resp = send_apdu(ccid_card, 0xA4, 0x04, 0x00, aid)
    return ccid_card

@pytest.fixture(scope="class")
def reset_oath(select_oath):
    send_apdu(select_oath, 0x04, p1=0xde, p2=0xad)
    return select_oath
