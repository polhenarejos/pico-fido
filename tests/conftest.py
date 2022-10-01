from http import client
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction, ClientError
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server
from fido2.ctap import CtapError
from fido2.webauthn import CollectedClientData
from getpass import getpass
import sys
import pytest
import os

DEFAULT_PIN='12345678'

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
        input()
        self.__setup_client(self.__origin, self.__user_interaction, self.__uv)

    def MC(self, client_data_hash=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, options=None, pin_uv_param=None, pin_uv_protocol=None, enterprise_attestation=None):
        att_obj = self.__client._backend.ctap2.make_credential(
            client_data_hash=client_data_hash if client_data_hash is not Ellipsis else os.urandom(32),
            rp=rp if rp is not Ellipsis else self.__rp,
            user=user if user is not Ellipsis else self.user(),
            key_params=key_params if key_params is not Ellipsis else self.__server.allowed_algorithms,
            exclude_list=exclude_list,
            extensions=extensions,
            options=options,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
            enterprise_attestation=enterprise_attestation
            )
        return att_obj

    def doMC(self, client_data=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, rk=None, user_verification=None, enterprise_attestation=None, event=None):

        result = self.__client._backend.do_make_credential(
            client_data=client_data if client_data is not Ellipsis else CollectedClientData.create(
                    type=CollectedClientData.TYPE.CREATE, origin=self.__origin, challenge=os.urandom(32)
                ),
            rp=rp if rp is not Ellipsis else self.__rp,
            user=user if user is not Ellipsis else self.user(),
            key_params=key_params if key_params is not Ellipsis else self.__server.allowed_algorithms,
            exclude_list=exclude_list,
            extensions=extensions,
            rk=rk,
            user_verification=user_verification,
            enterprise_attestation=enterprise_attestation,
            event=event
        )
        return result

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
        att_obj = self.__client._backend.ctap2.get_assertion(
        rp_id=rp_id if rp_id is not Ellipsis else self.__rp['id'],
        client_data_hash=client_data_hash if client_data_hash is not Ellipsis else os.urandom(32),
        allow_list=allow_list,
        extensions=extensions,
        options=options,
        pin_uv_param=pin_uv_param,
        pin_uv_protocol=pin_uv_protocol
        )
        return att_obj

    def GNA(self):
        return self.__client._backend.ctap2.get_next_assertion()

    def doGA(self, client_data=Ellipsis, rp_id=Ellipsis, allow_list=None, extensions=None, user_verification=None, event=None):
        result = self.__client._backend.do_get_assertion(
            client_data=client_data if client_data is not Ellipsis else CollectedClientData.create(
                    type=CollectedClientData.TYPE.CREATE, origin=self.__origin, challenge=os.urandom(32)
                ),
            rp_id=rp_id if rp_id is not Ellipsis else self.__rp['id'],
            allow_list=allow_list,
            extensions=extensions,
            user_verification=user_verification,
            event=event
        )
        return result


@pytest.fixture(scope="session")
def device():
    dev = Device()
    return dev

@pytest.fixture(scope="session")
def info(device):
    return device.client()._backend.info

@pytest.fixture(scope="session")
def MCRes(device, *args):
    return device.doMC(*args).attestation_object

@pytest.fixture(scope="session")
def resetdevice(device):
    device.reset()
    return device

@pytest.fixture(scope="session")
def GARes(device, MCRes, *args):
    r = device.doGA(allow_list=[
            {"id": MCRes.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)
    return r
