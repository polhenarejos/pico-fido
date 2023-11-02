#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

import sys
import argparse
import platform
from binascii import hexlify
from threading import Event
from typing import Mapping, Any, Optional, Callable
import struct
import urllib.request
import json
from enum import IntEnum, unique

try:
    from fido2.ctap2.config import Config
    from fido2.ctap2 import Ctap2, ClientPin, PinProtocolV2
    from fido2.hid import CtapHidDevice, CTAPHID
    from fido2.utils import bytes2int, int2bytes
    from fido2 import cbor
    from fido2.ctap import CtapDevice, CtapError
    from fido2.ctap2.pin import PinProtocol, _PinUv
    from fido2.ctap2.base import args
except:
    print('ERROR: fido2 module not found! Install fido2 package.\nTry with `pip install fido2`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
except:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)

from enum import IntEnum
from binascii import hexlify

def get_pki_data(url, data=None, method='GET'):
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; '
    'rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    method = 'GET'
    if (data is not None):
        method = 'POST'
    req = urllib.request.Request(f"https://www.picokeys.com/pico/pico-fido/{url}/",
                                method=method,
                                data=data,
                                headers={'User-Agent': user_agent, })
    response = urllib.request.urlopen(req)
    resp = response.read().decode('utf-8')
    j = json.loads(resp)
    return j

class VendorConfig(Config):

    class PARAM(IntEnum):
        VENDOR_COMMAND_ID         = 0x01
        VENDOR_AUT_CT             = 0x02

    class CMD(IntEnum):
        CONFIG_AUT_ENABLE    = 0x03e43f56b34285e2
        CONFIG_AUT_DISABLE   = 0x1831a40f04a25ed9
        CONFIG_VENDOR_PROTOTYPE = 0x7f

    class RESP(IntEnum):
        KEY_AGREEMENT = 0x01

    def __init__(self, ctap, pin_uv_protocol=None, pin_uv_token=None):
        super().__init__(ctap, pin_uv_protocol, pin_uv_token)

    def enable_device_aut(self, ct):
        self._call(
            VendorConfig.CMD.CONFIG_VENDOR_PROTOTYPE,
            {
                VendorConfig.PARAM.VENDOR_COMMAND_ID: VendorConfig.CMD.CONFIG_AUT_ENABLE,
                VendorConfig.PARAM.VENDOR_AUT_CT: ct
            },
        )

    def disable_device_aut(self):
        self._call(
            VendorConfig.CMD.CONFIG_VENDOR_PROTOTYPE,
            {
                VendorConfig.PARAM.VENDOR_COMMAND_ID: VendorConfig.CMD.CONFIG_AUT_DISABLE
            },
        )

class Ctap2Vendor(Ctap2):
    def __init__(self, device: CtapDevice, strict_cbor: bool = True):
        super().__init__(device=device, strict_cbor=strict_cbor)


    def send_vendor(
        self,
        cmd: int,
        data: Optional[Mapping[int, Any]] = None,
        *,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> Mapping[int, Any]:
        """Sends a VENDOR message to the device, and waits for a response.

        :param cmd: The command byte of the request.
        :param data: The payload to send (to be CBOR encoded).
        :param event: Optional threading.Event used to cancel the request.
        :param on_keepalive: Optional function called when keep-alive is sent by
            the authenticator.
        """
        request = struct.pack(">B", cmd)
        if data is not None:
            request += cbor.encode(data)
        response = self.device.call(CTAPHID.VENDOR_FIRST + 1, request, event, on_keepalive)
        status = response[0]
        if status != 0x00:
            raise CtapError(status)
        enc = response[1:]
        if not enc:
            return {}
        decoded = cbor.decode(enc)
        if self._strict_cbor:
            expected = cbor.encode(decoded)
            if expected != enc:
                raise ValueError(
                    "Non-canonical CBOR from Authenticator.\n"
                    f"Got: {enc.hex()}\nExpected: {expected.hex()}"
                )
        if isinstance(decoded, Mapping):
            return decoded
        raise TypeError("Decoded value of wrong type")

    def vendor(
        self,
        cmd: int,
        sub_cmd: int,
        sub_cmd_params: Optional[Mapping[int, Any]] = None,
        pin_uv_protocol: Optional[int] = None,
        pin_uv_param: Optional[bytes] = None,
    ) -> Mapping[int, Any]:
        """CTAP2 authenticator vendor command.

        This command is used to configure various authenticator features through the
        use of its subcommands.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the Config class.

        :param sub_cmd: A Config sub command.
        :param sub_cmd_params: Sub command specific parameters.
        :param pin_uv_protocol: PIN/UV auth protocol version used.
        :param pin_uv_param: PIN/UV Auth parameter.
        """
        return self.send_vendor(
            cmd,
            args(sub_cmd, sub_cmd_params, pin_uv_protocol, pin_uv_param),
        )


class Vendor:
    """Implementation of the CTAP2.1 Authenticator Vendor API. It is vendor implementation.

    :param ctap: An instance of a CTAP2Vendor object.
    :param pin_uv_protocol: An instance of a PinUvAuthProtocol.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @unique
    class CMD(IntEnum):
        VENDOR_BACKUP    = 0x01
        VENDOR_MSE       = 0x02
        VENDOR_UNLOCK    = 0x03
        VENDOR_EA        = 0x04

    @unique
    class PARAM(IntEnum):
        PARAM           = 0x01
        COSE_KEY        = 0x02

    class SUBCMD(IntEnum):
        ENABLE              = 0x01
        DISABLE             = 0x02
        KEY_AGREEMENT       = 0x01
        EA_CSR              = 0x01
        EA_UPLOAD           = 0x02

    class RESP(IntEnum):
        PARAM       = 0x01
        COSE_KEY    = 0x02

    def __init__(
        self,
        ctap: Ctap2Vendor,
        pin_uv_protocol: Optional[PinProtocol] = None,
        pin_uv_token: Optional[bytes] = None,
    ):
        self.ctap = ctap
        self.pin_uv = (
            _PinUv(pin_uv_protocol, pin_uv_token)
            if pin_uv_protocol and pin_uv_token
            else None
        )
        self.__key_enc = None
        self.__iv = None

        self.vcfg = VendorConfig(ctap, pin_uv_protocol=pin_uv_protocol, pin_uv_token=pin_uv_token)

    def _call(self, cmd, sub_cmd, params=None):
        if params:
            params = {k: v for k, v in params.items() if v is not None}
        else:
            params = None
        if self.pin_uv:
            msg = (
                b"\xff" * 32
                + b"\x0d"
                + struct.pack("<b", sub_cmd)
                + (cbor.encode(params) if params else b"")
            )
            pin_uv_protocol = self.pin_uv.protocol.VERSION
            pin_uv_param = self.pin_uv.protocol.authenticate(self.pin_uv.token, msg)
        else:
            pin_uv_protocol = None
            pin_uv_param = None
        return self.ctap.vendor(cmd, sub_cmd, params, pin_uv_protocol, pin_uv_param)

    def backup_save(self, filename):
        if (platform.system() == 'Windows' or platform.system() == 'Linux'):
            from secure_key import windows as skey
        elif (platform.system() == 'Darwin'):
            from secure_key import macos as skey
        else:
            print('ERROR: platform not supported')
            sys.exit(-1)
        from words import words
        ret = self._call(
            Vendor.CMD.VENDOR_BACKUP,
            Vendor.SUBCMD.ENABLE,
        )
        data = ret[Vendor.RESP.PARAM]
        d = int.from_bytes(skey.get_secure_key(), 'big')
        with open(filename, 'wb') as fp:
            fp.write(b'\x01')
            fp.write(data)
            pk = ec.derive_private_key(d, ec.SECP256R1())
            signature = pk.sign(data, ec.ECDSA(hashes.SHA256()))
            fp.write(signature)
        print('Remember the following words in this order:')
        for c in range(24):
            coef = (d//(2048**c))%2048
            print(f'{(c+1):02d} - {words[coef]}')

    def backup_load(self, filename):
        if (platform.system() == 'Windows' or platform.system() == 'Linux'):
            from secure_key import windows as skey
        elif (platform.system() == 'Darwin'):
            from secure_key import macos as skey
        else:
            print('ERROR: platform not supported')
            sys.exit(-1)
        from words import words
        d = 0
        if (d == 0):
            for c in range(24):
                word = input(f'Introduce word {(c+1):02d}: ')
                while (word not in words):
                    word = input(f'Word not found. Please, tntroduce the correct word {(c+1):02d}: ')
                coef = words.index(word)
                d = d+(2048**c)*coef

        pk = ec.derive_private_key(d, ec.SECP256R1())
        pb = pk.public_key()
        with open(filename, 'rb') as fp:
            format = fp.read(1)[0]
            if (format == 0x1):
                data = fp.read(60)
                signature = fp.read()
            pb.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        skey.set_secure_key(pk)
        return self._call(
            Vendor.CMD.VENDOR_BACKUP,
            Vendor.SUBCMD.DISABLE,
            {
                Vendor.PARAM.PARAM: data
            },
        )

    def mse(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pn = sk.public_key().public_numbers()
        self.__pb = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

        ret = self._call(
            Vendor.CMD.VENDOR_MSE,
            Vendor.SUBCMD.KEY_AGREEMENT,
            {
                Vendor.PARAM.COSE_KEY: key_agreement,
            },
        )

        peer_cose_key = ret[VendorConfig.RESP.KEY_AGREEMENT]

        x = bytes2int(peer_cose_key[-2])
        y = bytes2int(peer_cose_key[-3])
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        shared_key = sk.exchange(ec.ECDH(), pk)

        xkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12+32,
            salt=None,
            info=self.__pb
        )
        kdf_out = xkdf.derive(shared_key)
        self.__key_enc = kdf_out[12:]
        self.__iv = kdf_out[:12]

    def encrypt_chacha(self, data):
        chacha = ChaCha20Poly1305(self.__key_enc)
        ct = chacha.encrypt(self.__iv, data, self.__pb)
        return ct

    def unlock_device(self):
        ct = self.get_skey()
        self._call(
            Vendor.CMD.VENDOR_UNLOCK,
            Vendor.SUBCMD.ENABLE,
            {
                Vendor.PARAM.PARAM: ct
            },
        )

    def _get_key_device(self):
        if (platform.system() == 'Windows' or platform.system() == 'Linux'):
            from secure_key import windows as skey
        elif (platform.system() == 'Darwin'):
            from secure_key import macos as skey
        else:
            print('ERROR: platform not supported')
            sys.exit(-1)
        return skey.get_secure_key()

    def get_skey(self):
        self.mse()
        ct = self.encrypt_chacha(self._get_key_device())
        return ct

    def enable_device_aut(self):
        ct = self.get_skey()
        self.vcfg.enable_device_aut(ct)

    def disable_device_aut(self):
        self.vcfg.disable_device_aut()

    def csr(self):
        return self._call(
            Vendor.CMD.VENDOR_EA,
            Vendor.SUBCMD.EA_CSR,
        )[Vendor.RESP.PARAM]

    def upload_ea(self, der):
        self._call(
            Vendor.CMD.VENDOR_EA,
            Vendor.SUBCMD.EA_UPLOAD,
            {
                Vendor.PARAM.PARAM: der
            }
        )

def parse_args():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(title="commands", dest="command")
    parser.add_argument('-p','--pin', help='Specify the PIN of the device.', required=True)
    parser_secure = subparser.add_parser('secure', help='Manages security of Pico Fido.')
    parser_secure.add_argument('subcommand', choices=['enable', 'disable', 'unlock'], help='Enables, disables or unlocks the security.')

    parser_backup = subparser.add_parser('backup', help='Manages the backup of Pico Fido.')
    parser_backup.add_argument('subcommand', choices=['save', 'load'], help='Saves or loads a backup.')
    parser_backup.add_argument('filename', help='File to save or load the backup.')

    parser_attestation = subparser.add_parser('attestation', help='Manages Enterprise Attestation')
    parser_attestation.add_argument('subcommand', choices=['csr'])
    parser_attestation.add_argument('--filename', help='Uploads the certificate filename to the device as enterprise attestation certificate. If not provided, it will generate an enterprise attestation certificate automatically.')

    args = parser.parse_args()
    return args

def secure(vdr, args):
    if (args.subcommand == 'enable'):
        vdr.enable_device_aut()
    elif (args.subcommand == 'unlock'):
        vdr.unlock_device()
    elif (args.subcommand == 'disable'):
        vdr.disable_device_aut()

def backup(vdr, args):
    if (args.subcommand == 'save'):
        vdr.backup_save(args.filename)
    elif (args.subcommand == 'load'):
        vdr.backup_load(args.filename)

def attestation(vdr, args):
    if (args.subcommand == 'csr'):
        if (args.filename is None):
            csr = x509.load_der_x509_csr(vdr.csr())
            data = urllib.parse.urlencode({'csr': csr.public_bytes(Encoding.PEM)}).encode()
            j = get_pki_data('csr', data=data)
            cert = x509.load_pem_x509_certificate(j['x509'].encode())
        else:
            with open(args.filename, 'rb') as f:
                dataf = f.read()
                try:
                    cert = x509.load_der_x509_certificate(dataf)
                except ValueError:
                    cert = x509.load_pem_x509_certificate(dataf)
        vdr.upload_ea(cert.public_bytes(Encoding.DER))

def main(args):
    print('Pico Fido Tool v1.5')
    print('Author: Pol Henarejos')
    print('Report bugs to https://github.com/polhenarejos/pico-fido/issues')
    print('')
    print('')

    dev = next(CtapHidDevice.list_devices(), None)
    ctap = Ctap2Vendor(dev)
    client_pin = ClientPin(ctap)
    token = client_pin.get_pin_token(args.pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    vdr = Vendor(ctap, pin_uv_protocol=PinProtocolV2(), pin_uv_token=token)

    if (args.command == 'secure'):
        secure(vdr, args)
    elif (args.command == 'backup'):
        backup(vdr, args)
    elif (args.command == 'attestation'):
        attestation(vdr, args)

def run():
    args = parse_args()
    main(args)

if __name__ == "__main__":
    run()
