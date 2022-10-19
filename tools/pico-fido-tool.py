from fido2.ctap2.config import Config
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.utils import bytes2int, int2bytes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

from enum import IntEnum
from binascii import hexlify

class VendorConfig(Config):

    class PARAM(IntEnum):
        VENDOR_COMMAND_ID         = 0x01
        VENDOR_AUT_KEY_AGREEMENT  = 0x02
        VENDOR_AUT_CT             = 0x03

    class CMD(IntEnum):
        CONFIG_AUT           = 0x03e43f56b34285e2
        CONFIG_KEY_AGREEMENT = 0x1831a40f04a25ed9
        CONFIG_UNLOCK        = 0x54365966c9a74770

    class RESP(IntEnum):
        KEY_AGREEMENT = 0x01

    def __init__(self, ctap, pin_uv_protocol=None, pin_uv_token=None):
        super().__init__(ctap, pin_uv_protocol, pin_uv_token)

    def _get_key_device(self):
        return b"\x69"*32

    def _get_shared_key(self):
        ret = self._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {
                VendorConfig.PARAM.VENDOR_COMMAND_ID: VendorConfig.CMD.CONFIG_KEY_AGREEMENT,
            },
        )
        peer_cose_key = ret[VendorConfig.RESP.KEY_AGREEMENT]

        sk = ec.generate_private_key(ec.SECP256R1())
        pn = sk.public_key().public_numbers()
        pb = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

        x = bytes2int(peer_cose_key[-2])
        y = bytes2int(peer_cose_key[-3])
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        shared_key = sk.exchange(ec.ECDH(), pk)

        xkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12+32,
            salt=None,
            info=pb
        )
        kdf_out = xkdf.derive(shared_key)
        key_enc = kdf_out[12:]
        iv = kdf_out[:12]
        return iv, key_enc, key_agreement, pb

    def _send_command_key(self, cmd):
        iv, key_enc, key_agreement, pb = self._get_shared_key()

        chacha = ChaCha20Poly1305(key_enc)
        ct = chacha.encrypt(iv, self._get_key_device(), pb)
        self._call(
            Config.CMD.VENDOR_PROTOTYPE,
            {
                VendorConfig.PARAM.VENDOR_COMMAND_ID: cmd,
                VendorConfig.PARAM.VENDOR_AUT_KEY_AGREEMENT: key_agreement,
                VendorConfig.PARAM.VENDOR_AUT_CT: ct
            },
        )

    def enable_device_aut(self):
        self._send_command_key(VendorConfig.CMD.CONFIG_AUT)

    def unlock_device(self):
        self._send_command_key(VendorConfig.CMD.CONFIG_UNLOCK)

dev = next(CtapHidDevice.list_devices(), None)

vcfg = VendorConfig(Ctap2(dev))

#vcfg.enable_disable_device_aut(True)
vcfg.unlock_device()

