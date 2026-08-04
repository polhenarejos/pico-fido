import pytest

from utils import APDUResponse, send_apdu


OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
INS_OTP = 0x01
SLOT_CONFIGURE = 0x01
SLOT_SWAP = 0x06
ACCESS_CODE_SIZE = 6
OTP_CONFIG_SIZE = 52


def _crc16(data):
    crc = 0xFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc & 0xFFFF


def _protected_config(access_code):
    config = bytearray(OTP_CONFIG_SIZE)
    config[22:38] = bytes(range(1, 17))
    config[38:44] = access_code
    crc = _crc16(config[:-2])
    config[-2:] = ((~crc) & 0xFFFF).to_bytes(2, "little")
    assert _crc16(config) == 0xF0B8
    return list(config)


def test_slot_swap_requires_access_code_and_bounds_offsets(ccid_card):
    send_apdu(ccid_card, 0xA4, p1=0x04, p2=0x00, data=OTP_AID)
    access_code = bytes.fromhex("010203040506")
    config = _protected_config(access_code)

    with pytest.raises(APDUResponse) as e:
        send_apdu(
            ccid_card,
            INS_OTP,
            p1=SLOT_SWAP,
            p2=0,
            data=[4, 0] + [0] * ACCESS_CODE_SIZE,
        )
    assert [e.value.sw1, e.value.sw2] == [0x6A, 0x86]

    send_apdu(ccid_card, INS_OTP, p1=SLOT_CONFIGURE, p2=0, data=config)
    try:
        with pytest.raises(APDUResponse) as e:
            send_apdu(ccid_card, INS_OTP, p1=SLOT_SWAP, p2=0)
        assert [e.value.sw1, e.value.sw2] == [0x69, 0x82]

        status = send_apdu(
            ccid_card,
            INS_OTP,
            p1=SLOT_SWAP,
            p2=0,
            data=[0, 0] + list(access_code),
        )
        assert status[4] & 0x02
        assert not status[4] & 0x01

        send_apdu(
            ccid_card,
            INS_OTP,
            p1=SLOT_SWAP,
            p2=0,
            data=[0, 0] + list(access_code),
        )
    finally:
        send_apdu(
            ccid_card,
            INS_OTP,
            p1=SLOT_CONFIGURE,
            p2=0,
            data=[0] * OTP_CONFIG_SIZE + list(access_code),
        )
