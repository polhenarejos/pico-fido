import os
import socket
import time
from binascii import hexlify, unhexlify

import pytest
from fido2.ctap import CtapError
from fido2.hid import CTAPHID
from utils import Timeout

class TestHID(object):
    def test_long_ping(self, device):
        amt = 1000
        pingdata = os.urandom(amt)

        t1 = time.time() * 1000
        r = device.send_data(CTAPHID.PING, pingdata)
        t2 = time.time() * 1000
        delt = t2 - t1

        assert not (delt > 555 * (amt / 1000))

        assert r == pingdata

    def test_init(self, device, check_timeouts=False):
        if check_timeouts:
            with pytest.raises(socket.timeout):
                cmd, resp = self.recv_raw()

        payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
        r = device.send_data(CTAPHID.INIT, payload)
        print(r)
        assert r[:8] == payload

    def test_ping(self, device):

        pingdata = os.urandom(100)
        r = device.send_data(CTAPHID.PING, pingdata)
        assert r == pingdata

    def test_wink(self, device):
        r = device.send_data(CTAPHID.WINK, "")

    def test_cbor_no_payload(self, device):
        payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
        r = device.send_data(CTAPHID.INIT, payload)
        capabilities = r[16]

        if (capabilities ^ 0x04) != 0:
            print("Implements CBOR.")
            with pytest.raises(CtapError) as e:
                r = device.send_data(CTAPHID.CBOR, "")
            assert e.value.code == CtapError.ERR.INVALID_LENGTH
        else:
            print("CBOR is not implemented.")

    def test_no_data_in_u2f_msg(self, device):
        payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
        r = device.send_data(CTAPHID.INIT, payload)
        capabilities = r[16]

        if (capabilities ^ 0x08) == 0:
            print("U2F implemented.")
            with pytest.raises(CtapError) as e:
                r = device.send_data(CTAPHID.MSG, "")
                print(hexlify(r))
            assert e.value.code == CtapError.ERR.INVALID_LENGTH
        else:
            print("U2F not implemented.")

    def test_invalid_hid_cmd(self, device):
        r = device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")

        with pytest.raises(CtapError) as e:
            r = device.send_data(0x66, "")
        assert e.value.code == CtapError.ERR.INVALID_COMMAND

    def test_oversize_packet(self, device):
        device.send_raw("\x81\x1d\xba\x00")
        cmd, resp = device.recv_raw()
        assert resp[0] == CtapError.ERR.INVALID_LENGTH

    def test_skip_sequence_number(self, device):
        r = device.send_data(CTAPHID.PING, "\x44" * 200)
        device.send_raw("\x81\x04\x90")
        device.send_raw("\x00")
        device.send_raw("\x01")
        # skip 2
        device.send_raw("\x03")
        cmd, resp = device.recv_raw()
        assert resp[0] == CtapError.ERR.INVALID_SEQ

    def test_resync_and_ping(self, device):
        r = device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        pingdata = os.urandom(100)
        r = device.send_data(CTAPHID.PING, pingdata)
        if r != pingdata:
            raise ValueError("Ping data not echo'd")

    def test_ping_abort(self, device):
        device.send_raw("\x81\x04\x00")
        device.send_raw("\x00")
        device.send_raw("\x01")
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")

    def test_ping_abort_from_different_cid(self, device, check_timeouts=False):
        oldcid = device.dev._channel_id
        newcid = int.from_bytes(b"\x11\x22\x33\x44", 'big')
        device.send_raw("\x81\x10\x00")
        device.send_raw("\x00")
        device.send_raw("\x01")
        device.dev._channel_id = newcid
        device.send_raw(
            "\x86\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88"
        )  # init from different cid
        print("wait for init response")
        cmd, r = device.recv_raw()  # init response
        assert cmd == 0x86
        device.dev._channel_id = oldcid
        if check_timeouts:
            # print('wait for timeout')
            cmd, r = device.recv_raw()  # timeout response
            assert cmd == 0xBF

    def test_timeout(self, device):
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        t1 = time.time() * 1000
        device.send_raw("\x81\x04\x00")
        device.send_raw("\x00")
        device.send_raw("\x01")
        cmd, r = device.recv_raw()  # timeout response
        t2 = time.time() * 1000
        delt = t2 - t1
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.TIMEOUT
        assert delt < 1000 and delt > 400

    def test_not_cont(self, device, check_timeouts=False):
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        device.send_raw("\x81\x04\x00")
        device.send_raw("\x00")
        device.send_raw("\x01")
        device.send_raw("\x81\x10\x00")  # init packet
        cmd, r = device.recv_raw()  # timeout response
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_SEQ

        if check_timeouts:
            device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
            device.send_raw("\x01\x10\x00")
            with pytest.raises(socket.timeout):
                cmd, r = device.recv_raw()  # timeout response

    def test_check_busy(self, device):
        t1 = time.time() * 1000
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        oldcid = device.cid()
        newcid = b"\x11\x22\x33\x44"
        device.send_raw("\x81\x04\x00")
        device.set_cid(newcid)
        device.send_raw("\x81\x04\x00")
        cmd, r = device.recv_raw()  # busy response
        t2 = time.time() * 1000
        assert t2 - t1 < 100
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.CHANNEL_BUSY

        device.set_cid(oldcid)
        cmd, r = device.recv_raw()  # timeout response
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.TIMEOUT

    def test_check_busy_interleaved(self, device):
        cid1 = b"\x11\x22\x33\x44"
        cid2 = b"\x01\x22\x33\x44"
        device.set_cid(cid2)
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        device.set_cid(cid1)
        device.send_data(CTAPHID.INIT, "\x11\x22\x33\x44\x55\x66\x77\x88")
        device.send_raw("\x81\x00\x63")  # echo 99 bytes first channel

        device.set_cid(cid2)  # send ping on 2nd channel
        device.send_raw("\x81\x00\x39")
        time.sleep(0.1)
        device.send_raw("\x00")

        cmd, r = device.recv_raw()  # busy response

        device.set_cid(cid1)  # finish 1st channel ping
        device.send_raw("\x00")

        device.set_cid(cid2)

        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.CHANNEL_BUSY

        device.set_cid(cid1)
        cmd, r = device.recv_raw()  # ping response
        assert cmd == 0x81
        assert len(r) == 0x39

    def test_cid_0(self, device):
        device.set_cid("\x00\x00\x00\x00")
        device.send_raw(
            "\x86\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\x00\x00\x00\x00"
        )
        cmd, r = device.recv_raw()  # timeout
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_CHANNEL
        device.set_cid("\x05\x04\x03\x02")

    def test_cid_ffffffff(self, device):

        device.set_cid("\xff\xff\xff\xff")
        device.send_raw(
            "\x81\x00\x08\x11\x22\x33\x44\x55\x66\x77\x88", cid="\xff\xff\xff\xff"
        )
        cmd, r = device.recv_raw()  # timeout
        assert cmd == 0xBF
        assert r[0] == CtapError.ERR.INVALID_CHANNEL
        device.set_cid("\x05\x04\x03\x02")

    def test_keep_alive(self, device, check_timeouts=False):

        precanned_make_credential = unhexlify(
            '01a401582031323334353637383961626364656630313233343536373'\
            '8396162636465663002a26269646b6578616d706c652e6f7267646e61'\
            '6d65694578616d706c65525003a462696446cc2abaf119f26469636f6'\
            'e781f68747470733a2f2f7777772e77332e6f72672f54522f77656261'\
            '7574686e2f646e616d657256696e204f6c696d7069612047657272696'\
            '56b646973706c61794e616d65781c446973706c617965642056696e20'\
            '4f6c696d706961204765727269650481a263616c672664747970656a7'\
            '075626c69632d6b6579')

        count = 0
        def count_keepalive(_x):
            nonlocal count
            count += 1

        # We should get a keepalive within .5s
        try:
            r = device.send_data(CTAPHID.CBOR, precanned_make_credential, timeout = .50, on_keepalive = count_keepalive)
        except CtapError as e:
            assert e.code == CtapError.ERR.KEEPALIVE_CANCEL
        assert count > 0

        # wait for authnr to get UP or timeout
        while True:
            try:
                r = device.send_data(CTAPHID.CBOR, '\x04') # getInfo
                break
            except CtapError as e:
                assert e.code == CtapError.ERR.CHANNEL_BUSY
