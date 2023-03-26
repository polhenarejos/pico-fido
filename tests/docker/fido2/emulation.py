# Original work Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified work Copyright 2020 Yubico AB. All Rights Reserved.
# This file, with modifications, is licensed under the above Apache License.

from __future__ import annotations

from .base import HidDescriptor, CtapHidConnection

import socket
from typing import Set

import logging
import sys

HOST = '127.0.0.1'
PORT = 35962

# Don't typecheck this file on Windows
assert sys.platform != "win32"  # nosec

logger = logging.getLogger(__name__)

class EmulationCtapHidConnection(CtapHidConnection):
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.handle = descriptor.path
        self.handle.connect((HOST, PORT))

    def write_packet(self, packet):
        if (self.handle.send(len(packet).to_bytes(2, 'big')) != 2):
            raise OSError("write_packet sending size failed")
        if (self.handle.send(packet) != len(packet)):
            raise OSError("write_packet sending packet failed")

    def read_packet(self):
        bts = self.handle.recv(2)
        if (len(bts) != 2):
            raise OSError("read_packet failed reading size")
        size = int.from_bytes(bts, 'big')
        data = self.handle.recv(size)
        if (len(data) != size):
            raise OSError("read_packet failed reading packet")
        return data

    def close(self) -> None:
        return self.handle.close()


def open_connection(descriptor):
    return EmulationCtapHidConnection(descriptor)


def get_descriptor(_):
    HOST = 'localhost'    # The remote host
    PORT = 35962              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return HidDescriptor(s, 0x00, 0x00, 64, 64, "Pico-Fido", "AAAAAA")

def list_descriptors():
    devices = []
    try:
        devices.append(get_descriptor(None))
    except ValueError:
        pass  # Not a CTAP device, ignore.

    return devices
