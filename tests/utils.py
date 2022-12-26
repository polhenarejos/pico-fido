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


from fido2.webauthn import AttestedCredentialData
import random
import string
import secrets
import math
from threading import Event, Timer
from numbers import Number

import sys
try:
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f'SW:{sw1:02X}{sw2:02X}')

def send_apdu(card, command, p1, p2, data=None, ne=None):
    lc = []
    dataf = []
    if (data):
        lc = [0x00] + list(len(data).to_bytes(2, 'big'))
        dataf = data
    if (ne is None):
        le = [0x00, 0x00]
    else:
        le = list(ne.to_bytes(2, 'big'))
    if (isinstance(command, list) and len(command) > 1):
        apdu = command
    else:
        apdu = [0x00, command]

    apdu = apdu + [p1, p2] + lc + dataf + le
    try:
        response, sw1, sw2 = card.connection.transmit(apdu)
    except CardConnectionException:
        card.connection.reconnect()
        response, sw1, sw2 = card.connection.transmit(apdu)
    if (sw1 != 0x90):
        if (sw1 == 0x6A and sw2 == 0x82):
            response, sw1, sw2 = card.connection.transmit([0x00, 0xA4, 0x04, 0x00, 0xB, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01, 0x0])
            if (sw1 == 0x90):
                response, sw1, sw2 = card.connection.transmit(apdu)
                if (sw1 == 0x90):
                    return response
        elif (sw1 == 0x69 and sw2 == 0x82):
            response, sw1, sw2 = card.connection.transmit([0x00, 0x20, 0x00, 0x81, len(pin)] + list(pin.encode()) + [0x0])
            if (sw1 == 0x90):
                response, sw1, sw2 = card.connection.transmit(apdu)
                if (sw1 == 0x90):
                    return response
        raise APDUResponse(sw1, sw2)
    return response


def verify(MC, GA, client_data_hash):
    credential_data = AttestedCredentialData(MC.auth_data.credential_data)
    GA.verify(client_data_hash, credential_data.public_key)


def generate_random_user():
    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = random.randint(1, 64)
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = "User name"
    display_name = "Displayed " + name

    return {"id": user_id, "name": name, "displayName": display_name}

counter = 1
def generate_user_maximum():
    """
    Generate RK with the maximum lengths of the fields, according to the minimal requirements of the FIDO2 spec
    """
    global counter

    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = 64
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(64))

    name = f"{counter}: {name}"
    icon = "https://www.w3.org/TR/webauthn/" + "A" * 128
    display_name = "Displayed " + name

    name = name[:64]
    display_name = display_name[:64]
    icon = icon[:128]

    counter += 1

    return {"id": user_id, "name": name, "icon": icon, "displayName": display_name}

def shannon_entropy(data):
    s = 0.0
    total = len(data)
    for x in range(0, 256):
        freq = data.count(x)
        p = freq / total
        if p > 0:
            s -= p * math.log2(p)
    return s


# Timeout from:
#   https://github.com/Yubico/python-fido2/blob/f1dc028d6158e1d6d51558f72055c65717519b9b/fido2/utils.py
# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


class Timeout(object):
    """Utility class for adding a timeout to an event.
    :param time_or_event: A number, in seconds, or a threading.Event object.
    :ivar event: The Event associated with the Timeout.
    :ivar timer: The Timer associated with the Timeout, if any.
    """

    def __init__(self, time_or_event):

        if isinstance(time_or_event, Number):
            self.event = Event()
            self.timer = Timer(time_or_event, self.event.set)
        else:
            self.event = time_or_event
            self.timer = None

    def __enter__(self):
        if self.timer:
            self.timer.start()
        return self.event

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timer:
            self.timer.cancel()
            self.timer.join()
