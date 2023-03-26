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
from fido2.client import CtapError


def test_getinfo(device):
    pass


def test_get_info_version(info):
    assert "FIDO_2_0" in info.versions


def test_Check_pin_protocols_field(info):
    if len(info.pin_uv_protocols):
        assert sum(info.pin_uv_protocols) > 0


def test_Check_options_field(info):
    for x in info.options:
        assert info.options[x] in [True, False]


def test_Check_up_option(device, info):
    if "up" not in info.options or info.options["up"]:
        with pytest.raises(CtapError) as e:
            device.MC(options={"up": True})
        assert e.value.code == CtapError.ERR.INVALID_OPTION
