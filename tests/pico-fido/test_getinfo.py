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
