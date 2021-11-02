import pytest

from tcpparser.utils import convert_addr, convert_port, exe_exists, \
    filter_loopback_address
from tcpparser.exceptions import InvalidV4LittleEndianIpAddress, \
    InvalidBigEndianPortNumber

__author__ = "Bruno Criado"
__copyright__ = "Bruno Criado"
__license__ = "MIT"


@pytest.mark.parametrize(
    'addr, result', [
        ("0187007F:00FF", True),
        ("1489A1CF:00FF", False),
        ("0187007F:00FF", True),
        ("1489AD6F:00FF", False),
        ("7777777F:00FF", True),
        ("777777FF:00FF", False),
        ("FFFFFFF7:00FF", False),
    ]
)
def test_filter_loopback_address(addr, result):
    assert filter_loopback_address(addr) == result

@pytest.mark.parametrize(
    'addr, result', [
        ("1489A1CF", "207.161.137.20"),
        ("573B1FAC", "172.31.59.87"),
    ]
)
def test_convert_addr(addr, result):
    assert convert_addr(addr) == result


def test_convert_unexpected_address_with_exception():
    with pytest.raises(InvalidV4LittleEndianIpAddress):
        convert_addr("1489A1CFF")

def test_convert_port():
    assert convert_port("0016") == 22

def test_convert_unexpected_port_with_exception():
    with pytest.raises(InvalidBigEndianPortNumber):
        convert_port("2001F")

def test_exe_exists():
    assert exe_exists("iptables") is not None
    assert exe_exists("iptabless") is None

def test_