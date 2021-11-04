import pytest
from tcpparser.utils import convert_addr, convert_port, exe_exists, \
    filter_loopback_address, parse_data, read_file, formatted_output
from tcpparser.exceptions import InvalidV4LittleEndianIpAddress, \
    InvalidBigEndianPortNumber

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
    """ Verify if addr is a loopback address """
    assert filter_loopback_address(addr) == result

@pytest.mark.parametrize(
    'addr, result', [
        ("1489A1CF", "207.161.137.20"),
        ("573B1FAC", "172.31.59.87"),
    ]
)
def test_convert_addr(addr, result):
    """ Verify if address in hex little endian translate correctly to network address """
    assert convert_addr(addr) == result


def test_convert_unexpected_address_with_exception():
    """ Verify if address is valid """
    with pytest.raises(InvalidV4LittleEndianIpAddress):
        convert_addr("1489A1CFF")

@pytest.mark.parametrize(
    'port, result', [
        ("0016", 22),
        ("0050", 80),
    ]
)
def test_convert_port(port, result):
    """ Verify if port in hex big endian translate correctly to network port """
    assert convert_port(port) == result

def test_convert_unexpected_port_with_exception():
    """ Verify if port is valid """
    with pytest.raises(InvalidBigEndianPortNumber):
        convert_port("2001F")

def test_exe_exists():
    assert exe_exists("iptables") is not None
    assert exe_exists("iptabless") is None

def test_read_empty_file(capsys):
    read_file('tests/empty_file.txt')
    _, err = capsys.readouterr()
    assert '[ERROR]:' in err

def test_read_huge_file():
    """ Verifies if read_file function can read a big file and return its size """
    x = read_file('tests/huge_net_tcp')
    assert len(x) == 49801

def test_formatted_output(capsys):
    data = [{'LOCAL': '172.31.59.87:22', 'PEER': '20.191.37.74:60149', 'DIRECTION': '->'}]
    reason = "New connection"
    formatted_output(data, reason)
    out, _ = capsys.readouterr()
    assert 'New connection:    20.191.37.74:60149 -> 172.31.59.87:22' in out

def test_formatted_output_no_data(capsys):
    data = []
    reason = "New connection"
    formatted_output(data, reason)
    out, _ = capsys.readouterr()
    assert 'No TCP peer connection established yet' in out

def test_parse_data():
    raw_data = [ '  12: 573B1FAC:D7FC B03F1FAC:0016 01 00000000:00000000 02:00082210 00000000  '
                 '1000        0 8489782 2 ffff97f1ac5188c0 20 4 0 10 -1                   \n',]
    expected_data = [{'DIRECTION': '<-', 'LOCAL': '172.31.59.87:55292', 'PEER': '172.31.63.176:22'}]
    parsed_data = parse_data(raw_data)
    assert parsed_data == expected_data
