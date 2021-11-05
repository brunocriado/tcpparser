from tcpparser.environment import exe_exists


def test_exe_exists():
    assert exe_exists("iptables") is not None
    assert exe_exists("iptabless") is None
