from tcpparser.prompt import formatted_output


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
