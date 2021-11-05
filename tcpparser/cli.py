import collections
import time

from prometheus_client import Counter, start_http_server

import tcpparser.environment as environment
import tcpparser.network as network
import tcpparser.prompt as prompt
import tcpparser.utils as utils
from tcpparser.constants import HTTP_SERVER_PORT, INTERVAL, PROC_NET_TCP_FILE


def main():

    environment.got_root()
    prompt.splash()

    # Prometheus Exporter initialization
    connection_counter = Counter('new_connections', 'New Connections Counter')
    start_http_server(HTTP_SERVER_PORT)

    # Initialization of variables
    count = 0
    popfirst = False
    cnx = collections.OrderedDict()
    blocked_ips = []

    raw_data = utils.read_file(PROC_NET_TCP_FILE)
    data = utils.parse_data(raw_data, blocked_ips)
    prompt.formatted_output(data, "New connection")
    network.update_connections(cnx, data, popfirst)
    network.check_portscan(cnx, blocked_ips)

    if len(data) > 0:
        connection_counter.inc(len(data))

    while True:
        time.sleep(INTERVAL)
        raw_data = utils.read_file(PROC_NET_TCP_FILE)
        data = utils.parse_data(raw_data, blocked_ips)
        prompt.formatted_output(data, "New connection")
        count += 1

        if count >= 6:
            popfirst = True

        network.update_connections(cnx, data, popfirst)
        network.check_portscan(cnx, blocked_ips)

        if len(data) > connection_counter._value.get():
            connection_counter.inc(len(data) - connection_counter._value.get())
