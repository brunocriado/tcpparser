import collections
from prometheus_client import start_http_server, Counter
import time
from tcpparser.constants import PROC_NET_TCP_FILE, INTERVAL, HTTP_SERVER_PORT
import tcpparser.utils as utils


def main():

    utils.got_root()
    utils.splash()

    # Prometheus Exporter initialization 
    connection_counter = Counter('new_connections', 'New Connections Counter')
    start_http_server(HTTP_SERVER_PORT)

    # Initialization of variables 
    count = 0
    popfirst = False
    cnx = collections.OrderedDict()

    raw_data = utils.read_file(PROC_NET_TCP_FILE)
    data = utils.parse_data(raw_data)
    utils.formatted_output(data, "New connection")
    utils.update_connections(cnx, data, popfirst)
    utils.detect_portscan(cnx)

    if len(data) > 0:
        connection_counter.inc(len(data))

    while True:
        time.sleep(INTERVAL)
        raw_data = utils.read_file(PROC_NET_TCP_FILE)
        data = utils.parse_data(raw_data)
        utils.formatted_output(data, "New connection")
        count += 1
        if count >= 6:
            popfirst = True
        utils.update_connections(cnx, data, popfirst)
        utils.detect_portscan(cnx)

        if len(data) > connection_counter._value.get():
            connection_counter.inc(len(data) - connection_counter._value.get())