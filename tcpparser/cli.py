from prometheus_client import start_http_server, Counter
import time
from datetime import datetime
import sys
import collections
from tcpparser.constants import PROC_NET_TCP_FILE, INTERVAL, HTTP_SERVER_PORT
import tcpparser.utils as utils

# Sane use tho
__blocked_ips = []


def read_file(fd: str) -> list:

    try:
        with open(fd, 'r') as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        print(f"File {fd} not found")
        sys.exit(-1)
    except OSError:
        print(f"Error trying to open {fd}")
        sys.exit(-1)
    except Exception as e:
        print(f"Unexpected error to open {fd}")
        sys.exit(-1)

    raw_lines = raw_lines[1:]
    #TODO: create a lambda function to parse the file
    lines = []
    for line in raw_lines:
        st = line.split()[3]
        if st == "01":
            raw_local_addr = line.split()[1]
            raw_peer_addr = line.split()[2]
            host_ip = utils.convert_addr(raw_peer_addr.split(':')[0])
            # Doesn't show the ip if it's already blocked
            if not utils.filter_loopback_address(raw_peer_addr) and host_ip not in __blocked_ips:
                port = int(utils.convert_port(raw_local_addr.split(':')[1]))
                ack = int(line.split()[14])
                if port > 1024 and not ack:
                    direction = "<-"
                else:
                    direction = "->"
                conn = {
                    "LOCAL": utils.convert_netaddr(raw_local_addr),
                    "PEER": utils.convert_netaddr(raw_peer_addr),
                    "DIRECTION": direction
                }
                lines.append(conn)
    return lines


def formatted_output(data: list, reason: str) -> list:

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if len(data) > 0:
        for ldata in data:
            print("{:>19}: {:>18}: {:>21} {} {:<21}".format(
                now, reason, ldata["PEER"], ldata["DIRECTION"], ldata["LOCAL"]
            ))
    else:
        print("No TCP peer connection established yet")

def update_connections(cnx: dict, data: list, popfirst: bool) -> None:

    epoch = int(datetime.now().timestamp() * 1000)
    if popfirst:
        cnx.pop(next(iter(cnx)))
    
    group_conn = set()
    for ldata in data:
        if ldata["DIRECTION"] == "->":
            conn = tuple((ldata["PEER"].split(':')[0], ldata["LOCAL"]))
            group_conn.add(conn)
    cnx[epoch] = group_conn


def detect_portscan(cnx: dict) -> None:

    peers = collections.defaultdict(set)

    """
    Creates a dictionary (peers) with key based on peer address and all ports
    that it connected previous minute
    e.g:
    {'172.31.63.176': {'172.31.59.87:22'},
     '172.31.52.219': {'172.31.59.87:13',
                       '172.31.59.87:19',
                       '172.31.59.87:22',
                       '172.31.59.87:25',
                       '172.31.59.87:80',
                       '172.31.59.87:93'},
     '207.161.137.20': {'172.31.59.87:22'},
     '185.73.124.100': {'172.31.59.87:22'}
    """
    for _, values in cnx.items():
        for element in values:
            peers[element[0]].add(element[1])

    """
    Checks if a single peer address has more than 3 connection in the previous minute
    and send a message
    """
    for host_ip, sockets in peers.items():
        fail = False
        if len(sockets) > 3 and host_ip not in __blocked_ips:
            __blocked_ips.append(host_ip)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ports = []
            reason = "Port scan detected"
            for netaddr in sockets:
                ports.append(str(netaddr.split(':')[1]))
            local = str(netaddr.split(':')[0])
            print("{:>19}: {:>18}: {:>21} {} {:<21}".format(
                now, reason, host_ip, "->", local + " on ports " + ",".join(ports)
            ))
            if not fail:
                fail = utils.block_ip(host_ip)



def main():

    utils.splash()

    """ Prometheus Exporter initialization """
    connection_counter = Counter('new_connections', 'New Connections Counter')
    start_http_server(HTTP_SERVER_PORT)

    """ Initialization of variables """
    count = 0
    popfirst = False
    cnx = collections.OrderedDict()
    data = read_file(PROC_NET_TCP_FILE)

    formatted_output(data, "New connection")
    update_connections(cnx, data, popfirst)
    detect_portscan(cnx)

    if len(data) > 0:
        connection_counter.inc(len(data))

    while True:
        time.sleep(INTERVAL)
        data = read_file(PROC_NET_TCP_FILE)
        formatted_output(data, "New connection")
        count += 1
        if count >= 6:
            popfirst = True
        update_connections(cnx, data, popfirst)
        detect_portscan(cnx)

        if len(data) > connection_counter._value.get():
            connection_counter.inc(len(data) - connection_counter._value.get())