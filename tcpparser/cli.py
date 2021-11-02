import collections
from datetime import datetime
from prometheus_client import start_http_server, Counter
import time
from tcpparser.constants import PROC_NET_TCP_FILE, INTERVAL, HTTP_SERVER_PORT
import tcpparser.utils as utils

# SHORTCUT: Have a list of address already blocked and don't show
# that if already blocked. Ideally I was thinking to create a new
# iptables chain and get all ips that was blocked there by tcpparser.
# e.g:
#iptables -N tcpParser
#iptables -A tcpParser -j LOG --log-level 5 --log-prefix '[tcpparser]Packet dropped: '
#iptables -A tcpParser -j DROP
#iptables -A INPUT -s "163.172.32.1/32" -j tcpParser
# Every time tcpparser start running, list ips there (tcpParse chain) and 
# don't show until they are there.
# For this case I use a global var, sane use tho
__blocked_ips = []


def parse_data(raw_data):

    lines = []
    for line in raw_data:
        # Connection state
        # 01 == Established
        st = line.split()[3]
        if st == "01":

            try:
                raw_local_addr = utils.check_netaddr_pattern(line.split()[1])
                raw_peer_addr = utils.check_netaddr_pattern(line.split()[2])
                host_ip = utils.convert_addr(raw_peer_addr.split(':')[0])

                if not utils.filter_loopback_address(raw_peer_addr) and host_ip not in __blocked_ips:
                    port = int(utils.convert_port(raw_local_addr.split(':')[1]))
                    ack = int(line.split()[14])

                    if port > 1024 and ack == 0:
                        direction = "<-"
                    else:
                        direction = "->"

                    conn = {
                        "LOCAL": utils.convert_netaddr(raw_local_addr),
                        "PEER": utils.convert_netaddr(raw_peer_addr),
                        "DIRECTION": direction
                    }
                    lines.append(conn)

            except Exception as e:
                raise e

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
    """ Update a dictionary (cnx) with the connections from the last minute """

    # dict key
    epoch = int(datetime.now().timestamp() * 1000)

    # FIFO
    if popfirst:
        cnx.pop(next(iter(cnx)))
    
    group_conn = set()
    for ldata in data:
        if ldata["DIRECTION"] == "->":
            conn = tuple((ldata["PEER"].split(':')[0], ldata["LOCAL"]))
            group_conn.add(conn)
    cnx[epoch] = group_conn


def detect_portscan(cnx: dict) -> None:

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
     '20.191.237.140': {'172.31.59.87:22'},
     '185.73.124.100': {'172.31.59.87:22'}
    """

    peers = collections.defaultdict(set)

    for _, values in cnx.items():
        for element in values:
            peers[element[0]].add(element[1])

    # Checks if a single peer address has more than 3 connection in the previous minute
    # and shows "Port scan detected"
    for host_ip, sockets in peers.items():
        fail = False
        # Check if IP wasn't already blocked and has more than 3 ports
        # open on host running tcpparser
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
    data = parse_data(raw_data)
    formatted_output(data, "New connection")
    update_connections(cnx, data, popfirst)
    detect_portscan(cnx)

    if len(data) > 0:
        connection_counter.inc(len(data))

    while True:
        time.sleep(INTERVAL)
        raw_data = utils.read_file(PROC_NET_TCP_FILE)
        data = parse_data(raw_data)
        formatted_output(data, "New connection")
        count += 1
        if count >= 6:
            popfirst = True
        update_connections(cnx, data, popfirst)
        detect_portscan(cnx)

        if len(data) > connection_counter._value.get():
            connection_counter.inc(len(data) - connection_counter._value.get())