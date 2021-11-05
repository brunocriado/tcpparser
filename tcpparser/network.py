import sys
from datetime import datetime

import tcpparser.environment as environment
import tcpparser.utils as utils


def is_blocked(ip: str) -> bool:
    """ Check if ip is already blocked """
    cmd = "{} {} {} {} {}".format("iptables", "-C INPUT", "-s", ip, "-j DROP")
    return environment.execute(cmd)


def block_ip(ip: str) -> None:
    """
    Blocks source ip
    e.g: iptables -I INPUT -s 12.34.56.78/32 -j DROP
    """
    # SHORTCUT: Ideally should check if the ip is not one of the ips on any
    # physic or virtual network device before blocking.
    cmd = "{} {} {} {}/32 {}".format("iptables", "-I INPUT", "-s", ip, "-j DROP")
    exe = cmd.split(' ')[0]

    if environment.exe_exists(exe):

        if not is_blocked(ip):
            return environment.execute(cmd)

    else:
        print(f"[ERROR]: Unable to execute: {exe}", file=sys.stderr)
        print(f"Please check if {exe} is installed and is in the right path")


def update_connections(cnx: dict, data: list, popfirst: bool) -> None:
    """ Update a dictionary (cnx) with the connections from the last minute """

    # dict key
    epoch = int(datetime.now().timestamp() * 1000)

    # After 1 minute, start removing the first entry
    # cnx is an ordered dictionary
    # FIFO
    if popfirst:
        cnx.pop(next(iter(cnx)))

    # Uses set to avoid duplication of values
    group_conn = set()

    for ldata in data:

        if ldata["DIRECTION"] == "->":
            conn = tuple((ldata["PEER"].split(':')[0], ldata["LOCAL"]))
            group_conn.add(conn)

    cnx[epoch] = group_conn


def check_portscan(cnx: dict, blocked_ips: list) -> None:
    """ Checks established connections from a source ip """

    peers = utils.organize_peer_connections(cnx)

    # Checks if a single peer address has more than 3 connection in the previous minute
    # and shows "Port scan detected"
    for host_ip, sockets in peers.items():
        fail = False

        # Check if IP wasn't already blocked and has more than 3 ports
        # open on host running tcpparser
        if len(sockets) > 3 and host_ip not in blocked_ips:
            blocked_ips.append(host_ip)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ports = []
            reason = "Port scan detected"

            for netaddr in sockets:
                ports.append(str(netaddr.split(':')[1]))

            local = str(netaddr.split(':')[0])
            print("{:>19}: {:>18}: {:>21} {} {:<21}".format(
                now, reason, host_ip, "->", local + " on ports " + ",".join(ports)
            ))

            # Blocks the source ip only once
            if not fail:
                fail = block_ip(host_ip)
