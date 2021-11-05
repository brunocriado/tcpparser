import collections
import re
import socket
import struct
import sys

from tcpparser.exceptions import (InvalidBigEndianPortNumber,
                                  InvalidNetAddrFormat,
                                  InvalidV4LittleEndianIpAddress)


def check_netaddr_pattern(netaddr):
    """ Check if network address is in the expected format """
    netaddrpattern = r'^[0-9a-fA-F]{8}:{1}[0-9a-fA-F]{4}$'

    if re.match(netaddrpattern, netaddr):
        return netaddr
    else:
        raise InvalidNetAddrFormat


def convert_port(hexport: str) -> int:
    """ Converts only hex_port part to integer """
    portpattern = r'^[0-9a-fA-F]{4}$'
    port = int(hexport, 16)

    if (port <= 0 or port > 65535) or not re.match(portpattern, hexport):
        raise InvalidBigEndianPortNumber
    else:
        return port


def convert_addr(addr: str) -> str:
    """ Converts only hex_ip part to network ip """
    addrpattern = r'^[0-9a-fA-F]{8}$'
    invalid_addresses = ['00000000', 'FFFFFFFF']

    if re.match(addrpattern, addr) and addr not in invalid_addresses:
        return socket.inet_ntoa(struct.pack("<L", int(addr, 16)))
    else:
        raise InvalidV4LittleEndianIpAddress


def convert_netaddr(netaddr: str) -> str:
    """
    Converts network address from hex_ip:hex_port format to ip:port
    e,g: 573B1FAC:BE46 to 172.31.59.87:48710
    """
    try:

        if check_netaddr_pattern(netaddr):
            addr, port = netaddr.split(':')
            addr = convert_addr(addr)
            port = convert_port(port)
            return '{}:{}'.format(addr, port)

    except BaseException:
        raise InvalidNetAddrFormat


def read_file(fd: str) -> list:

    try:
        with open(fd, 'r') as f:
            raw_data = f.readlines()
    except FileNotFoundError:
        print(f"\n[ERROR]: File {fd} not found", file=sys.stderr)
        sys.exit(-1)
    except OSError:
        print(f"\n[ERROR]: Error trying to open {fd}", file=sys.stderr)
        sys.exit(-1)
    except BaseException:
        print(f"\n[ERROR]: Unexpected error to open {fd}", file=sys.stderr)
        sys.exit(-1)

    if not raw_data:
        print(
            f"\n[ERROR]: {fd} file or its content doesn't seem to be accurate.",
            file=sys.stderr)

    return raw_data[1:]


def filter_loopback_address(netaddr: str) -> bool:
    """
    Filter for invalid addresses
    SHORTCUT: For now I'm filtering only loopback address.
    The intention was to filter any invalid address for this purpose
    like network and broadcast address.
    """
    try:
        check_netaddr_pattern(netaddr)
        addr = netaddr.split(':')[0]

        if addr.endswith("7F") and convert_addr(addr):
            return True
        else:
            return False

    except Exception as e:
        raise e


def parse_data(raw_data: list, blocked_ips: list) -> list:

    lines = []
    for line in raw_data:
        # Connection state
        # 01 == Established
        st = line.split()[3]

        if st == "01":

            try:
                raw_local_addr = check_netaddr_pattern(line.split()[1])
                raw_peer_addr = check_netaddr_pattern(line.split()[2])
                host_ip = convert_addr(raw_peer_addr.split(':')[0])

                if not filter_loopback_address(
                        raw_peer_addr) and host_ip not in blocked_ips:
                    port = int(convert_port(raw_local_addr.split(':')[1]))
                    timer_active = int(line.split()[5].split(':')[0])

                    # If port > 1024 and timer is active (timer_active != 0)
                    # means that the host started a connection then the direction
                    # changes
                    if port > 1024 and timer_active != 0:
                        direction = "<-"
                    else:
                        direction = "->"
                    conn = {
                        "LOCAL": convert_netaddr(raw_local_addr),
                        "PEER": convert_netaddr(raw_peer_addr),
                        "DIRECTION": direction
                    }
                    lines.append(conn)

            except Exception as e:
                raise e

    return lines


def organize_peer_connections(cnx: dict) -> dict:
    """
    This function structures/organizes the peer connections by ip peer as key of dict
    and all ports that have established connection as values (single values) in the
    last check.
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

    return peers
