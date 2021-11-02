import collections
from datetime import datetime
import os
import re
import socket
import struct
import subprocess
import shutil
import sys
import time
from tcpparser.constants import CLEAR_SCREEN
from tcpparser.exceptions import InvalidV4LittleEndianIpAddress, \
    InvalidBigEndianPortNumber, InvalidNetAddrFormat


def check_netaddr_pattern(netaddr):
    netaddrpattern = r'^[0-9a-fA-F]{8}:{1}[0-9a-fA-F]{4}$'
    if re.match(netaddrpattern, netaddr):
        return netaddr
    else:
        raise InvalidNetAddrFormat

def convert_port(hexport: str) -> int:
    portpattern = r'^[0-9a-fA-F]{4}$'
    port = int(hexport, 16)
    if (port <= 0 or port > 65535) or not re.match(portpattern, hexport):
            raise InvalidBigEndianPortNumber
    else:
        return port

def convert_addr(addr: str) -> str:
    addrpattern = r'^[0-9a-fA-F]{8}$'
    invalid_addresses = ['00000000', 'FFFFFFFF']
    if re.match(addrpattern, addr) and addr not in invalid_addresses:
        return socket.inet_ntoa(struct.pack("<L", int(addr, 16)))
    else:
        raise InvalidV4LittleEndianIpAddress

def convert_netaddr(netaddr: str) -> str:
    try:
        if check_netaddr_pattern(netaddr):
            addr, port = netaddr.split(':')
            addr = convert_addr(addr)
            port = convert_port(port)
            return '{}:{}'.format(addr, port)
    except:
        raise InvalidNetAddrFormat


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


def splash():
    print(CLEAR_SCREEN)
    print("tcpparser starting...\n")
    time.sleep(0.3)

def exe_exists(exe):
    return shutil.which(exe)

def _execute(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result, err = process.communicate()
    return result.rstrip().decode("utf-8")


def is_blocked(ip: str) -> bool:
    """ Check if ip is already blocked """
    cmd = "{} {} {} {} {}".format("iptables", "-C INPUT", "-s", ip, "-j DROP")
    return _execute(cmd)


def block_ip(ip: str) -> None:
    """ 
    Blocks source ip 
    e.g: iptables -I INPUT -s 12.34.56.78/32 -j DROP
    """
    # SHORTCUT: Ideally should check if the ip is not one of the ips on any 
    # physic or virtual network device. 

    cmd = "{} {} {} {}/32 {}".format("iptables", "-I INPUT", "-s", ip, "-j DROP")
    exe = cmd.split(' ')[0]
    if exe_exists(exe):
        if not is_blocked(ip):
            return _execute(cmd)
    else:
        print(f"[ERROR]: Unable to execute: {exe}", file=sys.stderr)
        print(f"Please check if {exe} is installed and is in the right path")

def got_root():
    if os.geteuid() != 0:
        print("\n[ERROR]: For this purpose, is necessary to run tcpparser as root user.\n", file=sys.stderr)
        sys.exit(-1)


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
    except:
        print(f"\n[ERROR]: Unexpected error to open {fd}", file=sys.stderr)
        sys.exit(-1)

    if not raw_data:
        print(f"\n[ERROR]: {fd} file or its content doesn't seem to be accurate.", file=sys.stderr)

    return raw_data[1:]


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
                raw_local_addr = check_netaddr_pattern(line.split()[1])
                raw_peer_addr = check_netaddr_pattern(line.split()[2])
                host_ip = convert_addr(raw_peer_addr.split(':')[0])

                if not filter_loopback_address(raw_peer_addr) and host_ip not in __blocked_ips:
                    port = int(convert_port(raw_local_addr.split(':')[1]))
                    ack = int(line.split()[14])

                    if port > 1024 and ack == 0:
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
                fail = block_ip(host_ip)