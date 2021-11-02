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