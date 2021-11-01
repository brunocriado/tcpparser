import socket
import struct
import time
import subprocess
import shutil
from tcpparser.constants import CLEAR_SCREEN


def convert_port(port: str) -> int:
    return int(port, 16)

def convert_addr(addr: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(addr, 16)))

def convert_netaddr(netaddr: str) -> str:
    addr, port = netaddr.split(':')
    addr = convert_addr(addr)
    port = convert_port(port)
    return '{}:{}'.format(addr, port)


def filter_loopback_address(netaddr: str) -> bool:
    """
    Filter loopback addresses 
    """
    addr = netaddr.split(':')[0]
    return addr.endswith("7F")


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
    e.g: iptables -I INPUT -s 12.34.56.78 -j DROP
    """

    cmd = "{} {} {} {} {}".format("iptables", "-I INPUT", "-s", ip, "-j DROP")
    exe = cmd.split(' ')[0]
    if exe_exists(exe):
        if not is_blocked(ip):
            return _execute(cmd)
    else:
        print(f"[ERROR]: Unable to execute: {exe}")
        print(f"**> Please check if {exe} is installed and is in the right path")

