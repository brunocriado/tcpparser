import os
import shutil
import subprocess
import sys


def got_root():
    if os.geteuid() != 0:
        print(
            "\n[ERROR]: Is necessary to run tcpparser as root user.\n",
            file=sys.stderr)
        sys.exit(-1)


def exe_exists(exe):
    """ Returns the full path if executable exists and is the path. None otherwise """
    return shutil.which(exe)


def execute(cmd):
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    result, err = process.communicate()
    return result.rstrip().decode("utf-8")
