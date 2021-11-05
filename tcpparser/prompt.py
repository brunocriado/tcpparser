import time
from datetime import datetime

from tcpparser.constants import CLEAR_SCREEN


def formatted_output(data: list, reason: str) -> list:
    """ Prints the output in a formated way """

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if len(data) > 0:

        for ldata in data:
            print("{:>19}: {:>18}: {:>21} {} {:<21}".format(
                now, reason, ldata["PEER"], ldata["DIRECTION"], ldata["LOCAL"]
            ))

    else:
        print("No TCP peer connection established yet")


def splash():
    print(CLEAR_SCREEN)
    print("tcpparser starting...\n")
    time.sleep(0.3)
