class TcpParserException(Exception):
    """
    Base exception class.
    All Tcpparser-specific exceptions should subclass this class.
    """


class InvalidV4LittleEndianIpAddress(TcpParserException):
    """
    Exception for invalid ip address v4 in Little Endian format
    """


class InvalidBigEndianPortNumber(TcpParserException):
    """
    Exception for invalid port number.
    Valid range: 1 - 65535
    """


class InvalidNetAddrFormat(TcpParserException):
    """
    Exception for invalid netaddr
    Valid netaddr format: "00000000 - FFFFFFFF" + ":" + "0000 - FFFF"
    netaddrpattern = r'[0-9a-fA-F]{8}:[0-9a-fA-F]{4}'
    """
