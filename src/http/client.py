"""HTTP/1.1 client library."""

import email.message
import email.parser

from . import HTTPStatus

HTTP_PORT = 80

# Mapping status codes to official W3C names.
g_responses_map = {v: v.phrase for v in HTTPStatus.__members__.values()}

# maximal line length when calling readline()
_MAXLINE = 65536
_MAXHEADERS = 100


class HTTPMessage(email.message.Message):
    """An HTTPMessage is an email.message.Message with a few extras."""

    def getallmatchingheaders(self, name):
        """Return a list of all the header lines that match 'name'.

        'name' should be a string.
        """
        name = name.lower() + ":"
        n = len(name)
        lst = []
        hit = False
        for line in self.keys():
            if line[:n].lower() == name:
                hit = True
            if hit:
                lst.append(line)
        return lst


def _read_headers(fp, max_headers):
    """Read RFC 2822 headers from a file pointer.

    Length of line is limited by _MAXLINE, and number of
    headers is limited by _MAXHEADERS.
    """
    headers = []

    while True:
        line = fp.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise LineTooLong("header line")
        if line in (b"\r\n", b"\n", b""):
            break
        headers.append(line)
        if len(headers) > max_headers:
            raise HTTPException(f"got more than {max_headers} headers")
    return headers


def _parse_header_lines(header_lines, _class=HTTPMessage):
    """Parse RFC 2822 headers from header lines into an HTTPMessage object."""
    hstring = b"".join(header_lines).decode("iso-8859-1")
    return email.parser.Parser(_class=_class).parsestr(hstring)


def parse_headers(fp, _class=HTTPMessage, *, _max_headers=_MAXHEADERS):
    """Parse RFC 2822 headers from a file pointer into an HTTPMessage object."""
    header_lines = _read_headers(fp, _max_headers)
    return _parse_header_lines(header_lines, _class=_class)


class HTTPException(Exception):
    # Subclasses that define an __init__ must call Exception.__init__
    # or define self.args. Otherwise, str() will fail.
    pass


class LineTooLong(Exception):

    """Exception raised when a line is too long."""

    def __init__(self, line_type):
        HTTPException.__init__(
            self, f"got more than {_MAXLINE} bytes when reading {line_type}"
        )


class BadStatusLine(HTTPException):
    def __init__(self, line):
        if not line:
            line = repr(line)
        self.args = line
        self.line = line


class RemoteDisconnected(ConnectionResetError, BadStatusLine):
    def __init__(self, *pos, **kw):
        BadStatusLine.__init__(self, *pos, **kw)
        ConnectionResetError.__init__(self, *pos, **kw)


class UnknownProtocol(HTTPException):
    def __init__(self, version):
        self.args = version
        self.version = version


class IncompleteRead(HTTPException):
    def __init__(self, partial, expected=None):
        self.args = partial
        self.partial = partial
        self.expected = expected

    def __repr__(self):
        if self.expected is not None:
            e = f", {self.expected} more expected"
        else:
            e = ""
        return f"{self.__class__.__name__}({len(self.partial)} bytes read{e})"


class ImproperConnectionState(HTTPException):
    pass


class ResponseNotReady(ImproperConnectionState):
    pass


class InvalidURL(HTTPException):
    pass


class NotConnected(HTTPException):
    pass


class CannotSendRequest(ImproperConnectionState):
    pass


class CannotSendHeader(ImproperConnectionState):
    pass
