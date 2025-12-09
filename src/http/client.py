"""HTTP/1.1 client library."""

import collections
import email.message
import email.parser
import errno
import http
import io
import re
import socket
import sys
from errno import ENOPROTOOPT

from . import HTTPStatus

HTTP_PORT = 80

_UNKNOWN = "UNKNOWN"

# connettion states
_CS_IDLE = "Idle"
_CS_REQ_STARTED = "Request-started"
_CS_REQ_SENT = "Request-sent"

# Mapping status codes to official W3C names.
g_responses_map = {v: v.phrase for v in HTTPStatus.__members__.values()}

# maximal line length when calling readline()
_MAXLINE = 65536
_MAXHEADERS = 100

# the patterns for both name and value in header lines
_is_legal_header_name = re.compile(rb"[^:\s][^:\r\n]*").fullmatch
_is_illegal_header_value = re.compile(rb"\n(?![ \t])|\r(?![ \t\n])").search

# These characters are not allowed within HTTP URL paths.
# See https://tools.ietf.org/html/rfc3986#section-3.3 and the
# https://tools.ietf.org/html/rfc3986#appendix-A pchar definition.
# Prevents CVE-2019-9740. Includes control characters such as \r\n.
# We don't restrict chars above \x7f as putrequest() limits us to ASCII.
_contains_disallowed_url_pchar_re = re.compile("[\x00-\x20\x7f]")

# These characters are not allowed within HTTP method names
# to prevent http header injection.
_contains_disallowed_method_pchar_re = re.compile("[\x00-\x1f]")

# We always set the Content-Length header for these methods because some
# servers will otherwise resposne with a 411 Length Required error.
_METHODS_EXCEPTION_BODY = {"PATCH", "POST", "PUT"}


def _encode(data, name="data"):
    """Call data.encode("latin-1") but show a better error message on failure."""
    try:
        return data.encode("latin-1")
    except UnicodeEncodeError as e:
        raise UnicodeEncodeError(
            e.encoding,
            e.object,
            e.start,
            e.end,
            "%s (%.20r) is not valid latin-1. Use %s.encode('utf-8') instead."
            % (name.title(), data[e.start : e.end], name),
        ) from None


def _strip_ipv6_iface(enc_name: bytes) -> bytes:
    """Strip the interface identifier from an IPv6 address, if present."""
    enc_name, percent, _ = enc_name.partition(b"%")
    if percent:
        assert enc_name.startswith(b"[") and enc_name
        enc_name += b"]"
    return enc_name


class HTTPMessage(email.message.Message):
    """An HTTPMessage is an email.message.Message with a few extras."""

    def getallmatchingheaders(self, name):
        """Return a list of all the header lines that match 'name'.

        'name' should be a string.
        """
        name = name.lower() + ":"
        n = len(name)
        lst = []
        hit = 0
        for line in self.keys():
            if line[:n].lower() == name:
                hit = 1
            elif not line[:1].isspace():
                hit = 0
            if hit:
                lst.append(line)
        return lst


def _read_headers(fp):
    """Read RFC 2822 headers from a file pointer.

    Length of line is limited by _MAXLINE, and number of
    headers is limited by _MAXHEADERS.
    """
    headers = []

    while True:
        line = fp.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise LineTooLong("header line")
        headers.append(line)
        if len(headers) > _MAXHEADERS:
            raise HTTPException(f"got more than {_MAXHEADERS} headers")
        if line in (b"\r\n", b"\n", b""):
            break

    return headers


def _parse_header_lines(header_lines, _class=HTTPMessage):
    """Parse RFC 2822 headers from header lines into an HTTPMessage object."""
    hstring = b"".join(header_lines).decode("iso-8859-1")
    return email.parser.Parser(_class=_class).parsestr(hstring)


def parse_headers(fp, _class=HTTPMessage):
    """Parse RFC 2822 headers from a file pointer into an HTTPMessage object."""
    header_lines = _read_headers(fp)
    return _parse_header_lines(header_lines, _class=_class)


class HTTPResponse(io.BufferedIOBase):
    """See RFC 2616 sec 19.6 and RFC 1945 sec 6 for details."""

    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self.fp = sock.makefile("rb")
        self.debuglevel = debuglevel
        self._method = method
        self.headers = self.msg = None

        self.version = _UNKNOWN  # HTTP-Version
        self.status = _UNKNOWN  # Status-Code
        self.reason = _UNKNOWN  # Reason-Phrase

        self.chunked = _UNKNOWN  # is "chunked" being used
        self.chunk_left = _UNKNOWN  # bytes left in current chunk
        self.length = _UNKNOWN  # number of bytes left in response
        self.will_close = _UNKNOWN  # conn will close when done

    def _read_status(self):
        """Read the status line from the HTTP response."""
        line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
        if len(line) > _MAXLINE:
            raise LineTooLong("status line")
        if self.debuglevel > 0:
            print("reply:", repr(line))
        if not line:
            raise RemoteDisconnected("Remote end closed connection without response")

        try:
            version, status, reason = line.split(None, 2)
        except ValueError:
            try:
                version, status = line.split(None, 1)
                reason = ""
            except ValueError:
                # empty version will cause next test to fail
                version = ""

        if not version.startswith("HTTP/"):
            self._close_conn()
            raise BadStatusLine(line)

        # the status code is a three-digit number
        try:
            status = int(status)
            if status < 100 or status > 999:
                raise BadStatusLine(line)
        except ValueError:
            raise BadStatusLine(line)

        return version, status, reason

    def begin(self):
        """Begin reading response from the server."""
        if self.headers is not None:
            # we've already started reading the response
            return

        # read until we got a non-100 status
        while True:
            version, status, reason = self._read_status()
            if status != HTTPStatus.CONTINUE:
                break
            # skip the header from the 100 Continue response
            skipped_headers = _read_headers(self.fp)
            if self.debuglevel > 0:
                print("headers:", skipped_headers)
            del skipped_headers

        self.code = self.status = status
        self.reason = reason.strip()
        if version in ("HTTP/1.0", "HTTP/0.9"):
            self.version = 10
        elif version.startswith("HTTP/1.1"):
            self.version = 11
        else:
            raise UnknownProtocol(version)

        self.headers = self.msg = parse_headers(self.fp)

        if self.debubglevel > 0:
            for hdr, val in self.headers.items():
                print(f"headers: {hdr}: {val}")

        # are we using the chunked transfer encoding?
        tr_enc = self.headers.get("Transfer-Encoding", "").lower()
        if tr_enc and tr_enc == "chunked":
            self.chunked = True
            self.chunk_left = None
        else:
            self.chunked = False

        # will the connection close at the end of the response?
        self.will_close = self._check_close()

        # do we have a Content-Length header?
        self.length = None
        length = self.headers.get("Content-Length")
        if length and not self.chunked:
            try:
                self.length = int(length)
            except ValueError:
                self.length = None
            else:
                if self.length < 0:
                    self.length = None
        else:
            self.length = None

        # does the body have a fixed length?
        if (
            status == HTTPStatus.NO_CONTENT
            or status == HTTPStatus.NOT_MODIFIED
            or (100 <= status < 200)
            or self._method == "HEAD"
        ):
            self.length = 0

        # if the connection remains, and we aren't using chunked, and
        # a content-length is not given, then assume the connection will close
        if not self.chunked and self.length is None and not self.will_close:
            self.will_close = True

    def _check_close(self):
        """Check the Connection header to see if the connection will close."""
        conn = self.headers.get("Connection", "").lower()

        if self.version == 11:
            # HTTP/1.1 defaults to keep-alive unless stated otherwise
            if conn and "close" in conn:
                return True
            return False

        # for older HTTP, Keep-Alive must be explicitly requested
        if self.headers.get("Keep-Alive", ""):
            return False
        # at least Akamai returns "Connection: keep-alive"
        if conn and "keep-alive" in conn:
            return False
        # Proxy-Connection is a netscape hack
        pconn = self.headers.get("Proxy-Connection", "").lower()
        if pconn and "keep-alive" in pconn:
            return False
        return True

    def _close_conn(self):
        """Close the connection to the server."""
        fp = self.fp
        self.fp = None
        fp.close()

    def close(self):
        """Close the response."""
        try:
            super().close()
        finally:
            if self.fp:
                self._close_conn()

    # These implements are for the benefit of io.BufferedIOBase
    def flush(self):
        super().flush()
        if self.fp:
            self.fp.flush()

    def readable(self):
        return True

    def isclosed(self):
        """True if the connection to the server is closed."""
        return self.fp is None

    def read(self, amt=None):
        """Read and return the resposne body, or up to the next amt bytes."""
        if self.fp is None:
            return b""

        if self._method == "HEAD":
            self._close_conn()
            return b""

        if self.chunked:
            return self._read_chunked(amt)

        if amt is not None and amt >= 0:
            if self.length is not None and amt > self.length:
                amt = self.length
            s = self.fp.read(amt)
            if not s and amt:
                # remote end closed connection
                self._close_conn()
            elif self.length is not None:
                self.length -= len(s)
                if self.length == 0:
                    self._close_conn()
            return s
        else:
            # amount is not given (unbounded read) so we must check self.length
            if self.length is None:
                s = self.fp.read()
            else:
                try:
                    s = self._safe_read(self.length)
                except IncompleteRead:
                    self._close_conn()
                    raise
                self.length = 0
            self._close_conn()
            return s

    def readinto(self, b):
        """Read up to len(b) bytes into bytearray b and return number of bytes read."""
        if self.fp is None:
            return 0

        if self._method == "HEAD":
            self._close_conn()
            return 0

        if self.chunked:
            return self._readinto_chunked(b)

        if self.length is not None:
            if len(b) > self.length:
                # clip the read to the "end of response"
                b = memoryview(b)[: self.length]

        n = self.fp.readinto(b)
        if not n and b:
            self._close_conn()
        elif self.length is not None:
            self.length -= n
            if self.length == 0:
                self._close_conn()
        return n

    def _read_next_chunk_size(self):
        """Read the next chunk size from the response."""
        line = self.fp.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise LineTooLong("chunk size line")
        i = line.find(b";")
        try:
            return int(line, 16)
        except ValueError:
            self._close_conn()
            raise

    def _read_and_discard_trailer(self):
        """Read and discard the trailer up to the CRLF terminator."""
        while True:
            line = self.fp.readline(_MAXLINE + 1)
            if len(line) > _MAXLINE:
                raise LineTooLong("trailer line")
            if not line:
                break
            if line in (b"\r\n", b"\n"):
                break

    def _get_chunk_left(self):
        """return self.chunk_left, reading a new chunk size if needed."""
        chunk_left = self.chunk_left
        if not chunk_left:  # can be 0 or None
            if chunk_left is not None:
                # we're at the end of the previous chunk, read the trailing CRLF
                self._safe_read(2)
            try:
                chunk_left = self._read_next_chunk_size()
            except ValueError:
                raise IncompleteRead(b"")
            if chunk_left == 0:
                # last chunk: 1*("0") [ chunk-extension ] CRLF
                self._read_and_discard_trailer()
                self._close_conn()
                chunk_left = None
            self.chunk_left = chunk_left
        return chunk_left

    def _read_chunked(self, amt=None):
        """Read up to amt bytes using chunked transfer encoding."""
        assert self.chunked != _UNKNOWN
        if amt is not None and amt < 0:
            amt = None
        value = []
        try:
            while (chunk_left := self._get_chunk_left()) is not None:
                if amt is not None and amt <= chunk_left:
                    value.append(self._safe_read(amt))
                    self.chunk_left = chunk_left - amt
                    break

                value.append(self._safe_read(chunk_left))
                if amt is not None:
                    amt -= chunk_left
                self.chunk_left = 0
            return b"".join(value)
        except IncompleteRead as e:
            raise IncompleteRead(b"".join(value)) from e

    def _readinto_chunked(self, b):
        """Read up to len(b) bytes into bytearray b using chunked transfter encoding."""
        assert self.chunked != _UNKNOWN
        total_bytes = 0
        mvb = memoryview(b)
        try:
            while True:
                chunk_left = self._get_chunk_left()
                if chunk_left is None:
                    return total_bytes

                if len(mvb) <= chunk_left:
                    n = self._safe_readinto(mvb)
                    self.chunk_left = chunk_left - n
                    return total_bytes + n

                temp_mvb = mvb[:chunk_left]
                n = self._safe_readinto(temp_mvb)
                total_bytes += n
                mvb = mvb[chunk_left:]
                self.chunk_left = 0
        except IncompleteRead:
            raise IncompleteRead(b[:total_bytes])

    def _safe_read(self, amt):
        """Read the number of bytes requested, or raise IncompleteRead."""
        data = self.fp.read(amt)
        if len(data) < amt:
            raise IncompleteRead(data, amt - len(data))
        return data

    def _safe_readinto(self, b):
        """Read into the buffer b, or raise IncompleteRead."""
        n = self.fp.readinto(b)
        if n < len(b):
            raise IncompleteRead(b[:n], len(b) - n)
        return n

    def read1(self, n=-1):
        """Read with at most one underlying system call. If at least one
        byte is buffered, return that instead."""
        if self.fp is None or self._method == "HEAD":
            return b""
        if self.chunked:
            return self._read1_chunked(n)
        if self.length is not None and (n < 0 or n > self.length):
            n = self.length
        result = self.fp.read1(n)
        if not result and n:
            # remote end closed connection
            self._close_conn()
        elif self.length is not None:
            self.length -= len(result)
            if not self.length:
                self._close_conn()
        return result

    def peek(self, n=-1):
        """Return buffered bytes without advancing the position."""
        if self.fp is None or self._method == "HEAD":
            return b""
        if self.chunked:
            return self._peek_chunked(n)
        return self.fp.peek(n)

    def readline(self, limit=-1):
        """Read and return a single line from the response."""
        if self.fp is None or self._method == "HEAD":
            return b""
        if self.chunked:
            # Fallback to IOBase readline which uses peek() and read()
            return super().readline(limit)
        if self.length is not None and (limit < 0 or limit > self.length):
            limit = self.length
        result = self.fp.readline(limit)
        if not result and limit:
            # remote end closed connection
            self._close_conn()
        elif self.length is not None:
            self.length -= len(result)
            if not self.length:
                self._close_conn()
        return result

    def _read1_chunked(self, n):
        """Read with at most one underlying system call using chunked transfer encoding."""
        chunk_left = self._get_chunk_left()
        if chunk_left is None or n == 0:
            return b""
        if not (0 <= n <= chunk_left):
            n = chunk_left
        read = self.fp.read1(n)
        if not read:
            raise IncompleteRead(b"")
        return read

    def _peek_chunked(self, n):
        """Peek up to n bytes using chunked transfer encoding."""
        try:
            chunk_left = self._get_chunk_left()
        except IncompleteRead:
            return b""
        if chunk_left is None:
            return b""
        return self.fp.peek(chunk_left)[:chunk_left]

    def fileno(self):
        """Return the underlying socket file descriptor."""
        if self.fp is None:
            raise OSError("I/O operation on closed HTTP response")
        return self.fp.fileno()

    def getheader(self, name, default=None):
        """Return the value of the named header or default if not found."""
        if self.headers is None:
            raise ResponseNotReady()
        headers = self.headers.get_all(name) or default
        if isinstance(headers, str) or not hasattr(headers, "__iter__"):
            return headers
        return ", ".join(headers)

    def getheaders(self):
        """Return a list of (header, value) tuples."""
        if self.headers is None:
            raise ResponseNotReady()
        return list(self.headers.items())

    # Override IOBase.__iter__ so that it doesn't check for closed-ness
    def __iter__(self):
        """Return an iterator over the response body lines."""
        return self

    def info(self):
        """Return an instance of the class mimetools.Message containing meta-information
        associated with the URL."""
        return self.headers

    def geturl(self):
        """Return the real URL of the page."""
        return self.url

    def getcode(self):
        """Return the HTTP status code."""
        return self.status


class HTTPConnection:
    _http_vsn = 11
    _http_vsn_str = "HTTP/1.1"

    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = 1
    debuglevel = 0

    @staticmethod
    def _is_textIO(stream):
        """Check if a file-like object is a text or a binary stream."""
        return isinstance(stream, io.TextIOBase)

    @staticmethod
    def _get_content_length(body, method):
        """Get the content-length based on the body."""
        if body is None:
            if method.upper() in _METHODS_EXCEPTION_BODY:
                return 0
            else:
                return None

        if hasattr(body, "read"):
            # file-like object
            return None

        try:
            # whehter implement the buffer protocol
            mv = memoryview(body)
            return mv.nbytes
        except TypeError:
            pass

        if isinstance(body, str):
            return len(body)

        return None

    def __init__(
        self,
        host,
        port=None,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
        blocksize=8192,
        *,
        max_response_headers=None,
    ):
        self.timeout = timeout
        self.source_address = source_address
        self.blocksize = blocksize
        self.sock = None
        self._buffer = []
        self.__response = None
        self.__state = _CS_IDLE
        self._method = None
        self._tunnel_host = None
        self._tunnel_port = None
        self._tunner_headers = {}
        self._raw_proxy_headers = None
        self.max_response_headers = max_response_headers

        (self.host, self.port) = self._get_hostport(host, port)
        self._validate_host(self.host)

        # This is stored as an instance variable to allow unit
        # tests to replace it with a mock socket.
        self._create_connection = socket.create_connection

    def set_tunnel(self, host, port=None, headers=None):
        """Set up host and port for HTTP CPNNECT tunneling."""
        if self.sock:
            raise RuntimeError("Cannot set up tunnel for established connection")

        self._tunnel_host, self._tunnel_port = self._get_hostport(host, port)
        if headers:
            self._tunner_headers = headers
        else:
            self._tunner_headers = {}

        if not any(header.lower() == "host" for header in self._tunner_headers):
            # reference: https://en.wikipedia.org/wiki/Punycode
            encoded_host = self._tunnel_host.encode("idna").decode("ascii")
            self._tunnel_headers["Host"] = f"{encoded_host}:{self._tunnel_port}"

    def _get_hostport(self, host, port):
        """Return (host, port) tuple, filling in default port if needed."""
        if port is None:
            i = host.rfind(":")
            j = host.rfind("]")
            if i > j:
                try:
                    port = int(host[i + 1 :])
                except ValueError:
                    if host[i + 1 :] == "":
                        port = self.default_port
                    else:
                        raise InvalidURL(f"nonnumeric port: {host[i+1:]}")
            else:
                port = self.default_port
        if host and host[0] == "[" and host[-1] == "]":
            host = host[1:-1]

        return (host, port)

    def set_debuglevel(self, level):
        """Set the debug output level."""
        self.debuglevel = level

    def _wrap_ipv6(self, ip):
        """Wrap IPv6 address in square brackets if needed."""
        if b":" in ip and ip[0] != b"["[0]:
            return b"[" + ip + b"]"
        return ip

    def _tunnel(self):
        """Establish a tunnel connection."""
        connect = b"CONNECT %s:%d %s\r\n" % (
            self._wrap_ipv6(self._tunnel_host.encode("idna")),
            self._tunnel_port,
            self._http_vsn_str.encode("ascii"),
        )
        headers = [connect]
        for hdr, val in self._tunner_headers.items():
            headers.append(f"{hdr}: {val}\r\n".encode("latin-1"))
        headers.append(b"\r\n")
        self.send(b"".join(headers))

        response = self.response_class(self.sock, method=self._method)
        try:
            (version, code, message) = response._read_status()

            self._raw_proxy_headers = _read_headers(
                response.fp, response.max_response_headers
            )

            if self.debuglevel > 0:
                for header in self._raw_proxy_headers:
                    print("header: ", header.decode())

            if code != http.HTTPStatus.OK:
                self.close()
                raise OSError(f"Tunnel connection failed: {code} {message.strip()}")
        finally:
            response.close()

    def get_proxy_response_headers(self):
        """Return a dictionary with the headers of the resposne
        received from the proxy server to to CONNECT request
        sent to set the tunnel.
        """
        return (
            _parse_header_lines(self._raw_proxy_headers)
            if self._raw_proxy_headers is not None
            else None
        )

    def connect(self):
        """Connect to the host and port specified in __init__."""
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            if e.errno != errno.ENOPROTOOPT:
                raise

        if self._tunnel_host:
            self._tunnel()

    def close(self):
        """Close the connection to the server."""
        self.__state = _CS_IDLE
        try:
            sock = self.sock
            if sock:
                self.sock = None
                sock.close()
        finally:
            response = self.__response
            if response:
                self.__response
                response.close()

    def send(self, data):
        """Send 'data' to the server."""
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise NotConnected()

        if self.debuglevel > 0:
            print("send:", repr(data))
        if hasattr(data, "read"):
            if self.debuglevel > 0:
                print("sneding a readable")
            encode = self._is_textIO(data)
            if encode and self.debuglevel > 0:
                print("encoding file using iso-8859-1")
            while datablock := data.read(self.blocksize):
                if encode:
                    datablock = datablock.encode("iso-8859-1")
                sys.audit("http.client.send", self, datablock)
                self.sock.sendall(datablock)
            return
        sys.audit("http.client.send", self, data)
        try:
            self.sock.sendall(data)
        except TypeError:
            if isinstance(data, collections.abc.Iterable):
                for d in data:
                    self.sock.sendall(d)
            else:
                raise TypeError(
                    f"data must be bytes, a file-like object, or an iterable of bytes, got {type(data)}"
                )

    def _output(self, s):
        """Add a line of output to the current request buffer."""
        self._buffer.append(s)

    def _read_readable(self, readable):
        """Read all data from a readable object."""
        if self.debuglevel > 0:
            print("reading from readable object")
        encode = self._is_textIO(readable)
        if encode and self.debuglevel > 0:
            print("encoding file using iso-8859-1")
        while datablock := readable.read(self.blocksize):
            if encode:
                datablock = datablock.encode("iso-8859-1")
            yield datablock

    def _send_output(self, message_body=None, encode_chunked=False):
        """Send the currently buffered request and clear the buffer."""
        self._buffer.extend((b"", b""))
        msg = b"\r\n".join(self._buffer)
        self.send(msg)

        if message_body is not None:
            if hasattr(message_body, "read"):
                chunks = self._read_readable(message_body)
            else:
                try:
                    # this is solely to check to see if message_body supports
                    # the buffer protocol.
                    memoryview(message_body)
                except TypeError:
                    try:
                        chunks = iter(message_body)
                    except TypeError:
                        raise TypeError(
                            "message_body must be a bytes-like object, a file-like object, or an iterable of bytes"
                        ) from None
                else:
                    # the object implements the buffer interface and
                    # can be passed directly into socket methods
                    chunks = (message_body,)

            for chunk in chunks:
                if not chunk:
                    if self.debuglevel > 0:
                        print("ignore empty chunk")
                    continue
                if encode_chunked and self._http_vsn == 11:
                    # chunked encoding
                    chunk = f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n"
                self.send(chunk)

            if encode_chunked and self._http_vsn == 11:
                # final chunk
                self.send(b"0\r\n\r\n")

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        """Send a request to the server."""
        if self.__response and self.__response.isclose():
            self.__response = None

        if self.__state == _CS_IDLE:
            self.__state = _CS_REQ_STARTED
        else:
            raise CannotSendRequest(self.__state)

        self._validate_method(method)
        self._method = method

        url = url or "/"
        self._validate_path(url)

        request = f"{method} {url} {self._http_vsn_str}"
        self._output(request.encode("ascii"))

        if self._http_vsn == 11:
            if not skip_host:
                # HTTP/1.1 requires a Host header
                netloc = ""
                if url.startswith("http"):
                    nil, netloc, nil, nil, nil = http.client.urlsplit(url)
                if netloc:
                    try:
                        netloc_enc = netloc.encode("ascii")
                    except UnicodeEncodeError:
                        # reference: https://en.wikipedia.org/wiki/Punycode
                        netloc_enc = netloc.encode("idna")
                else:
                    if self._tunnel_host:
                        host = self._tunnel_host
                        port = self._tunnel_port
                    else:
                        host = self.host
                        port = self.port

                    try:
                        host_enc = host.encode("ascii")
                    except UnicodeEncodeError:
                        # reference: https://en.wikipedia.org/wiki/Punycode
                        host_enc = host.encode("idna")

                    # as per RFC 273, IPv6 address shoud be wrapped with []
                    # when used as Host header
                    host_enc = self._wrap_ipv6(host_enc)
                    if ":" in host:
                        host_enc = _strip_ipv6_iface(host_enc)

                    if port == self.default_port:
                        self.putheader("Host", host_enc)
                    else:
                        host_enc = host_enc.decode("ascii")
                        self.putheader("Host", f"{host_enc}:{port}")
            if not skip_accept_encoding:
                self.putheader("Accept-Encoding", "identity")
        else:
            pass

    def _encode_request(self, request):
        """ASCII also helps prevent CVE-2019-9740."""
        return request.encode("ascii")

    def _validate_method(self, method):
        """Validate a method name for putrequest."""
        match = _contains_disallowed_method_pchar_re.search(method)
        if match:
            raise ValueError(
                f"method contains disallowed character {match!r} (found at least {match.group()!r})"
            )

    def _validate_path(self, url):
        """Validate a request url for putrequest."""
        # prevent CVE-2019-9740
        match = _contains_disallowed_url_pchar_re.search(url)
        if match:
            raise ValueError(
                f"url contains disallowed character {match!r} (found at least {match.group()!r})"
            )

    def putheader(self, header, *values):
        """Send a request header line to the server."""
        if self.__state != _CS_REQ_STARTED:
            raise CannotSendHeader()

        if hasattr(header, "encode"):
            header = header.encode("ascii")

        if not _is_legal_header_name(header):
            raise ValueError(f"illegal header name {header!r}")

        values = list(values)
        for i, one_value in enumerate(values):
            if hasattr(one_value, "encode"):
                values[i] = one_value.encode("latin-1")
            elif isinstance(one_value, int):
                values[i] = str(one_value).encode("ascii")

            if _is_illegal_header_value(values[i]):
                raise ValueError(f"illegal header value {values[i]!r}")

        value = b"\r\n\t".join(values)
        header = header + b": " + value
        self._output(header)

    def request(self, method, url, body=None, headers={}, *, encode_chunked=False):
        """Send a complete request to the server."""
        self._send_request(method, url, body, headers, encode_chunked=encode_chunked)

    def _send_request(self, method, url, body, headers, *, encode_chunked=False):
        """Internal method to send a complete request to the server."""
        header_names = frozenset(k.lower() for k in headers)
        skips = {}
        if "host" in header_names:
            skips["skip_host"] = True
        if "accept-encoding" in header_names:
            skips["skip_accept_encoding"] = True

        self.putrequest(method, url, **skips)

        # chunked encoding will happedn if HTTP/1.1 is used and
        # either the caller passes encode_chunked=True or the following
        # conditions hold:
        # 1. content-length is not given
        # 2. the body is a file or iterable, but not a str or bytes-like
        # 3. Transfer-Encoding has not been explicitly set by the caller
        if "content-lenth" not in header_names:
            if "transfer-encoding" not in header_names:
                encode_chunked = False
                content_length = self._get_content_length(body, method)
                if content_length is None:
                    if body is not None:
                        if self.debuglevel > 0:
                            print(f"unable to determine size of {body!r}")
                        encode_chunked = True
                        self.putheader("Transfer-Encoding", "chunked")
                else:
                    self.putheader("Content-Length", str(content_length))
        else:
            encode_chunked = False

        for hdr, val in headers.items():
            self.putheader(hdr, val)
        if isinstance(body, str):
            # RFC 2616 Section 3.7.1 says that text default has a
            # default charset of iso-8859-1.
            body = body.encode("iso-8859-1")
        self.endheaders(body, encode_chunked=encode_chunked)

    def getresponse(self):
        """Get the resposne from the server."""
        if self.__response and self.__response.isclose():
            self.__response = None

        if self.__state != _CS_REQ_SENT or self.__response:
            raise ResponseNotReady(self.__state)

        if self.debuglevel > 0:
            response = self.response_class(
                self.sock, self.debuglevel, method=self._method
            )
        else:
            response = self.response_class(self.sock, method=self._method)

        try:
            try:
                if self.max_response_headers is None:
                    response.begin()
                else:
                    response.begin(_max_headers=self.max_response_headers)
            except ConnectionError:
                self.close()
                raise
            assert response.will_close != _UNKNOWN
            self.__state = _CS_IDLE

            if response.will_close:
                # this effectively passes the connection to the response
                self.close()
            else:
                # remember this, so we can tell when it is complete
                self.__response = response
        except:
            response.close()
            raise


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
