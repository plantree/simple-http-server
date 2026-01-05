"""HTTP server classes."""

import datetime
import email
import http
import http.client
import io
import mimetypes
import os
import posixpath
import shutil
import sys
import time
import typing
import urllib
from functools import partial
from pydoc import html

from . import HTTPStatus, __author__, __version__

# Default error message template
DEFAULT_ERROR_MESSAGE = """\
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <style type="text/css">
            :root {
                color-scheme: light dark;
            }
        </style>
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: %(code)d</p>
        <p>Message: %(message)s.</p>
        <p>Error code explanation: %(code)s - %(explain)s.</p>
    </body>
</html>
"""

DEFAULT_ERROR_CONTENT_TYPE = "text/html;charset=utf-8"

import socket
import socketserver


class HTTPServer(socketserver.TCPServer):
    """A simple HTTP server class."""

    # avoid TIME_WAIT issues on restart
    allow_reuse_address = True
    allow_reuse_port = False

    def server_bind(self):
        """Override server_bind to store the server name."""
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port


class BaseHTTPRequestHandler(socketserver.StreamRequestHandler):
    """A base class for HTTP request handler."""

    server_version = f"{__author__}/{__version__}"

    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE

    # Only support HTTP/1.1
    default_request_version = "HTTP/1.1"

    def parse_request(self) -> bool:
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an error
        is sent back to the client.
        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True

        # 1. Parse request line.
        # Example: `GET /home.html HTTP/1.1`.
        requestline = self.raw_requestline.decode("iso-8859-1")
        requestline = requestline.rstrip("\r\n")
        self.requestline = requestline

        words = requestline.split()

        if not (len(words) == 3):
            self.send_error(
                HTTPStatus.BAD_REQUEST, f"Bad request syntax ({requestline!r})"
            )
            return False

        command, path, version = words
        self.command, self.path = command, path

        # `version` must fit HTTP/1.1
        if version != "HTTP/1.1":
            self.send_error(
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                f"Unsupported HTTP version ({version})",
            )
            return False

        self.request_version = version

        # 2. Examines the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(
                self.rfile, _class=self.MessageClass
            )
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, "Line too long", str(err)
            )
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, "Too many headers", str(err)
            )
            return False

        conntype = self.headers.get("Connection", "")
        if conntype.lower() == "close":
            self.close_connection = True
        elif conntype.lower() == "keep-alive":
            self.close_connection = False

        # Examine 'Expect' header for '100-continue'.
        expect = self.headers.get("Expect", "")
        if expect.lower() == "100-continue":
            if not self.handle_expect_100():
                return False

        return True

    def handle_expect_100(self) -> bool:
        """Handle an 'Expect: 100-continue' header from the client.

        If the client is expecting a 100 Continue response, we must
        respond with either a 100 Continue or a final response before
        waiting for the request body. The default is to always respond
        with a 100 Continue. You can behave differently (for example,
        reject unauthorized requests) by overriding this method.

        This method should either return True (possibly after sending
        a 100 Continue response) or send an error response and return
        False.
        """
        self.send_response_only(HTTPStatus.CONTINUE)
        self.end_headers()
        return True

    def handle_one_request(self) -> None:
        """Handle a single HTTP request."""
        try:
            # The first line is the request line.
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(HTTPStatus.URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                # An error code has been sent inside parse_request().
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(
                    HTTPStatus.NOT_IMPLEMENTED, f"Unsupported method ({self.command}!r)"
                )
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush()  # Actually send the response if not already done.
        except TimeoutError as e:
            self.log_error(f"Request timed out: {e!r}")
            self.close_connection = True
            return

    def handle(self):
        """Handle multiple requests if necessary."""
        self.close_connection = True

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def send_error(self, code: int, message: str = None, explain: str = None) -> None:
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching
        the response code in the responses dictionary.
        """
        # Send headers first
        try:
            shormsg, longmsg = self.responses[code]
        except KeyError:
            shormsg, longmsg = "???", "???"
        if message is None:
            message = shormsg
        if explain is None:
            explain = longmsg
        self.log_error(f"code: {code}, message: {message}")

        self.send_response(code, message)
        self.send_header("Connection", "close")

        # message body is omitted for cases defined in RFC 7230 section 3.3.6
        body = None
        if code >= 200 and code not in (
            HTTPStatus.NO_CONTENT,
            HTTPStatus.RESET_CONTENT,
            HTTPStatus.NOT_MODIFIED,
        ):
            content = self.error_message_format % {
                "code": code,
                "message": message,
                "explain": explain,
            }
            body = content.encode("utf-8", "replace")
            self.send_header("Content-Type", self.error_content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        # Send body, if any
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def send_response(self, code: int, message: str = None) -> None:
        """Send the response header and log the response code.

        Also sends two standard headers: Server and Date.
        """
        self.log_request(code)

        # Send the response line first.
        self.send_response_only(code, message)

        # Add two standard headers.
        self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())

    def send_response_only(self, code: int, message: str = None) -> None:
        """Send the response header only."""
        if message is None:
            try:
                message = self.responses[code][0]
            except KeyError:
                message = ""
        if not hasattr(self, "_headers_buffer"):
            self._headers_buffer = []
        # Construct response line.
        self._headers_buffer.append(
            f"{self.protocol_version} {code} {message}\r\n".encode("latin-1", "strict")
        )

    def send_header(self, keyword: str, value: str) -> None:
        """Send a MIME header to the headers buffer.

        Attention: according to the HTTP/1.1 specification (RFC 7230):
            HTTP headers MUST use ASCII or ISO-8859-1 (latin-1) encoding
            HTTP header field values are defined as sequences of octets (bytes 0-255)
            The protocol explicitly restricts header characters to the US-ASCII or ISO-8859-1 character set
        """
        if not hasattr(self, "_headers_buffer"):
            self._headers_buffer = []
        self._headers_buffer.append(
            f"{keyword}: {value}\r\n".encode("latin-1", "strict")
        )

        # Update connection state if needed.
        if keyword.lower() == "connection":
            if value.lower() == "close":
                self.close_connection = True
            elif value.lower() == "keep-alive":
                self.close_connection = False

    def end_headers(self) -> None:
        """Send the blank line ending the MIME headers."""
        self._headers_buffer.append(b"\r\n")
        self.flush_headers()

    def flush_headers(self) -> None:
        """Flush the headers buffer to the output stream."""
        if hasattr(self, "_headers_buffer"):
            # headers in headers_buffer already have final CRLF
            self.wfile.write(b"".join(self._headers_buffer))
            self._headers_buffer = []

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Log an accepted request.

        This is called by send_response().
        """
        if isinstance(code, HTTPStatus):
            code = code.value
        self.log_message('"%s" %s %s', self.requestline, str(code), str(size))

    def log_error(self, format: str, *args) -> None:
        """Log an error.

        This is called when a request cannot be fulfilled.
        """
        self.log_message(format, *args)

    def log_message(self, format: str, *args) -> None:
        """Log an arbitrary message.

        This is used by all other logging functions. Override
        it if you have specific logging wishes.
        """
        message = format % args
        sys.stderr.write(
            f"{self.address_string()} - - [{self.log_date_time_string()}] {message}\n"
        )

    def version_string(self) -> str:
        """Return the server software version string."""
        return f"{self.server_version}"

    def date_time_string(self, timestamp=None) -> str:
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        return email.utils.formatdate(timestamp, usegmt=True)

    def log_date_time_string(self) -> None:
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, _, _, _ = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
            day,
            self.monthname[month],
            year,
            hh,
            mm,
            ss,
        )
        return s

    def address_string(self) -> str:
        """Return the client address formatted for logging."""
        return self.client_address[0]

    # Essentially static class variables
    protocol_version = "HTTP/1.1"
    MessageClass = http.client.HTTPMessage
    responses = {v: (v.phrase, v.description) for v in HTTPStatus.__members__.values()}

    monthname = [
        None,
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]


class SimpleHttpRequestHandler(BaseHTTPRequestHandler):
    """Simple HTTP request handler with GET and HEAD commands.

    This serves files from the current directory and any of its
    subdirectories. The MIME type for files is determined by
    calling the guess_type() method.
    """

    server_version = "SimpleHTTP/" + __version__
    index_pages = ["index.html", "index.htm"]
    extensions_map = _encodings_map_default = {
        ".gz": "application/gzip",
        ".Z": "application/octet-stream",
        ".bz2": "application/x-bzip2",
        ".xz": "application/x-xz",
    }

    def __init__(self, *args, directory: str = None, **kwargs) -> None:
        if directory is None:
            directory = os.getcwd()
        self.directory = os.fspath(directory)
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.copyfile(f, self.wfile)
            finally:
                f.close()

    def do_HEAD(self) -> None:
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def send_head(self) -> typing.Optional[typing.IO[bytes]]:
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is a file object (which has to be copied
        to the outputfile by the caller unless the command was
        HEAD, and must be closed by the caller under all
        circumstances), or None in case of an error.
        """
        path = self.translate_path(self.path)
        f = None

        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(path)
            print(parts)
            if not parts.path.endswith(("/", "%2f", "%2F")):
                # redirect browser - doing basically what apache does
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + "/", parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                print(new_url)
                self.send_header("Location", new_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None

            for index in self.index_pages:
                index_path = os.path.join(path, index)
                if os.path.exists(index_path):
                    path = index_path
                    break
            else:
                # No index page, list directory contents.
                return self.list_directory(path)

        ctype = self.guess_type(path)
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            # use browser cache is possible
            if (
                "If-Modified-Since" in self.headers
                and "If-None-Match" not in self.headers
            ):
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.headers["If-Modified-Since"]
                    )
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc
                        )
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(fs.st_size))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise

    def list_directory(self, path) -> typing.Optional[typing.IO[bytes]]:
        """Helper to produce a directory listing (absent index.html)."""
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())

        r = []
        displaypath = self.path
        displaypath = displaypath.split("#", 1)[0]
        displaypath = displaypath.split("?", 1)[0]
        try:
            displaypath = urllib.parse.unquote(displaypath, errors="surrogatepass")
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(displaypath)
        displaypath = html.escape(displaypath)

        enc = sys.getfilesystemencoding()
        title = f"Directory listing for {displaypath}"
        r.append(f"<!DOCTYPE HTML>")
        r.append('<html lang="en">')
        r.append("<head>")
        r.append(f'<meta charset="{enc}">')
        r.append(
            '<style type="text/css">\n:root {\nolor-scheme: light dark;\n}\n</style>'
        )
        r.append(f"<title>{title}</title>")
        r.append(f"<body>\n<h1>{title}</h1>")
        r.append("<hr>\n<ul>")
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
            path = urllib.parse.quote(linkname, errors="surrogatepass")
            r.append(f'<li><a href="{path}">{html.escape(displayname)}</a></li>')
        r.append("</ul>\n<hr>\n</body>\n</html>\n")
        encoded = "\n".join(r).encode(enc, "surrogateescape")

        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"text/html; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()

        return f

    def translate_path(self, path: str) -> str:
        """Translate a /-separated PATH to the local filename syntex."""
        if os.path.abspath(path):
            return path
        # abandon query parameters
        path = path.split("#", 1)[0]
        path = path.split("?", 1)[0]

        try:
            path = urllib.parse.unquote(path, errors="surrogatepass")
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)

        trailing_slash = path.endswith("/")
        path = posixpath.normpath(path)
        words = path.split("/")
        words = filter(None, words)
        path = self.directory
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += "/"
        return path

    def copyfile(self, source: typing.IO[bytes], outputfile: typing.IO[bytes]) -> None:
        """Copy all data between two file objects."""
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path: str) -> str:
        """Guess the type of a file."""
        _, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        guess, _ = mimetypes.guess_type(path)
        if guess:
            return guess
        return "application/octet-stream"


def _get_best_family(*address):
    """Get the best address family for the given address."""
    infos = socket.getaddrinfo(
        *address,
        type=socket.SOCK_STREAM,
        flags=socket.AI_PASSIVE,
    )
    family, _, _, _, sa = infos[0]
    return family, sa


def test(
    HandlerClass=BaseHTTPRequestHandler,
    ServerClass=HTTPServer,
    protocol="HTTP/1.1",
    port=8000,
    bind=None,
    directory=None,
):
    """Test the HTTP request handler class."""
    ServerClass.address_family, addr = _get_best_family(bind, port)
    HandlerClass.protocol_version = protocol

    # Bind the directory parameter to the handler
    if directory:
        HandlerClass = partial(HandlerClass, directory=directory)

    server = ServerClass(addr, HandlerClass)

    with server as httpd:
        host, port = httpd.server_address[:2]
        url_host = f"[{host}]" if ":" in host else host
        protocol = "HTTP"
        print(f"Serving HTTP on {url_host} port {port} (http://{url_host}:{port}/) ...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")
            httpd.server_close()
            sys.exit(0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--bind",
        metavar="ADDRESS",
        help="bind to this address (default: all interfaces)",
    )
    parser.add_argument(
        "port",
        metavar="PORT",
        type=int,
        default=8080,
        nargs="?",
        help="specify alternate port (default: 8080)",
    )
    parser.add_argument(
        "-d",
        "--directory",
        default=os.getcwd(),
        help="serve this directory (default: current directory)",
    )

    args = parser.parse_args()

    handle_class = SimpleHttpRequestHandler

    test(
        HandlerClass=handle_class,
        ServerClass=HTTPServer,
        port=args.port,
        bind=args.bind,
        directory=args.directory,
    )
