"""Tests for HTTP server classes."""

import io
import os
import socket
import ssl
import tempfile
import threading
from http import HTTPStatus
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
    HTTPSServer,
    SimpleHttpRequestHandler,
    ThreadingHTTPSServer,
    _get_best_family,
)
from unittest.mock import MagicMock


def http_request(host, port, method="GET", path="/", headers=None):
    """Make a raw HTTP request using sockets."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        request_lines = [f"{method} {path} HTTP/1.1"]
        request_lines.append(f"Host: {host}:{port}")
        request_lines.append("Connection: close")
        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
        request_lines.append("")
        request_lines.append("")
        request = "\r\n".join(request_lines)
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode("utf-8", errors="replace")
    finally:
        sock.close()


def parse_response(response):
    """Parse HTTP response into status code, headers, and body."""
    header_end = response.find("\r\n\r\n")
    if header_end == -1:
        return None, {}, response

    header_section = response[:header_end]
    body = response[header_end + 4 :]

    lines = header_section.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 else None

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.lower()] = value

    return status_code, headers, body


class TestHTTPServer:
    """Test cases for HTTPServer class."""

    def test_server_creation(self):
        """Test that HTTPServer can be created."""
        server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        assert server is not None
        assert server.server_address[0] == "127.0.0.1"
        server.server_close()

    def test_allow_reuse_address(self):
        """Test that allow_reuse_address is True."""
        assert HTTPServer.allow_reuse_address is True

    def test_allow_reuse_port(self):
        """Test that allow_reuse_port is False."""
        assert HTTPServer.allow_reuse_port is False

    def test_server_bind_sets_server_name(self):
        """Test that server_bind sets server_name and server_port."""
        server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        assert hasattr(server, "server_name")
        assert hasattr(server, "server_port")
        assert server.server_port > 0
        server.server_close()


class TestGetBestFamily:
    """Test cases for _get_best_family function."""

    def test_get_best_family_ipv4(self):
        """Test _get_best_family with IPv4."""
        family, addr = _get_best_family("127.0.0.1", 8080)
        assert family == socket.AF_INET
        assert addr[0] == "127.0.0.1"
        assert addr[1] == 8080

    def test_get_best_family_none_bind(self):
        """Test _get_best_family with None bind address."""
        family, addr = _get_best_family(None, 8080)
        assert family in (socket.AF_INET, socket.AF_INET6)
        assert addr[1] == 8080


class TestBaseHTTPRequestHandler:
    """Test cases for BaseHTTPRequestHandler class."""

    def test_server_version(self):
        """Test server_version attribute."""
        assert "Plantree" in BaseHTTPRequestHandler.server_version

    def test_protocol_version(self):
        """Test protocol_version is HTTP/1.1."""
        assert BaseHTTPRequestHandler.protocol_version == "HTTP/1.1"

    def test_responses_dict(self):
        """Test that responses dictionary is populated."""
        responses = BaseHTTPRequestHandler.responses
        assert HTTPStatus.OK in responses
        assert HTTPStatus.NOT_FOUND in responses
        assert responses[HTTPStatus.OK][0] == "OK"

    def test_monthname_list(self):
        """Test monthname list."""
        monthname = BaseHTTPRequestHandler.monthname
        assert len(monthname) == 13  # None + 12 months
        assert monthname[0] is None
        assert monthname[1] == "Jan"
        assert monthname[12] == "Dec"


class TestSimpleHttpRequestHandler:
    """Test cases for SimpleHttpRequestHandler class."""

    def test_server_version(self):
        """Test server_version attribute."""
        assert "SimpleHTTP" in SimpleHttpRequestHandler.server_version

    def test_index_pages(self):
        """Test index_pages list."""
        assert "index.html" in SimpleHttpRequestHandler.index_pages
        assert "index.htm" in SimpleHttpRequestHandler.index_pages

    def test_extensions_map(self):
        """Test extensions_map dictionary."""
        ext_map = SimpleHttpRequestHandler.extensions_map
        assert ".gz" in ext_map
        assert ext_map[".gz"] == "application/gzip"

    def test_guess_type_known_extension(self):
        """Test guess_type with known extensions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            assert handler.guess_type("test.gz") == "application/gzip"
            assert handler.guess_type("test.bz2") == "application/x-bzip2"

    def test_guess_type_html(self):
        """Test guess_type with HTML file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.guess_type("test.html")
            assert "text/html" in result

    def test_guess_type_unknown(self):
        """Test guess_type with unknown extension."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            assert handler.guess_type("test.unknown123") == "application/octet-stream"

    def test_translate_path_simple(self):
        """Test translate_path with simple path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.translate_path("/test.html")
            assert result == os.path.join(tmpdir, "test.html")

    def test_translate_path_with_query(self):
        """Test translate_path strips query parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.translate_path("/test.html?param=value")
            assert "?" not in result
            assert result.endswith("test.html")

    def test_translate_path_with_fragment(self):
        """Test translate_path strips fragment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.translate_path("/test.html#section")
            assert "#" not in result
            assert result.endswith("test.html")

    def test_translate_path_preserves_trailing_slash(self):
        """Test translate_path preserves trailing slash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.translate_path("/subdir/")
            assert result.endswith("/")

    def test_translate_path_filters_parent_dir(self):
        """Test translate_path filters out parent directory references."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = create_mock_handler(tmpdir)
            result = handler.translate_path("/../../../etc/passwd")
            # Should not escape the directory
            assert not result.startswith("/etc")


class TestIntegration:
    """Integration tests for the HTTP server."""

    def test_serve_file(self):
        """Test serving a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_content = b"Hello, World!"
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "wb") as f:
                f.write(test_content)

            # Start server
            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/test.txt")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_serve_index_html(self):
        """Test serving index.html for directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create index.html
            test_content = b"<html><body>Index</body></html>"
            index_file = os.path.join(tmpdir, "index.html")
            with open(index_file, "wb") as f:
                f.write(test_content)

            # Start server
            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_serve_index_htm(self):
        """Test serving index.htm for directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create index.htm (not index.html)
            test_content = b"<html><body>Index HTM</body></html>"
            index_file = os.path.join(tmpdir, "index.htm")
            with open(index_file, "wb") as f:
                f.write(test_content)

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/")
                status, headers, body = parse_response(response)
                assert status == 200
                assert "Index HTM" in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_404_not_found(self):
        """Test 404 response for non-existent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/nonexistent.txt")
                status, headers, body = parse_response(response)
                assert status == 404
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_directory_listing(self):
        """Test directory listing when no index.html."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files (but no index.html)
            with open(os.path.join(tmpdir, "file1.txt"), "w") as f:
                f.write("file1")
            with open(os.path.join(tmpdir, "file2.txt"), "w") as f:
                f.write("file2")

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/")
                status, headers, body = parse_response(response)
                assert status == 200
                assert "file1.txt" in body
                assert "file2.txt" in body
                assert "Directory listing" in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_head_request(self):
        """Test HEAD request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_content = b"Hello, World!"
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "wb") as f:
                f.write(test_content)

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request(
                    "127.0.0.1", port, method="HEAD", path="/test.txt"
                )
                status, headers, body = parse_response(response)
                assert status == 200
                # HEAD should return empty body
                assert body == ""
                # But should have Content-Length header
                assert headers.get("content-length") == str(len(test_content))
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_subdirectory(self):
        """Test serving files from subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            test_content = b"Subdir content"
            with open(os.path.join(subdir, "file.txt"), "wb") as f:
                f.write(test_content)

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/subdir/file.txt")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_content_type_html(self):
        """Test Content-Type header for HTML files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "page.html"), "w") as f:
                f.write("<html></html>")

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/page.html")
                status, headers, body = parse_response(response)
                assert status == 200
                assert "text/html" in headers.get("content-type", "")
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_path_with_query_string(self):
        """Test that query strings are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_content = b"Query test"
            with open(os.path.join(tmpdir, "file.txt"), "wb") as f:
                f.write(test_content)

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request(
                    "127.0.0.1", port, path="/file.txt?param=value&other=123"
                )
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_path_with_fragment(self):
        """Test that fragments are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_content = b"Fragment test"
            with open(os.path.join(tmpdir, "file.txt"), "wb") as f:
                f.write(test_content)

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/file.txt#section")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_symlink_display(self):
        """Test symlink display in directory listing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file and symlink to it
            with open(os.path.join(tmpdir, "original.txt"), "w") as f:
                f.write("original")
            os.symlink(
                os.path.join(tmpdir, "original.txt"), os.path.join(tmpdir, "link.txt")
            )

            server = HTTPServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = http_request("127.0.0.1", port, path="/")
                status, headers, body = parse_response(response)
                assert status == 200
                assert "link.txt@" in body  # Symlinks shown with @
            finally:
                thread.join(timeout=5)
                server.server_close()


def create_mock_handler(directory):
    """Create a mock SimpleHttpRequestHandler for testing."""
    mock_request = MagicMock()
    mock_request.makefile.return_value = io.BytesIO()
    mock_client_address = ("127.0.0.1", 12345)
    mock_server = MagicMock()

    # Create handler without actually connecting
    handler = SimpleHttpRequestHandler.__new__(SimpleHttpRequestHandler)
    handler.directory = directory
    handler.path = "/"
    handler.headers = {}
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    handler.requestline = "GET / HTTP/1.1"
    handler.client_address = mock_client_address
    handler.server = mock_server
    handler.close_connection = False
    handler._headers_buffer = []
    handler.wfile = io.BytesIO()
    handler.rfile = io.BytesIO()

    return handler


def generate_self_signed_cert(cert_path, key_path):
    """Generate a self-signed certificate for testing."""
    from subprocess import DEVNULL, run

    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


def https_request(host, port, method="GET", path="/", headers=None):
    """Make a raw HTTPS request using SSL sockets."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    ssl_sock = context.wrap_socket(sock, server_hostname=host)
    try:
        ssl_sock.connect((host, port))
        request_lines = [f"{method} {path} HTTP/1.1"]
        request_lines.append(f"Host: {host}:{port}")
        request_lines.append("Connection: close")
        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
        request_lines.append("")
        request_lines.append("")
        request = "\r\n".join(request_lines)
        ssl_sock.sendall(request.encode())

        response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode("utf-8", errors="replace")
    finally:
        ssl_sock.close()


class TestHTTPSServer:
    """Test cases for HTTPSServer class."""

    def test_https_server_stores_ssl_attributes(self):
        """Test that HTTPSServer stores SSL configuration attributes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            server = HTTPSServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
                bind_and_activate=False,
                certifile=cert_file,
                keyfile=key_file,
                password=None,
            )

            assert server.certifile == cert_file
            assert server.keyfile == key_file
            assert server.password is None
            assert server.alpn_protocols == ["http/1.1"]
            server.server_close()

    def test_https_server_custom_alpn_protocols(self):
        """Test that HTTPSServer accepts custom ALPN protocols."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            custom_protocols = ["h2", "http/1.1"]
            server = HTTPSServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
                bind_and_activate=False,
                certifile=cert_file,
                keyfile=key_file,
                alpn_protocols=custom_protocols,
            )

            assert server.alpn_protocols == custom_protocols
            server.server_close()

    def test_https_server_inherits_from_httpserver(self):
        """Test that HTTPSServer inherits from HTTPServer."""
        assert issubclass(HTTPSServer, HTTPServer)

    def test_https_server_has_allow_reuse_address(self):
        """Test that HTTPSServer inherits allow_reuse_address."""
        assert HTTPSServer.allow_reuse_address is True

    def test_https_server_create_context(self):
        """Test that HTTPSServer._create_context creates an SSL context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            server = HTTPSServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
                bind_and_activate=False,
                certifile=cert_file,
                keyfile=key_file,
            )

            context = server._create_context()
            assert isinstance(context, ssl.SSLContext)
            server.server_close()


class TestThreadingHTTPSServer:
    """Test cases for ThreadingHTTPSServer class."""

    def test_threading_https_server_inherits_from_https_server(self):
        """Test that ThreadingHTTPSServer inherits from HTTPSServer."""
        assert issubclass(ThreadingHTTPSServer, HTTPSServer)

    def test_threading_https_server_has_daemon_threads(self):
        """Test that ThreadingHTTPSServer has daemon_threads set to True."""
        assert ThreadingHTTPSServer.daemon_threads is True

    def test_threading_https_server_creation(self):
        """Test that ThreadingHTTPSServer can be created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            server = ThreadingHTTPSServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
                bind_and_activate=False,
                certifile=cert_file,
                keyfile=key_file,
            )

            assert server is not None
            server.server_close()


class TestHTTPSIntegration:
    """Integration tests for HTTPS server."""

    def test_https_serve_file(self):
        """Test serving a file over HTTPS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate self-signed certificate
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            # Create a test file
            test_content = b"Hello, HTTPS World!"
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "wb") as f:
                f.write(test_content)

            # Start HTTPS server
            server = HTTPSServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
                certifile=cert_file,
                keyfile=key_file,
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = https_request("127.0.0.1", port, path="/test.txt")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_https_serve_index_html(self):
        """Test serving index.html over HTTPS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate self-signed certificate
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            # Create index.html
            test_content = b"<html><body>HTTPS Index</body></html>"
            index_file = os.path.join(tmpdir, "index.html")
            with open(index_file, "wb") as f:
                f.write(test_content)

            # Start HTTPS server
            server = HTTPSServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
                certifile=cert_file,
                keyfile=key_file,
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = https_request("127.0.0.1", port, path="/")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_https_404_not_found(self):
        """Test 404 response over HTTPS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate self-signed certificate
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            # Start HTTPS server with empty directory
            server = HTTPSServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
                certifile=cert_file,
                keyfile=key_file,
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = https_request("127.0.0.1", port, path="/nonexistent.txt")
                status, headers, body = parse_response(response)
                assert status == 404
            finally:
                thread.join(timeout=5)
                server.server_close()

    def test_threading_https_serve_file(self):
        """Test serving a file using ThreadingHTTPSServer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate self-signed certificate
            cert_file = os.path.join(tmpdir, "cert.pem")
            key_file = os.path.join(tmpdir, "key.pem")
            generate_self_signed_cert(cert_file, key_file)

            # Create a test file
            test_content = b"Hello, Threading HTTPS!"
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "wb") as f:
                f.write(test_content)

            # Start Threading HTTPS server
            server = ThreadingHTTPSServer(
                ("127.0.0.1", 0),
                lambda *args, **kwargs: SimpleHttpRequestHandler(
                    *args, directory=tmpdir, **kwargs
                ),
                certifile=cert_file,
                keyfile=key_file,
            )
            port = server.server_address[1]

            thread = threading.Thread(target=server.handle_request)
            thread.start()

            try:
                response = https_request("127.0.0.1", port, path="/test.txt")
                status, headers, body = parse_response(response)
                assert status == 200
                assert test_content.decode() in body
            finally:
                thread.join(timeout=5)
                server.server_close()
