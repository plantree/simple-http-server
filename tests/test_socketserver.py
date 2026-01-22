"""Tests for socket server classes."""

import os
import socket
import threading
import time

import pytest
from src.socket.socketserver import (
    BaseRequestHandler,
    BaseServer,
    DatagramRequestHandler,
    StreamRequestHandler,
    TCPServer,
    ThreadingMixIn,
    ThreadingTCPServer,
    ThreadingUDPServer,
    UDPServer,
    _NoThreads,
    _SocketWriter,
    _Threads,
)

# Check if forking is available
HAS_FORK = hasattr(os, "fork")
if HAS_FORK:
    from src.socket.socketserver import (
        ForkingMixIn,
        ForkingTCPServer,
        ForkingUDPServer,
    )

# Check if Unix sockets are available
HAS_UNIX_SOCKETS = hasattr(socket, "AF_UNIX")
if HAS_UNIX_SOCKETS:
    from src.socket.socketserver import (  # noqa: F401
        ThreadingUnixDatagramServer,
        ThreadingUnixStreamServer,
        UnixDatagramServer,
        UnixStreamServer,
    )


class EchoHandler(BaseRequestHandler):
    """Simple echo handler for testing."""

    def handle(self):
        pass


class EchoStreamHandler(StreamRequestHandler):
    """Echo handler for TCP streams."""

    def handle(self):
        data = self.rfile.readline()
        self.wfile.write(data)


class EchoDatagramHandler(DatagramRequestHandler):
    """Echo handler for UDP datagrams."""

    def handle(self):
        data = self.rfile.read()
        self.wfile.write(data)


# =============================================================================
# BaseServer Tests
# =============================================================================


class TestBaseServer:
    """Test cases for BaseServer class."""

    def test_init(self):
        """Test BaseServer initialization."""
        handler = EchoHandler
        server = BaseServer(("127.0.0.1", 8000), handler)
        assert server.server_address == ("127.0.0.1", 8000)
        assert server.RequestHandlerClass == handler

    def test_server_activate_default(self):
        """Test that server_activate does nothing by default."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        # Should not raise
        server.server_activate()

    def test_get_request_not_implemented(self):
        """Test that get_request raises NotImplementedError."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        with pytest.raises(NotImplementedError):
            server.get_request()

    def test_verify_request_default(self):
        """Test that verify_request returns True by default."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        assert server.verify_request(None, None) is True

    def test_handle_timeout_default(self):
        """Test that handle_timeout does nothing by default."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        # Should not raise
        server.handle_timeout()

    def test_server_close_default(self):
        """Test that server_close does nothing by default."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        # Should not raise
        server.server_close()

    def test_context_manager(self):
        """Test BaseServer as context manager."""
        server = BaseServer(("127.0.0.1", 8000), EchoHandler)
        with server as s:
            assert s is server
        # server_close should have been called (no error)


# =============================================================================
# TCPServer Tests
# =============================================================================


class TestTCPServer:
    """Test cases for TCPServer class."""

    def test_creation(self):
        """Test TCPServer can be created and binds to a port."""
        server = TCPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        assert server.server_address[0] == "127.0.0.1"
        assert server.server_address[1] > 0  # Port assigned
        server.server_close()

    def test_address_family(self):
        """Test default address family is AF_INET."""
        assert TCPServer.address_family == socket.AF_INET

    def test_socket_type(self):
        """Test socket type is SOCK_STREAM."""
        assert TCPServer.socket_type == socket.SOCK_STREAM

    def test_request_queue_size(self):
        """Test default request queue size."""
        assert TCPServer.request_queue_size == 5

    def test_allow_reuse_address_default(self):
        """Test allow_reuse_address is False by default."""
        assert TCPServer.allow_reuse_address is False

    def test_allow_reuse_port_default(self):
        """Test allow_reuse_port is False by default."""
        assert TCPServer.allow_reuse_port is False

    def test_fileno(self):
        """Test fileno returns socket file descriptor."""
        server = TCPServer(("127.0.0.1", 0), EchoHandler)
        assert server.fileno() == server.socket.fileno()
        server.server_close()

    def test_get_request(self):
        """Test get_request accepts a connection."""
        server = TCPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]

        def connect():
            time.sleep(0.1)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", port))
            client.close()

        thread = threading.Thread(target=connect)
        thread.start()

        conn, addr = server.get_request()
        assert conn is not None
        assert addr[0] == "127.0.0.1"
        conn.close()
        thread.join()
        server.server_close()

    def test_context_manager(self):
        """Test TCPServer as context manager."""
        with TCPServer(("127.0.0.1", 0), EchoHandler) as server:
            assert server.socket is not None
        # Socket should be closed after exiting context

    def test_bind_and_activate_false(self):
        """Test creating server without binding."""
        server = TCPServer(("127.0.0.1", 0), EchoHandler, bind_and_activate=False)
        # Socket created but not bound
        assert server.socket is not None
        server.server_close()

    def test_server_bind_reuse_address(self):
        """Test server_bind with allow_reuse_address."""

        class ReuseAddrServer(TCPServer):
            allow_reuse_address = True

        server = ReuseAddrServer(("127.0.0.1", 0), EchoHandler)
        assert server.server_address[1] > 0
        server.server_close()


# =============================================================================
# UDPServer Tests
# =============================================================================


class TestUDPServer:
    """Test cases for UDPServer class."""

    def test_creation(self):
        """Test UDPServer can be created."""
        server = UDPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        assert server.server_address[1] > 0
        server.server_close()

    def test_socket_type(self):
        """Test socket type is SOCK_DGRAM."""
        assert UDPServer.socket_type == socket.SOCK_DGRAM

    def test_max_packet_size(self):
        """Test default max packet size."""
        assert UDPServer.max_packet_size == 65536

    def test_server_activate_does_nothing(self):
        """Test server_activate does nothing for UDP."""
        server = UDPServer(("127.0.0.1", 0), EchoHandler)
        # Should not raise
        server.server_activate()
        server.server_close()

    def test_get_request(self):
        """Test get_request receives UDP data."""
        server = UDPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]

        def send_data():
            time.sleep(0.1)
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(b"hello", ("127.0.0.1", port))
            client.close()

        thread = threading.Thread(target=send_data)
        thread.start()

        (data, sock), addr = server.get_request()
        assert data == b"hello"
        assert sock is server.socket
        thread.join()
        server.server_close()


# =============================================================================
# ThreadingMixIn Tests
# =============================================================================


class TestThreadingMixIn:
    """Test cases for ThreadingMixIn class."""

    def test_daemon_threads_default(self):
        """Test daemon_threads is False by default."""
        assert ThreadingMixIn.daemon_threads is False

    def test_block_on_close_default(self):
        """Test block_on_close is True by default."""
        assert ThreadingMixIn.block_on_close is True


class TestThreadingTCPServer:
    """Test cases for ThreadingTCPServer class."""

    def test_creation(self):
        """Test ThreadingTCPServer can be created."""
        server = ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        server.server_close()

    def test_inherits_threading_mixin(self):
        """Test ThreadingTCPServer inherits from ThreadingMixIn."""
        assert issubclass(ThreadingTCPServer, ThreadingMixIn)
        assert issubclass(ThreadingTCPServer, TCPServer)


class TestThreadingUDPServer:
    """Test cases for ThreadingUDPServer class."""

    def test_creation(self):
        """Test ThreadingUDPServer can be created."""
        server = ThreadingUDPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        server.server_close()

    def test_inherits_threading_mixin(self):
        """Test ThreadingUDPServer inherits from ThreadingMixIn."""
        assert issubclass(ThreadingUDPServer, ThreadingMixIn)
        assert issubclass(ThreadingUDPServer, UDPServer)


# =============================================================================
# ForkingMixIn Tests (Unix only)
# =============================================================================


@pytest.mark.skipif(not HAS_FORK, reason="Forking not available on this platform")
class TestForkingMixIn:
    """Test cases for ForkingMixIn class."""

    def test_timeout_default(self):
        """Test timeout is 300 by default."""
        assert ForkingMixIn.timeout == 300

    def test_max_children_default(self):
        """Test max_children is 40 by default."""
        assert ForkingMixIn.max_children == 40

    def test_block_on_close_default(self):
        """Test block_on_close is False by default."""
        assert ForkingMixIn.block_on_close is False

    def test_active_children_default(self):
        """Test active_children is None by default."""
        assert ForkingMixIn.active_children is None


@pytest.mark.skipif(not HAS_FORK, reason="Forking not available on this platform")
class TestForkingTCPServer:
    """Test cases for ForkingTCPServer class."""

    def test_creation(self):
        """Test ForkingTCPServer can be created."""
        server = ForkingTCPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        server.server_close()

    def test_inherits_forking_mixin(self):
        """Test ForkingTCPServer inherits from ForkingMixIn."""
        assert issubclass(ForkingTCPServer, ForkingMixIn)
        assert issubclass(ForkingTCPServer, TCPServer)


@pytest.mark.skipif(not HAS_FORK, reason="Forking not available on this platform")
class TestForkingUDPServer:
    """Test cases for ForkingUDPServer class."""

    def test_creation(self):
        """Test ForkingUDPServer can be created."""
        server = ForkingUDPServer(("127.0.0.1", 0), EchoHandler)
        assert server.socket is not None
        server.server_close()


# =============================================================================
# Unix Socket Tests (Unix only)
# =============================================================================


@pytest.mark.skipif(
    not HAS_UNIX_SOCKETS, reason="Unix sockets not available on this platform"
)
class TestUnixStreamServer:
    """Test cases for UnixStreamServer class."""

    def test_address_family(self):
        """Test address family is AF_UNIX."""
        assert UnixStreamServer.address_family == socket.AF_UNIX


@pytest.mark.skipif(
    not HAS_UNIX_SOCKETS, reason="Unix sockets not available on this platform"
)
class TestUnixDatagramServer:
    """Test cases for UnixDatagramServer class."""

    def test_address_family(self):
        """Test address family is AF_UNIX."""
        assert UnixDatagramServer.address_family == socket.AF_UNIX


# =============================================================================
# BaseRequestHandler Tests
# =============================================================================


class TestBaseRequestHandler:
    """Test cases for BaseRequestHandler class."""

    def test_handle_not_implemented(self):
        """Test that handle raises NotImplementedError."""

        class TestHandler(BaseRequestHandler):
            pass

        # Create a mock socket
        mock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket.bind(("127.0.0.1", 0))

        with pytest.raises(NotImplementedError):
            TestHandler(mock_socket, ("127.0.0.1", 12345), None)

        mock_socket.close()


# =============================================================================
# StreamRequestHandler Tests
# =============================================================================


class TestStreamRequestHandler:
    """Test cases for StreamRequestHandler class."""

    def test_rbufsize_default(self):
        """Test rbufsize is -1 by default."""
        assert StreamRequestHandler.rbufsize == -1

    def test_wbufsize_default(self):
        """Test wbufsize is 0 by default."""
        assert StreamRequestHandler.wbufsize == 0

    def test_timeout_default(self):
        """Test timeout is None by default."""
        assert StreamRequestHandler.timeout is None

    def test_disable_nagle_default(self):
        """Test disable_nagle_algorithm is False by default."""
        assert StreamRequestHandler.disable_nagle_algorithm is False


# =============================================================================
# _Threads Tests
# =============================================================================


class TestThreads:
    """Test cases for _Threads helper class."""

    def test_append_non_daemon(self):
        """Test appending non-daemon thread."""
        threads = _Threads()
        t = threading.Thread(target=lambda: None)
        t.daemon = False
        threads.append(t)
        assert len(threads) == 1

    def test_append_daemon_ignored(self):
        """Test daemon threads are not appended."""
        threads = _Threads()
        t = threading.Thread(target=lambda: None)
        t.daemon = True
        threads.append(t)
        assert len(threads) == 0

    def test_pop_all(self):
        """Test pop_all returns all threads and clears list."""
        threads = _Threads()
        t1 = threading.Thread(target=lambda: time.sleep(0.5))
        t2 = threading.Thread(target=lambda: time.sleep(0.5))
        t1.daemon = False
        t2.daemon = False
        t1.start()  # Start threads so they're alive during append
        t2.start()
        threads.append(t1)
        threads.append(t2)

        result = threads.pop_all()
        assert len(result) == 2
        assert len(threads) == 0

        # Clean up
        for t in result:
            t.join()

    def test_join(self):
        """Test join waits for all threads."""
        threads = _Threads()
        results = []

        def worker(n):
            time.sleep(0.05)
            results.append(n)

        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            t.daemon = False
            threads.append(t)
            t.start()

        threads.join()
        assert len(results) == 3

    def test_reap_removes_dead_threads(self):
        """Test reap removes non-alive threads."""
        threads = _Threads()
        t = threading.Thread(target=lambda: None)
        t.daemon = False
        t.start()
        t.join()  # Wait for thread to finish

        threads.append(t)  # append calls reap, so dead thread won't be added
        # The thread is dead, so it shouldn't be in the list after reap
        threads.reap()
        assert len(threads) == 0


class TestNoThreads:
    """Test cases for _NoThreads helper class."""

    def test_append_does_nothing(self):
        """Test append does nothing."""
        no_threads = _NoThreads()
        t = threading.Thread(target=lambda: None)
        no_threads.append(t)
        # No error, no effect

    def test_join_does_nothing(self):
        """Test join does nothing."""
        no_threads = _NoThreads()
        no_threads.join()
        # No error, no effect


# =============================================================================
# _SocketWriter Tests
# =============================================================================


class TestSocketWriter:
    """Test cases for _SocketWriter class."""

    def test_writable(self):
        """Test writable returns True."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        writer = _SocketWriter(sock)
        assert writer.writable() is True
        sock.close()

    def test_fileno(self):
        """Test fileno returns socket file descriptor."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        writer = _SocketWriter(sock)
        assert writer.fileno() == sock.fileno()
        sock.close()


# =============================================================================
# Integration Tests
# =============================================================================


class TestTCPServerIntegration:
    """Integration tests for TCP server."""

    def test_handle_request(self):
        """Test handling a single TCP request."""
        received = []

        class RecordingHandler(StreamRequestHandler):
            def handle(self):
                data = self.rfile.readline()
                received.append(data)
                self.wfile.write(b"OK\n")

        server = TCPServer(("127.0.0.1", 0), RecordingHandler)
        port = server.server_address[1]

        def client():
            time.sleep(0.1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", port))
            sock.sendall(b"hello\n")
            response = sock.recv(1024)
            sock.close()
            return response

        client_thread = threading.Thread(target=client)
        client_thread.start()

        server.handle_request()
        client_thread.join()

        assert received == [b"hello\n"]
        server.server_close()

    def test_serve_forever_and_shutdown(self):
        """Test serve_forever can be stopped with shutdown."""
        server = ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()

        time.sleep(0.1)  # Let server start

        server.shutdown()
        server_thread.join(timeout=2)
        assert not server_thread.is_alive()
        server.server_close()


class TestUDPServerIntegration:
    """Integration tests for UDP server."""

    def test_handle_request(self):
        """Test handling a single UDP request."""
        received = []

        class RecordingHandler(DatagramRequestHandler):
            def handle(self):
                data = self.rfile.read()
                received.append(data)

        server = UDPServer(("127.0.0.1", 0), RecordingHandler)
        port = server.server_address[1]

        def client():
            time.sleep(0.1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"hello", ("127.0.0.1", port))
            sock.close()

        client_thread = threading.Thread(target=client)
        client_thread.start()

        server.handle_request()
        client_thread.join()

        assert received == [b"hello"]
        server.server_close()
