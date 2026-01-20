"""Generic socket server classes.

This module defines base classes for creating network servers using sockets.
These classes can be extended to implement specific server behaviors, such as handling HTTP requests.
"""

import os
import selectors
import socket
import sys
import threading
from io import BufferedIOBase
from time import monotonic as time

__all__ = [
    "BaseServer",
    "TCPServer",
    "UDPServer",
    "ThreadingUDPServer",
    "ThreadingTCPServer",
    "BaseRequestHandler",
    "StreamRequestHandler",
    "DatagramRequestHandler",
    "ThreadingMixIn",
]

if hasattr(os, "fork"):
    __all__.extend(["ForkingMixIn", "ForkingTCPServer", "ForkingUDPServer"])
if hasattr(socket, "AF_UNIX"):
    __all__.extend(
        [
            "UnixStreamServer",
            "UnixDatagramServer",
            "ThreadingUnixStreamServer",
            "ThreadingUnixDatagramServer",
        ]
    )
    if hasattr(os, "fork"):
        __all__.extend(["ForkingUnixStreamServer", "ForkingUnixDatagramServer"])

# poll/select have the advantage of not requiring any extra file descriptors
# contrarily to epoll/kqueue (which require a single syscall)
if hasattr(selectors, "PollSelector"):
    _Selector = selectors.PollSelector
else:
    _Selector = selectors.SelectSelector


class BaseServer:
    """Base class for all server classes.

    This class defines the basic interface for server classes, including methods
    for starting and stopping the server, and handling requests.
    """

    def __init__(self, server_address: tuple, RequestHandlerClass):
        """Contructor. May be extended, do not override."""
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False

    def server_activate(self) -> None:
        """Activate the server. May be overridden."""
        pass

    def server_forever(self, poll_interval=0.5) -> None:
        """Handle one request at a time until shutdown."""
        self.__is_shut_down.clear()

        try:
            with _Selector() as selector:
                selector.register(self.socket, selectors.EVENT_READ)

                while not self.__shutdown_request:
                    ready = selector.select(poll_interval)
                    if self.__shutdown_request:
                        break
                    if ready:
                        self._handle_request_noblock()

                    self.service_actions()
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def shutdown(self) -> None:
        """Stops the serve_forever loop."""
        self.__shutdown_request = True
        self.__is_shut_down.wait()

    def service_actions(self) -> None:
        """Called by the serve_forever() loop to perform periodic actions.

        Maybe overridden byu a subclass / Mixin.
        """
        pass

    def handle_request(self) -> None:
        """Handle one request, possibly blocking."""
        timeout = self.socket.gettimeout()
        if timeout is None:
            timeout = self.timeout
        elif self.timeout is not None:
            timeout = min(timeout, self.timeout)
        if timeout is not None:
            deadline = time() + timeout

        with _Selector() as selector:
            selector.register(self.socket, selectors.EVENT_READ)

            while True:
                if selector.select(timeout):
                    return self._handle_request_noblock()
                else:
                    if timeout is not None:
                        timeout = deadline - time()
                        if timeout < 0:
                            return self.handle_timeout()

    def _handle_request_noblock(self) -> None:
        """Handle one request, without blocking."""
        try:
            request, client_address = self.get_request()
        except OSError:
            return
        if self.verify_request(request, client_address):
            try:
                self.process_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except:
                self.shutdown_request(request)
                raise
        else:
            self.shutdown_request(request)

    def handle_timeout(self) -> None:
        """Called if no new request arrives within self.timeout. Maybe overridden."""
        pass

    def verify_request(self, request: socket.socket, client_address: tuple) -> bool:
        """Verify the request. May be overridden."""
        return True

    def process_request(self, request: socket.socket, client_address: tuple) -> None:
        """Process the request. May be overridden.

        Overridden by ForkingMixIn and ThreadingMixIn
        """
        self.finish_request(request, client_address)
        self.shutdown_request(request)

    def server_close(self) -> None:
        """Called to clean up the server. May be overridden."""
        pass

    def finish_request(self, request: socket.socket, client_address: tuple) -> None:
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self)

    def shutdown_request(self, request: socket.socket) -> None:
        """Called to shutdown and close an individual request."""
        self.close_request(request)

    def close_request(self, request: socket.socket) -> None:
        """Called to clean up an individual request."""
        pass

    def handle_error(self, request: socket.socket, client_address: tuple) -> None:
        """Handle an error gracefully. May be overridden."""
        print("-" * 40, file=sys.stderr)
        print(
            "Exception happened during processing of request from",
            client_address,
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc()
        print("-" * 40, file=sys.stderr)

    def __enter__(self):
        return self

    def __exit__(self):
        self.server_close()


class TcpServer(BaseServer):
    """Base class for various socket-based server classes."""

    address_family: int = socket.AF_INET
    socket_type: int = socket.SOCK_STREAM
    request_queue_size: int = 5

    allow_reuse_address: bool = False
    allow_reuse_port: bool = False

    def __init__(
        self, server_address: tuple, RequestHandlerClass, bind_and_activate: bool = True
    ):
        """Constructor. May be extended, do not override."""
        super().__init__(server_address, RequestHandlerClass)
        self.socket = socket.socket(self.address_family, self.socket_type)

        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise

    def server_bind(self) -> None:
        """Called by constructor to bind the socket. May be overridden."""
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Since Linux 6.12.9, SO_REUSEPORT is not allowed on other address families than
        # AF_INET and AF_INET6.
        if (
            hasattr(socket, "SO_REUSEPORT")
            and self.allow_reuse_port
            and self.address_family in (socket.AF_INET, socket.AF_INET6)
        ):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    def server_activate(self) -> None:
        """Activate the server. Maybe overridden."""
        self.socket.listen(self.request_queue_size)

    def server_close(self) -> None:
        """Called to clean up the server. May be overridden."""
        self.socket.close()

    def fileno(self) -> int:
        """Return the server socket file descriptor. Interface required by selector."""
        return self.socket.fileno()

    def get_request(self) -> tuple[socket.socket, tuple]:
        """Get the request and client address from the socket. May be overridden."""
        return self.socket.accept()

    def shutdown_request(self, request: socket.socket) -> None:
        """Called to shutdown and close an individual request."""
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # some platforms may raise ENOTCONN here
        self.close_request(request)


class UDPServer(TcpServer):
    """UDP server class."""

    allow_reuse_address: bool = False
    allow_reuse_port: bool = False
    socket_type: int = socket.SOCK_DGRAM
    max_packet_size: int = 65536

    def get_request(self) -> tuple[tuple[bytes, socket.socket], tuple]:
        """Get the request and client address from the socket. May be overridden."""
        data, client_address = self.socket.recvfrom(self.max_packet_size)
        return (data, self.socket), client_address

    def server_activate(self) -> None:
        """Activate the server. Maybe overridden."""
        pass  # No listen() for UDP

    def shutdown_request(self, request: tuple[bytes, socket.socket]) -> None:
        """Called to shutdown and close an individual request."""
        self.close_request(request)  # No shutdown for UDP sockets

    def close_request(self, request: tuple[bytes, socket.socket]) -> None:
        """Called to clean up an individual request."""
        pass  # No close for UDP sockets


# Fork
if hasattr(os, "fork"):

    class ForkingMixIn:
        """Mix-in class to handle each request in a new process."""

        timeout: int = 300
        active_children: set[int] | None = None
        max_children: int = 40
        # If true, server_close() will wait for all child processes to finish.
        block_on_close: bool = False

        def collect_children(self, *, blocking=False) -> None:
            """Internal routine to wait for child processes to terminate."""
            if self.active_children is None:
                return

            # If we're above the max number of children, wait and reap them until
            # we go back below threshold. Note that we use waitpid(-1) below to be
            # able to collect children in size(<defunct children>) syscalls instead
            # of size(<children>): the downside is that this might reap children
            # which we didn't spawn, which is why we only resort to this when we're
            # above max_children.
            while len(self.active_children) >= self.max_children:
                try:
                    pid, _ = os.waitpid(-1, 0)
                    self.active_children.discard(pid)
                except ChildProcessError:
                    # we don't have any child processes
                    self.active_children.clear()
                except OSError:
                    break

            # Now reap all defunct children
            for pid in self.active_children.copy():
                try:
                    flags = 0 if blocking else os.WNOHANG
                    pid, _ = os.waitpid(pid, flags)
                    # if the child hasn't exited yet, pid will be 0 and ignored
                    # by discard() below
                    self.active_children.discard(pid)
                except ChildProcessError:
                    self.active_children.discard(pid)
                except OSError:
                    pass

        def handle_timeout(self) -> None:
            """Wait for zombies after self.timeout seconds to inactively. May be extended, do not override."""
            self.collect_children()

        def service_actions(self) -> None:
            """Collect the zombie child processes regularly int the ForkingMixIn."""
            self.collect_children()

        def process_request(
            self, request: socket.socket, client_address: tuple
        ) -> None:
            """Fork a new process to handle the request."""
            pid = os.fork()
            if pid:
                # parent process
                if self.active_children is None:
                    self.active_children = set()
                self.active_children.add(pid)
                self.close_request(request)
                return
            else:
                # child process
                status: int = 1
                try:
                    self.finish_request(request, client_address)
                    status = 0
                except:
                    self.handle_error(request, client_address)
                finally:
                    try:
                        self.shutdown_request(request)
                    finally:
                        os._exit(status)

        def server_close(self) -> None:
            """Called to clean up the server."""
            super().server_close()
            self.collect_children(blocking=self.block_on_close)


class _Threads(list):
    """Joinable list of all non-daemon thread."""

    def append(self, thread: threading.Thread) -> None:
        """Append a non-daemon thread to the list."""
        self.reap()
        if thread.daemon:
            return
        super().append(thread)

    def pop_all(self) -> list[threading.Thread]:
        """Pop all threads from the list."""
        self[:], result = [], self[:]
        return result

    def join(self) -> None:
        """Join all non-daemon threads."""
        for thread in self.pop_all():
            thread.join()

    def reap(self) -> None:
        """Remove all non-alive threads from the list."""
        self[:] = (thread for thread in self if thread.is_alive())


class _NoThreads:
    """Degenerate version of _Threads."""

    def append(self, thread: threading.Thread) -> None:
        pass

    def join(self) -> None:
        pass


# Threading
class ThreadingMixIn:
    """Mix-in class to handle each request in a new thread."""

    daemon_threads: bool = False
    block_on_close: bool = True
    _threads = _NoThreads()

    def process_request_thread(
        self, request: socket.socket, client_address: tuple
    ) -> None:
        """Handle the request in a separate thread."""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def process_request(self, request: socket.socket, client_address: tuple) -> None:
        """Start a new thread to process the request."""
        if self.block_on_close:
            vars(self).setdefault("_threads", _Threads())

        t = threading.Thread(
            target=self.process_request_thread, args=(request, client_address)
        )
        t.daemon = self.daemon_threads
        self._threads.append(t)
        t.start()

    def server_close(self) -> None:
        """Called to clean up the server."""
        super().server_close()
        self._threads.join()


if hasattr(os, "fork"):

    class ForkingUDPServer(ForkingMixIn, UDPServer):
        """UDP server class with ForkingMixIn."""

        pass

    class ForkingTCPServer(ForkingMixIn, TcpServer):
        """TCP server class with ForkingMixIn."""

        pass


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    """UDP server class with ThreadingMixIn."""

    pass


class ThreadingTCPServer(ThreadingMixIn, TcpServer):
    """TCP server class with ThreadingMixIn."""

    pass


if hasattr(socket, "AF_UNIX"):

    class UnixStreamServer(TcpServer):
        """Unix domain stream server class."""

        address_family: int = socket.AF_UNIX

    class UnixDatagramServer(UDPServer):
        """Unix domain datagram server class."""

        address_family: int = socket.AF_UNIX

    class ThreadingUnixStreamServer(ThreadingMixIn, UnixStreamServer):
        """Unix domain stream server class with ThreadingMixIn."""

        pass

    class ThreadingUnixDatagramServer(ThreadingMixIn, UnixDatagramServer):
        """Unix domain datagram server class with ThreadingMixIn."""

        pass


class BaseRequestHandler:
    """Base class for request handler classes."""

    def __init__(
        self, request: socket.socket, client_address: tuple, server: BaseServer
    ):
        """Constructor. May be extended, do not override."""
        self.request = request
        self.client_address = client_address
        self.server = server
        self.setup()
        try:
            self.handle()
        finally:
            self.finish()

    def setup(self) -> None:
        """Initialize the request handler. May be overridden."""
        pass

    def handle(self) -> None:
        """Handle the request. Must be overridden."""
        raise NotImplementedError("Must be overridden by subclass.")

    def finish(self) -> None:
        """Clean up the request handler. May be overridden."""
        pass


# The following two classes make it possible to use the same service
# class for stream or datagram services.
class StreamRequestHandler(BaseRequestHandler):
    """Define self.rfile and self.wfile for stream (TCP) requests."""

    rbufsize: int = -1
    wbufsize: int = 0

    timeout: float | None = None
    disable_nagle_algorithm: bool = False

    def setup(self) -> None:
        """Initialize rfile and wfile."""
        self.connection = self.request
        if self.timeout is not None:
            self.connection.settimeout(self.timeout)
        if self.disable_nagle_algorithm:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        if self.wbufsize == 0:
            self.wfile = _SocketWriter(self.connection)
        else:
            self.wfile = self.connection.makefile("wb", self.wbufsize)

    def finish(self) -> None:
        """Clean up rfile and wfile."""
        if not self.wfile.closed:
            try:
                self.wfile.flush()
            except socket.error:
                # A final socket error may have occurred here, such
                # as the local error ECONNABORTED.
                pass
        self.wfile.close()
        self.rfile.close()


class _SocketWriter(BufferedIOBase):
    """Simple writable BufferedIOBase implementation for a socket."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    def writable(self) -> bool:
        return True

    def write(self, b: bytes) -> int:
        self._sock.sendall(b)
        with memoryview(b) as mv:
            return mv.nbytes

    def fileno(self) -> int:
        return self._sock.fileno()


class DatagramRequestHandler(BaseRequestHandler):
    """Define self.rfile and self.wfile for datagram (UDP) requests."""

    def setup(self) -> None:
        from io import BytesIO

        self.packet, self.socket = self.request
        self.rfile = BytesIO(self.packet)
        self.wfile = BytesIO()

    def finish(self) -> None:
        """Send the response packet."""
        self.socket.sendto(self.wfile.getvalue(), self.client_address)
