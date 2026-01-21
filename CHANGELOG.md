# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Socket server module (`src/socket/socketserver.py`) with:
  - `BaseServer` - Abstract base class for all servers
  - `TCPServer` - TCP/IP socket server
  - `UDPServer` - UDP socket server
  - `ThreadingMixIn` - Mix-in for handling requests in separate threads
  - `ForkingMixIn` - Mix-in for handling requests in separate processes (Unix only)
  - `ThreadingTCPServer`, `ThreadingUDPServer` - Pre-mixed threading servers
  - `ForkingTCPServer`, `ForkingUDPServer` - Pre-mixed forking servers (Unix only)
  - `UnixStreamServer`, `UnixDatagramServer` - Unix domain socket servers
  - `BaseRequestHandler`, `StreamRequestHandler`, `DatagramRequestHandler` - Request handler classes
- Comprehensive test suite for socketserver module (`tests/test_socketserver.py`)
- Host header validation for HTTP/1.1 requests

### Changed
- HTTP server now uses local socketserver module instead of standard library

## [0.1.0] - 2025-11-13

### Added
- Initial release
- Project scaffolding
