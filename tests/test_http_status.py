"""Tests for HTTPStatus enum."""

from http import HTTPStatus

import pytest


class TestHTTPStatus:
    """Test cases for HTTPStatus enum."""

    def test_status_value(self):
        """Test that status codes have correct integer values."""
        assert HTTPStatus.OK == 200
        assert HTTPStatus.NOT_FOUND == 404
        assert HTTPStatus.INTERNAL_SERVER_ERROR == 500

    def test_status_phrase(self):
        """Test that status codes have correct phrases."""
        assert HTTPStatus.OK.phrase == "OK"
        assert HTTPStatus.NOT_FOUND.phrase == "Not Found"
        assert HTTPStatus.BAD_REQUEST.phrase == "Bad Request"

    def test_status_description(self):
        """Test that status codes have descriptions."""
        assert "succeeded" in HTTPStatus.OK.description.lower()
        assert "not be found" in HTTPStatus.NOT_FOUND.description.lower()

    def test_is_informational(self):
        """Test is_informational property."""
        assert HTTPStatus.CONTINUE.is_informational is True
        assert HTTPStatus.SWITCHING_PROTOCOLS.is_informational is True
        assert HTTPStatus.OK.is_informational is False
        assert HTTPStatus.NOT_FOUND.is_informational is False

    def test_is_success(self):
        """Test is_success property."""
        assert HTTPStatus.OK.is_success is True
        assert HTTPStatus.CREATED.is_success is True
        assert HTTPStatus.NO_CONTENT.is_success is True
        assert HTTPStatus.NOT_FOUND.is_success is False
        assert HTTPStatus.CONTINUE.is_success is False

    def test_is_redirection(self):
        """Test is_redirection property."""
        assert HTTPStatus.MOVED_PERMANENTLY.is_redirection is True
        assert HTTPStatus.FOUND.is_redirection is True
        assert HTTPStatus.NOT_MODIFIED.is_redirection is True
        assert HTTPStatus.OK.is_redirection is False
        assert HTTPStatus.NOT_FOUND.is_redirection is False

    def test_is_client_error(self):
        """Test is_client_error property."""
        assert HTTPStatus.BAD_REQUEST.is_client_error is True
        assert HTTPStatus.NOT_FOUND.is_client_error is True
        assert HTTPStatus.METHOD_NOT_ALLOWED.is_client_error is True
        assert HTTPStatus.OK.is_client_error is False
        assert HTTPStatus.INTERNAL_SERVER_ERROR.is_client_error is False

    def test_is_server_error(self):
        """Test is_server_error property."""
        assert HTTPStatus.INTERNAL_SERVER_ERROR.is_server_error is True
        assert HTTPStatus.BAD_GATEWAY.is_server_error is True
        assert HTTPStatus.SERVICE_UNAVAILABLE.is_server_error is True
        assert HTTPStatus.OK.is_server_error is False
        assert HTTPStatus.NOT_FOUND.is_server_error is False

    def test_status_is_int(self):
        """Test that HTTPStatus values can be used as integers."""
        assert int(HTTPStatus.OK) == 200
        assert HTTPStatus.OK + 1 == 201
        assert HTTPStatus.NOT_FOUND > HTTPStatus.OK

    def test_all_status_codes_have_properties(self):
        """Test that all status codes have phrase and description."""
        for status in HTTPStatus:
            assert hasattr(status, "phrase")
            assert hasattr(status, "description")
            assert isinstance(status.phrase, str)
            assert isinstance(status.description, str)
            assert len(status.phrase) > 0
            assert len(status.description) > 0
