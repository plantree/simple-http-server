"""Tests for HTTPMethod enum."""

from http import HTTPMethod


class TestHTTPMethod:
    """Test cases for HTTPMethod enum."""

    def test_method_value(self):
        """Test that methods have correct string values."""
        assert HTTPMethod.GET == "GET"
        assert HTTPMethod.POST == "POST"
        assert HTTPMethod.PUT == "PUT"
        assert HTTPMethod.DELETE == "DELETE"

    def test_method_description(self):
        """Test that methods have descriptions."""
        assert "representation" in HTTPMethod.GET.description.lower()
        assert "submits" in HTTPMethod.POST.description.lower()
        assert "deletes" in HTTPMethod.DELETE.description.lower()

    def test_method_is_str(self):
        """Test that HTTPMethod values can be used as strings."""
        assert str(HTTPMethod.GET) == "GET"
        assert HTTPMethod.POST.upper() == "POST"
        assert HTTPMethod.DELETE.lower() == "delete"

    def test_method_repr(self):
        """Test the repr of HTTPMethod."""
        assert "HTTPMethod" in repr(HTTPMethod.GET)
        assert "GET" in repr(HTTPMethod.GET)

    def test_all_methods_have_description(self):
        """Test that all methods have descriptions."""
        for method in HTTPMethod:
            assert hasattr(method, "description")
            assert isinstance(method.description, str)
            assert len(method.description) > 0

    def test_standard_methods_exist(self):
        """Test that all standard HTTP methods are defined."""
        standard_methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "TRACE",
            "CONNECT",
        ]
        for method_name in standard_methods:
            assert hasattr(HTTPMethod, method_name)
            assert HTTPMethod[method_name] == method_name
