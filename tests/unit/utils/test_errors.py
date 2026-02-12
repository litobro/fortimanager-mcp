"""Unit tests for utils.errors module."""

import pytest

from fortimanager_mcp.utils.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
    FortiManagerError,
    PermissionError,
    ResourceNotFoundError,
    TimeoutError,
    ValidationError,
    parse_fmg_error,
)


class TestFortiManagerError:
    """Test FortiManagerError base class."""

    def test_init_basic(self):
        """Test basic initialization."""
        error = FortiManagerError("Test error")
        assert error.message == "Test error"
        assert error.code is None
        assert error.details == {}

    def test_init_with_code(self):
        """Test initialization with error code."""
        error = FortiManagerError("Test error", code=-1)
        assert error.message == "Test error"
        assert error.code == -1
        assert error.details == {}

    def test_init_with_details(self):
        """Test initialization with details."""
        details = {"url": "/api/test", "method": "POST"}
        error = FortiManagerError("Test error", details=details)
        assert error.message == "Test error"
        assert error.details == details

    def test_str_without_code(self):
        """Test string representation without code."""
        error = FortiManagerError("Test error")
        assert str(error) == "Test error"

    def test_str_with_code(self):
        """Test string representation with code."""
        error = FortiManagerError("Test error", code=-1)
        assert str(error) == "[Error -1] Test error"

    def test_to_dict(self):
        """Test dictionary serialization."""
        error = FortiManagerError("Test error", code=-1, details={"key": "value"})
        result = error.to_dict()
        assert result == {
            "error": "FortiManagerError",
            "message": "Test error",
            "code": -1,
            "details": {"key": "value"},
        }


class TestAuthenticationError:
    """Test AuthenticationError class."""

    def test_inheritance(self):
        """Test AuthenticationError inherits from FortiManagerError."""
        error = AuthenticationError("Auth failed")
        assert isinstance(error, FortiManagerError)

    def test_to_dict_class_name(self):
        """Test dictionary includes correct class name."""
        error = AuthenticationError("Auth failed")
        result = error.to_dict()
        assert result["error"] == "AuthenticationError"


class TestConnectionError:
    """Test ConnectionError class."""

    def test_inheritance(self):
        """Test ConnectionError inherits from FortiManagerError."""
        error = ConnectionError("Connection failed")
        assert isinstance(error, FortiManagerError)

    def test_to_dict_class_name(self):
        """Test dictionary includes correct class name."""
        error = ConnectionError("Connection failed")
        result = error.to_dict()
        assert result["error"] == "ConnectionError"


class TestAPIError:
    """Test APIError class."""

    def test_inheritance(self):
        """Test APIError inherits from FortiManagerError."""
        error = APIError("API error")
        assert isinstance(error, FortiManagerError)


class TestValidationError:
    """Test ValidationError class."""

    def test_inheritance(self):
        """Test ValidationError inherits from FortiManagerError."""
        error = ValidationError("Validation failed")
        assert isinstance(error, FortiManagerError)


class TestResourceNotFoundError:
    """Test ResourceNotFoundError class."""

    def test_inheritance(self):
        """Test ResourceNotFoundError inherits from FortiManagerError."""
        error = ResourceNotFoundError("Not found")
        assert isinstance(error, FortiManagerError)


class TestPermissionError:
    """Test PermissionError class."""

    def test_inheritance(self):
        """Test PermissionError inherits from FortiManagerError."""
        error = PermissionError("Permission denied")
        assert isinstance(error, FortiManagerError)


class TestTimeoutError:
    """Test TimeoutError class."""

    def test_inheritance(self):
        """Test TimeoutError inherits from FortiManagerError."""
        error = TimeoutError("Timeout")
        assert isinstance(error, FortiManagerError)


class TestParseFmgError:
    """Test parse_fmg_error function."""

    def test_parse_internal_error(self):
        """Test parsing internal error (-1)."""
        error = parse_fmg_error(-1, "Something went wrong")
        assert isinstance(error, APIError)
        assert "Internal error" in error.message
        assert error.code == -1

    def test_parse_object_exists(self):
        """Test parsing object exists error (-2)."""
        error = parse_fmg_error(-2, "Duplicate")
        assert isinstance(error, APIError)
        assert "Object already exists" in error.message
        assert error.code == -2

    def test_parse_object_not_found(self):
        """Test parsing object not found error (-3)."""
        error = parse_fmg_error(-3, "Missing")
        assert isinstance(error, ResourceNotFoundError)
        assert "Object does not exist" in error.message
        assert error.code == -3

    def test_parse_permission_denied(self):
        """Test parsing permission denied error (-4)."""
        error = parse_fmg_error(-4, "Access denied")
        assert isinstance(error, PermissionError)
        assert "Permission denied" in error.message
        assert error.code == -4

    def test_parse_invalid_format(self):
        """Test parsing invalid format error (-5)."""
        error = parse_fmg_error(-5, "Bad format")
        assert isinstance(error, ValidationError)
        assert "Invalid request format" in error.message
        assert error.code == -5

    def test_parse_invalid_argument(self):
        """Test parsing invalid argument error (-6)."""
        error = parse_fmg_error(-6, "Bad argument")
        assert isinstance(error, ValidationError)
        assert "Invalid argument" in error.message
        assert error.code == -6

    def test_parse_action_not_allowed(self):
        """Test parsing action not allowed error (-10)."""
        error = parse_fmg_error(-10, "Not allowed")
        assert isinstance(error, PermissionError)
        assert "Action not allowed" in error.message
        assert error.code == -10

    def test_parse_no_permission(self):
        """Test parsing no permission error (-11)."""
        error = parse_fmg_error(-11, "No access")
        assert isinstance(error, PermissionError)
        assert "No permission for the resource" in error.message
        assert error.code == -11

    def test_parse_session_expired(self):
        """Test parsing session expired error (-20)."""
        error = parse_fmg_error(-20, "Session timeout")
        assert isinstance(error, AuthenticationError)
        assert "Session expired" in error.message
        assert error.code == -20

    def test_parse_unknown_error(self):
        """Test parsing unknown error code."""
        error = parse_fmg_error(-999, "Unknown error")
        assert isinstance(error, APIError)
        assert error.message == "Unknown error"
        assert error.code == -999

    def test_parse_with_url(self):
        """Test parsing error with URL."""
        error = parse_fmg_error(-3, "Not found", url="/api/test")
        assert isinstance(error, ResourceNotFoundError)
        assert error.details["url"] == "/api/test"

    def test_parse_without_url(self):
        """Test parsing error without URL."""
        error = parse_fmg_error(-1, "Error")
        assert error.details == {}
