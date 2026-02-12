"""Unit tests for utils.config module."""

import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from fortimanager_mcp.utils.config import Settings, get_settings


class TestSettings:
    """Test Settings class."""

    def test_init_minimal(self):
        """Test initialization with minimal required fields."""
        settings = Settings(FORTIMANAGER_HOST="192.168.1.1")
        assert settings.FORTIMANAGER_HOST == "192.168.1.1"
        assert settings.FORTIMANAGER_API_TOKEN is None
        assert settings.FORTIMANAGER_USERNAME is None
        assert settings.FORTIMANAGER_PASSWORD is None
        assert settings.FORTIMANAGER_VERIFY_SSL is True
        assert settings.FORTIMANAGER_TIMEOUT == 30
        assert settings.FORTIMANAGER_MAX_RETRIES == 3

    def test_init_with_token_auth(self):
        """Test initialization with API token auth."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_API_TOKEN="test-token-123",
        )
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"
        assert settings.FORTIMANAGER_API_TOKEN == "test-token-123"

    def test_init_with_session_auth(self):
        """Test initialization with session-based auth."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_USERNAME="admin",
            FORTIMANAGER_PASSWORD="password",
        )
        assert settings.FORTIMANAGER_USERNAME == "admin"
        assert settings.FORTIMANAGER_PASSWORD == "password"

    def test_init_missing_host(self):
        """Test initialization without required host."""
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "FORTIMANAGER_HOST" in str(exc_info.value)

    def test_validate_host_removes_https(self):
        """Test host validator removes https protocol."""
        settings = Settings(FORTIMANAGER_HOST="https://fmg.example.com")
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"

    def test_validate_host_removes_http(self):
        """Test host validator removes http protocol."""
        settings = Settings(FORTIMANAGER_HOST="http://fmg.example.com")
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"

    def test_validate_host_removes_trailing_slash(self):
        """Test host validator removes trailing slash."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com/")
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"

    def test_validate_host_complex(self):
        """Test host validator with protocol and trailing slash."""
        settings = Settings(FORTIMANAGER_HOST="https://fmg.example.com:8443/")
        assert settings.FORTIMANAGER_HOST == "fmg.example.com:8443"

    def test_has_token_auth_true(self):
        """Test has_token_auth property when token is set."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_API_TOKEN="test-token",
        )
        assert settings.has_token_auth is True

    def test_has_token_auth_false(self):
        """Test has_token_auth property when token is not set."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.has_token_auth is False

    def test_has_session_auth_true(self):
        """Test has_session_auth property when credentials are set."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_USERNAME="admin",
            FORTIMANAGER_PASSWORD="password",
        )
        assert settings.has_session_auth is True

    def test_has_session_auth_false_no_username(self):
        """Test has_session_auth property when username is missing."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_PASSWORD="password",
        )
        assert settings.has_session_auth is False

    def test_has_session_auth_false_no_password(self):
        """Test has_session_auth property when password is missing."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_USERNAME="admin",
        )
        assert settings.has_session_auth is False

    def test_has_forticloud_auth_true(self):
        """Test has_forticloud_auth property when configured."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTICLOUD_AUTH=True,
            FORTIMANAGER_USERNAME="admin",
            FORTIMANAGER_PASSWORD="password",
        )
        assert settings.has_forticloud_auth is True

    def test_has_forticloud_auth_false_not_enabled(self):
        """Test has_forticloud_auth property when not enabled."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTICLOUD_AUTH=False,
            FORTIMANAGER_USERNAME="admin",
            FORTIMANAGER_PASSWORD="password",
        )
        assert settings.has_forticloud_auth is False

    def test_has_forticloud_auth_false_no_credentials(self):
        """Test has_forticloud_auth property when credentials missing."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTICLOUD_AUTH=True,
        )
        assert settings.has_forticloud_auth is False

    def test_base_url(self):
        """Test base_url property."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.base_url == "https://fmg.example.com/jsonrpc"

    def test_base_url_with_port(self):
        """Test base_url property with custom port."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com:8443")
        assert settings.base_url == "https://fmg.example.com:8443/jsonrpc"

    def test_mcp_server_defaults(self):
        """Test MCP server default settings."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.MCP_SERVER_HOST == "0.0.0.0"
        assert settings.MCP_SERVER_PORT == 8000
        assert settings.MCP_SERVER_MODE == "auto"

    def test_tool_mode_default(self):
        """Test tool mode default setting."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.FMG_TOOL_MODE == "full"

    def test_log_level_default(self):
        """Test log level default setting."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.LOG_LEVEL == "INFO"

    def test_test_adom_default(self):
        """Test TEST_ADOM default."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.TEST_ADOM == "root"

    def test_test_skip_write_tests_default(self):
        """Test TEST_SKIP_WRITE_TESTS default."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        assert settings.TEST_SKIP_WRITE_TESTS is False

    def test_timeout_validation_min(self):
        """Test timeout validation minimum value."""
        with pytest.raises(ValidationError):
            Settings(FORTIMANAGER_HOST="fmg.example.com", FORTIMANAGER_TIMEOUT=0)

    def test_timeout_validation_max(self):
        """Test timeout validation maximum value."""
        with pytest.raises(ValidationError):
            Settings(FORTIMANAGER_HOST="fmg.example.com", FORTIMANAGER_TIMEOUT=301)

    def test_max_retries_validation_min(self):
        """Test max retries validation minimum value."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com", FORTIMANAGER_MAX_RETRIES=0
        )
        assert settings.FORTIMANAGER_MAX_RETRIES == 0

    def test_max_retries_validation_max(self):
        """Test max retries validation maximum value."""
        with pytest.raises(ValidationError):
            Settings(FORTIMANAGER_HOST="fmg.example.com", FORTIMANAGER_MAX_RETRIES=11)

    def test_port_validation_min(self):
        """Test port validation minimum value."""
        with pytest.raises(ValidationError):
            Settings(FORTIMANAGER_HOST="fmg.example.com", MCP_SERVER_PORT=0)

    def test_port_validation_max(self):
        """Test port validation maximum value."""
        with pytest.raises(ValidationError):
            Settings(FORTIMANAGER_HOST="fmg.example.com", MCP_SERVER_PORT=65536)

    def test_configure_logging(self):
        """Test configure_logging method."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com", LOG_LEVEL="DEBUG")
        
        # Mock basicConfig to avoid affecting test logging
        with patch("logging.basicConfig") as mock_config:
            settings.configure_logging()
            mock_config.assert_called_once()
            call_kwargs = mock_config.call_args[1]
            assert call_kwargs["level"] == logging.DEBUG

    def test_get_log_handlers_console_only(self):
        """Test _get_log_handlers with console only."""
        settings = Settings(FORTIMANAGER_HOST="fmg.example.com")
        handlers = settings._get_log_handlers()
        assert len(handlers) == 1
        assert isinstance(handlers[0], logging.StreamHandler)

    def test_get_log_handlers_with_file(self, tmp_path):
        """Test _get_log_handlers with file handler."""
        log_file = tmp_path / "test.log"
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            LOG_FILE=str(log_file),
        )
        handlers = settings._get_log_handlers()
        assert len(handlers) == 2
        assert isinstance(handlers[0], logging.StreamHandler)
        assert isinstance(handlers[1], logging.FileHandler)


class TestGetSettings:
    """Test get_settings function."""

    def test_get_settings_returns_settings(self, monkeypatch):
        """Test get_settings returns Settings instance."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "fmg.example.com")
        
        # Clear the cache
        get_settings.cache_clear()
        
        settings = get_settings()
        assert isinstance(settings, Settings)
        assert settings.FORTIMANAGER_HOST == "fmg.example.com"

    def test_get_settings_cached(self, monkeypatch):
        """Test get_settings returns cached instance."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "fmg.example.com")
        
        # Clear the cache
        get_settings.cache_clear()
        
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_get_settings_missing_required(self, monkeypatch):
        """Test get_settings raises error when required settings missing."""
        # Clear any existing env vars
        monkeypatch.delenv("FORTIMANAGER_HOST", raising=False)
        
        # Clear the cache
        get_settings.cache_clear()
        
        with pytest.raises(ValidationError):
            get_settings()
