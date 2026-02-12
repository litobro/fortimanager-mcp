"""Unit tests for api.auth module."""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import httpx

from fortimanager_mcp.api.auth import (
    TokenAuthProvider,
    SessionAuthProvider,
    FortiCloudAuthProvider,
    create_auth_provider,
)
from fortimanager_mcp.utils.errors import AuthenticationError


class TestTokenAuthProvider:
    """Test TokenAuthProvider class."""

    def test_init(self):
        """Test initialization."""
        provider = TokenAuthProvider(api_token="test-token-123")
        assert provider.api_token == "test-token-123"

    async def test_authenticate_returns_none(self):
        """Test authenticate returns None for token auth."""
        provider = TokenAuthProvider(api_token="test-token")
        client = AsyncMock(spec=httpx.AsyncClient)
        
        result = await provider.authenticate(client, "https://fmg.example.com/jsonrpc")
        
        assert result is None
        client.post.assert_not_called()

    def test_get_headers(self):
        """Test get_headers returns bearer token."""
        provider = TokenAuthProvider(api_token="test-token-123")
        
        headers = provider.get_headers()
        
        assert headers == {
            "Authorization": "Bearer test-token-123",
            "Content-Type": "application/json",
        }

    async def test_logout_does_nothing(self):
        """Test logout does nothing for token auth."""
        provider = TokenAuthProvider(api_token="test-token")
        client = AsyncMock(spec=httpx.AsyncClient)
        
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "session123")
        
        client.post.assert_not_called()


class TestSessionAuthProvider:
    """Test SessionAuthProvider class."""

    def test_init(self):
        """Test initialization."""
        provider = SessionAuthProvider(username="admin", password="password123")
        assert provider.username == "admin"
        assert provider.password == "password123"
        assert provider._session_id is None

    async def test_authenticate_success(self):
        """Test successful authentication."""
        provider = SessionAuthProvider(username="admin", password="password123")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}}],
            "session": "test-session-id",
        }
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        session_id = await provider.authenticate(client, "https://fmg.example.com/jsonrpc")
        
        assert session_id == "test-session-id"
        assert provider._session_id == "test-session-id"
        assert provider.session_id == "test-session-id"
        
        client.post.assert_called_once()
        call_args = client.post.call_args
        assert call_args[0][0] == "https://fmg.example.com/jsonrpc"
        
        payload = call_args[1]["json"]
        assert payload["method"] == "exec"
        assert payload["params"][0]["url"] == "sys/login/user"
        assert payload["params"][0]["data"]["user"] == "admin"
        assert payload["params"][0]["data"]["passwd"] == "password123"

    async def test_authenticate_failure_no_result(self):
        """Test authentication failure with no result."""
        provider = SessionAuthProvider(username="admin", password="wrong")
        
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1}
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        with pytest.raises(AuthenticationError, match="No result in login response"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_failure_error_code(self):
        """Test authentication failure with error code."""
        provider = SessionAuthProvider(username="admin", password="wrong")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": -11, "message": "Invalid credentials"}}],
        }
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        with pytest.raises(AuthenticationError, match="Login failed: Invalid credentials"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_failure_no_session(self):
        """Test authentication failure with no session ID."""
        provider = SessionAuthProvider(username="admin", password="password")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}}],
        }
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        with pytest.raises(AuthenticationError, match="No session ID in login response"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_http_error(self):
        """Test authentication with HTTP error."""
        provider = SessionAuthProvider(username="admin", password="password")
        
        mock_response = Mock()
        mock_response.status_code = 500
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.HTTPStatusError(
            "Server error", request=Mock(), response=mock_response
        )
        
        with pytest.raises(AuthenticationError, match="HTTP error: 500"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_request_error(self):
        """Test authentication with request error."""
        provider = SessionAuthProvider(username="admin", password="password")
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.RequestError("Connection refused", request=Mock())
        
        with pytest.raises(AuthenticationError, match="Connection error"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_key_error(self):
        """Test authentication with unexpected response format."""
        provider = SessionAuthProvider(username="admin", password="password")
        
        mock_response = Mock()
        mock_response.json.return_value = {"id": 1, "result": [{}]}
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        with pytest.raises(AuthenticationError, match="Login failed: Unknown error"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    def test_get_headers(self):
        """Test get_headers returns content type."""
        provider = SessionAuthProvider(username="admin", password="password")
        
        headers = provider.get_headers()
        
        assert headers == {"Content-Type": "application/json"}

    async def test_logout_success(self):
        """Test successful logout."""
        provider = SessionAuthProvider(username="admin", password="password")
        provider._session_id = "test-session"
        
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "test-session")
        
        assert provider._session_id is None
        client.post.assert_called_once()
        
        payload = client.post.call_args[1]["json"]
        assert payload["method"] == "exec"
        assert payload["params"][0]["url"] == "sys/logout"
        assert payload["session"] == "test-session"

    async def test_logout_no_session(self):
        """Test logout with no session."""
        provider = SessionAuthProvider(username="admin", password="password")
        client = AsyncMock(spec=httpx.AsyncClient)
        
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "")
        
        client.post.assert_not_called()

    async def test_logout_failure_non_critical(self):
        """Test logout failure is non-critical."""
        provider = SessionAuthProvider(username="admin", password="password")
        provider._session_id = "test-session"
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.RequestError("Connection error", request=Mock())
        
        # Should not raise exception
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "test-session")
        
        assert provider._session_id is None

    def test_session_id_property(self):
        """Test session_id property."""
        provider = SessionAuthProvider(username="admin", password="password")
        assert provider.session_id is None
        
        provider._session_id = "test-session"
        assert provider.session_id == "test-session"


class TestFortiCloudAuthProvider:
    """Test FortiCloudAuthProvider class."""

    def test_init(self):
        """Test initialization."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password123",
            client_id="FortiManager",
        )
        assert provider.username == "user@example.com"
        assert provider.password == "password123"
        assert provider.client_id == "FortiManager"
        assert provider._session_id is None

    def test_init_default_client_id(self):
        """Test initialization with default client_id."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password123",
        )
        assert provider.client_id == "FortiManager"

    async def test_authenticate_success(self):
        """Test successful FortiCloud authentication."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password123",
        )
        
        # Mock OAuth token response
        oauth_response = Mock()
        oauth_response.json.return_value = {"access_token": "oauth-access-token"}
        oauth_response.raise_for_status = Mock()
        
        # Mock FortiManager login response
        login_response = Mock()
        login_response.json.return_value = {"session": "fmg-session-id"}
        login_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = [oauth_response, login_response]
        
        session_id = await provider.authenticate(
            client, "https://fmg.example.com/jsonrpc"
        )
        
        assert session_id == "fmg-session-id"
        assert provider._session_id == "fmg-session-id"
        assert provider.session_id == "fmg-session-id"
        
        assert client.post.call_count == 2
        
        # Check OAuth request
        oauth_call = client.post.call_args_list[0]
        assert oauth_call[0][0] == provider.FORTICLOUD_AUTH_URL
        oauth_payload = oauth_call[1]["json"]
        assert oauth_payload["username"] == "user@example.com"
        assert oauth_payload["password"] == "password123"
        assert oauth_payload["client_id"] == "FortiManager"
        assert oauth_payload["grant_type"] == "password"
        
        # Check FortiManager login request
        login_call = client.post.call_args_list[1]
        assert login_call[0][0] == "https://fmg.example.com/p/forticloud_jsonrpc_login/"
        login_payload = login_call[1]["json"]
        assert login_payload["access_token"] == "oauth-access-token"

    async def test_authenticate_oauth_no_token(self):
        """Test authentication failure when OAuth returns no token."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="wrong",
        )
        
        oauth_response = Mock()
        oauth_response.json.return_value = {}
        oauth_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = oauth_response
        
        with pytest.raises(
            AuthenticationError, match="No access_token in FortiCloud OAuth response"
        ):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_oauth_http_error(self):
        """Test authentication with OAuth HTTP error."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="wrong",
        )
        
        mock_response = Mock()
        mock_response.status_code = 401
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.HTTPStatusError(
            "Unauthorized", request=Mock(), response=mock_response
        )
        
        with pytest.raises(AuthenticationError, match="FortiCloud OAuth failed: HTTP 401"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_oauth_request_error(self):
        """Test authentication with OAuth request error."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.RequestError("Connection refused", request=Mock())
        
        with pytest.raises(
            AuthenticationError, match="FortiCloud OAuth connection error"
        ):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_login_no_session(self):
        """Test authentication failure when login returns no session."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        
        oauth_response = Mock()
        oauth_response.json.return_value = {"access_token": "oauth-token"}
        oauth_response.raise_for_status = Mock()
        
        login_response = Mock()
        login_response.json.return_value = {}
        login_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = [oauth_response, login_response]
        
        with pytest.raises(
            AuthenticationError, match="No session ID in FortiCloud login response"
        ):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_login_http_error(self):
        """Test authentication with login HTTP error."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        
        oauth_response = Mock()
        oauth_response.json.return_value = {"access_token": "oauth-token"}
        oauth_response.raise_for_status = Mock()
        
        mock_response = Mock()
        mock_response.status_code = 403
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = [
            oauth_response,
            httpx.HTTPStatusError("Forbidden", request=Mock(), response=mock_response),
        ]
        
        with pytest.raises(AuthenticationError, match="FortiCloud login failed: HTTP 403"):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    async def test_authenticate_login_request_error(self):
        """Test authentication with login request error."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        
        oauth_response = Mock()
        oauth_response.json.return_value = {"access_token": "oauth-token"}
        oauth_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = [
            oauth_response,
            httpx.RequestError("Connection error", request=Mock()),
        ]
        
        with pytest.raises(
            AuthenticationError, match="FortiCloud login connection error"
        ):
            await provider.authenticate(client, "https://fmg.example.com/jsonrpc")

    def test_get_headers(self):
        """Test get_headers returns content type."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        
        headers = provider.get_headers()
        
        assert headers == {"Content-Type": "application/json"}

    async def test_logout_success(self):
        """Test successful logout."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        provider._session_id = "test-session"
        
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.return_value = mock_response
        
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "test-session")
        
        assert provider._session_id is None
        client.post.assert_called_once()
        
        payload = client.post.call_args[1]["json"]
        assert payload["method"] == "exec"
        assert payload["params"][0]["url"] == "sys/logout"
        assert payload["session"] == "test-session"

    async def test_logout_no_session(self):
        """Test logout with no session."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "")
        
        client.post.assert_not_called()

    async def test_logout_failure_non_critical(self):
        """Test logout failure is non-critical."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        provider._session_id = "test-session"
        
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = Exception("Connection error")
        
        # Should not raise exception
        await provider.logout(client, "https://fmg.example.com/jsonrpc", "test-session")
        
        assert provider._session_id is None

    def test_session_id_property(self):
        """Test session_id property."""
        provider = FortiCloudAuthProvider(
            username="user@example.com",
            password="password",
        )
        assert provider.session_id is None
        
        provider._session_id = "test-session"
        assert provider.session_id == "test-session"


class TestCreateAuthProvider:
    """Test create_auth_provider factory function."""

    def test_create_token_auth(self):
        """Test creating token auth provider."""
        provider = create_auth_provider(api_token="test-token")
        
        assert isinstance(provider, TokenAuthProvider)
        assert provider.api_token == "test-token"

    def test_create_session_auth(self):
        """Test creating session auth provider."""
        provider = create_auth_provider(username="admin", password="password")
        
        assert isinstance(provider, SessionAuthProvider)
        assert provider.username == "admin"
        assert provider.password == "password"

    def test_create_forticloud_auth(self):
        """Test creating FortiCloud auth provider."""
        provider = create_auth_provider(
            username="user@example.com",
            password="password",
            forticloud=True,
        )
        
        assert isinstance(provider, FortiCloudAuthProvider)
        assert provider.username == "user@example.com"
        assert provider.password == "password"
        assert provider.client_id == "FortiManager"

    def test_create_forticloud_auth_custom_client_id(self):
        """Test creating FortiCloud auth with custom client_id."""
        provider = create_auth_provider(
            username="user@example.com",
            password="password",
            forticloud=True,
            forticloud_client_id="FortiAnalyzer",
        )
        
        assert isinstance(provider, FortiCloudAuthProvider)
        assert provider.client_id == "FortiAnalyzer"

    def test_create_forticloud_auth_missing_username(self):
        """Test FortiCloud auth requires username."""
        with pytest.raises(
            AuthenticationError,
            match="FortiCloud authentication requires both.*USERNAME.*PASSWORD",
        ):
            create_auth_provider(password="password", forticloud=True)

    def test_create_forticloud_auth_missing_password(self):
        """Test FortiCloud auth requires password."""
        with pytest.raises(
            AuthenticationError,
            match="FortiCloud authentication requires both.*USERNAME.*PASSWORD",
        ):
            create_auth_provider(username="user@example.com", forticloud=True)

    def test_token_takes_precedence(self):
        """Test token auth takes precedence over session auth."""
        provider = create_auth_provider(
            api_token="test-token",
            username="admin",
            password="password",
        )
        
        assert isinstance(provider, TokenAuthProvider)

    def test_token_takes_precedence_over_forticloud(self):
        """Test token auth takes precedence over FortiCloud auth."""
        provider = create_auth_provider(
            api_token="test-token",
            username="user@example.com",
            password="password",
            forticloud=True,
        )
        
        assert isinstance(provider, TokenAuthProvider)

    def test_no_auth_config_raises_error(self):
        """Test error when no authentication config provided."""
        with pytest.raises(
            AuthenticationError,
            match="No authentication configuration provided",
        ):
            create_auth_provider()

    def test_only_username_raises_error(self):
        """Test error when only username provided."""
        with pytest.raises(
            AuthenticationError,
            match="No authentication configuration provided",
        ):
            create_auth_provider(username="admin")

    def test_only_password_raises_error(self):
        """Test error when only password provided."""
        with pytest.raises(
            AuthenticationError,
            match="No authentication configuration provided",
        ):
            create_auth_provider(password="password")
