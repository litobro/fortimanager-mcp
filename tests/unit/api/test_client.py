"""Unit tests for api.client module."""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import httpx

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.api.auth import TokenAuthProvider, SessionAuthProvider
from fortimanager_mcp.api.models import APIResponse
from fortimanager_mcp.utils.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
    TimeoutError,
    ResourceNotFoundError,
)
from fortimanager_mcp.utils.config import Settings


class TestFortiManagerClientInit:
    """Test FortiManagerClient initialization."""

    def test_init_with_token(self):
        """Test initialization with API token."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        assert client.host == "fmg.example.com"
        assert client.base_url == "https://fmg.example.com/jsonrpc"
        assert client.verify_ssl is True
        assert client.timeout == 30
        assert client.max_retries == 3
        assert isinstance(client.auth, TokenAuthProvider)
        assert client._client is None
        assert client._session_id is None
        assert client._request_id == 0

    def test_init_with_session_auth(self):
        """Test initialization with username/password."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        assert isinstance(client.auth, SessionAuthProvider)

    def test_init_strips_https(self):
        """Test initialization strips https:// from host."""
        client = FortiManagerClient(
            host="https://fmg.example.com",
            api_token="test-token",
        )
        
        assert client.host == "fmg.example.com"
        assert client.base_url == "https://fmg.example.com/jsonrpc"

    def test_init_strips_http(self):
        """Test initialization strips http:// from host."""
        client = FortiManagerClient(
            host="http://fmg.example.com",
            api_token="test-token",
        )
        
        assert client.host == "fmg.example.com"

    def test_init_strips_trailing_slash(self):
        """Test initialization strips trailing slash."""
        client = FortiManagerClient(
            host="fmg.example.com/",
            api_token="test-token",
        )
        
        assert client.host == "fmg.example.com"

    def test_init_custom_timeout(self):
        """Test initialization with custom timeout."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
            timeout=60,
        )
        
        assert client.timeout == 60

    def test_init_custom_max_retries(self):
        """Test initialization with custom max_retries."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
            max_retries=5,
        )
        
        assert client.max_retries == 5

    def test_init_verify_ssl_false(self):
        """Test initialization with SSL verification disabled."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
            verify_ssl=False,
        )
        
        assert client.verify_ssl is False

    def test_init_no_auth_raises_error(self):
        """Test initialization without authentication raises error."""
        with pytest.raises(AuthenticationError):
            FortiManagerClient(host="fmg.example.com")

    def test_from_settings(self):
        """Test creating client from settings."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_API_TOKEN="test-token",
            FORTIMANAGER_VERIFY_SSL=False,
            FORTIMANAGER_TIMEOUT=45,
            FORTIMANAGER_MAX_RETRIES=5,
        )
        
        client = FortiManagerClient.from_settings(settings)
        
        assert client.host == "fmg.example.com"
        assert client.verify_ssl is False
        assert client.timeout == 45
        assert client.max_retries == 5

    def test_from_settings_forticloud(self):
        """Test creating client from settings with FortiCloud auth."""
        settings = Settings(
            FORTIMANAGER_HOST="fmg.example.com",
            FORTIMANAGER_USERNAME="user@example.com",
            FORTIMANAGER_PASSWORD="password",
            FORTICLOUD_AUTH=True,
            FORTICLOUD_CLIENT_ID="FortiAnalyzer",
        )
        
        client = FortiManagerClient.from_settings(settings)
        
        assert client.host == "fmg.example.com"


class TestFortiManagerClientConnect:
    """Test FortiManagerClient connection methods."""

    async def test_connect_with_token_auth(self):
        """Test connecting with token authentication."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            await client.connect()
            
            assert client._client is not None
            assert client._session_id is None
            mock_client_class.assert_called_once()

    async def test_connect_with_session_auth(self):
        """Test connecting with session authentication."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}}],
            "session": "test-session",
        }
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            await client.connect()
            
            assert client._client is not None
            assert client._session_id == "test-session"

    async def test_connect_already_connected(self):
        """Test connecting when already connected."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            await client.connect()
            first_client = client._client
            
            await client.connect()
            
            # Should not create a new client
            assert client._client is first_client

    async def test_connect_auth_failure_cleanup(self):
        """Test connection cleanup on authentication failure."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="wrong",
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.side_effect = AuthenticationError("Auth failed")
            mock_client_class.return_value = mock_client
            
            with pytest.raises(AuthenticationError):
                await client.connect()
            
            # Client should be cleaned up
            assert client._client is None
            mock_client.aclose.assert_called_once()

    async def test_disconnect_with_session(self):
        """Test disconnecting with session-based auth."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        mock_client = AsyncMock()
        client._client = mock_client
        client._session_id = "test-session"
        
        mock_logout_response = Mock()
        mock_logout_response.raise_for_status = Mock()
        mock_client.post.return_value = mock_logout_response
        
        await client.disconnect()
        
        assert client._client is None
        assert client._session_id is None
        mock_client.aclose.assert_called_once()

    async def test_disconnect_without_session(self):
        """Test disconnecting with token auth (no session)."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_client = AsyncMock()
        client._client = mock_client
        
        await client.disconnect()
        
        assert client._client is None
        mock_client.aclose.assert_called_once()

    async def test_disconnect_not_connected(self):
        """Test disconnecting when not connected."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        # Should not raise error
        await client.disconnect()

    async def test_disconnect_logout_failure(self):
        """Test disconnect continues even if logout fails."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Logout error")
        client._client = mock_client
        client._session_id = "test-session"
        
        # Should not raise error
        await client.disconnect()
        
        assert client._client is None
        assert client._session_id is None
        mock_client.aclose.assert_called_once()

    async def test_context_manager(self):
        """Test using client as async context manager."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            async with client as ctx:
                assert ctx is client
                assert client._client is not None
            
            assert client._client is None
            mock_client.aclose.assert_called_once()


class TestFortiManagerClientRequests:
    """Test FortiManagerClient request methods."""

    def test_get_next_request_id(self):
        """Test request ID increments."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        assert client._get_next_request_id() == 1
        assert client._get_next_request_id() == 2
        assert client._get_next_request_id() == 3

    async def test_request_not_connected(self):
        """Test request raises error when not connected."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        with pytest.raises(ConnectionError, match="Not connected"):
            await client._request("get", "/api/v2/test")

    async def test_request_success(self):
        """Test successful request."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}, "data": {"test": "value"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        response = await client._request("get", "/dvmdb/device")
        
        assert isinstance(response, APIResponse)
        assert response.is_success
        assert response.data == {"test": "value"}
        
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == client.base_url
        
        payload = call_args[1]["json"]
        assert payload["method"] == "get"
        assert payload["params"][0]["url"] == "/dvmdb/device"
        assert payload["verbose"] == 1

    async def test_request_with_data(self):
        """Test request with data payload."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client._request("add", "/api/test", data={"name": "test"})
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["params"][0]["data"] == {"name": "test"}

    async def test_request_with_params(self):
        """Test request with additional parameters."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client._request("get", "/api/test", params={"fields": ["name", "ip"]})
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["params"][0]["fields"] == ["name", "ip"]

    async def test_request_with_session(self):
        """Test request includes session for session-based auth."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0, "message": "OK"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        client._session_id = "test-session"
        
        await client._request("get", "/api/test")
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["session"] == "test-session"

    async def test_request_api_error(self):
        """Test request handles API errors."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": -3, "message": "Object not found"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        with pytest.raises(ResourceNotFoundError):
            await client._request("get", "/api/test")

    async def test_request_timeout(self):
        """Test request handles timeout errors."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("Timeout")
        client._client = mock_client
        
        with pytest.raises(TimeoutError, match="Request timeout"):
            await client._request("get", "/api/test")

    async def test_request_http_status_error(self):
        """Test request handles HTTP status errors."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.status_code = 500
        
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Server error", request=Mock(), response=mock_response
        )
        client._client = mock_client
        
        with pytest.raises(ConnectionError, match="HTTP 500"):
            await client._request("get", "/api/test")

    async def test_request_connection_error(self):
        """Test request handles connection errors."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("Connection refused", request=Mock())
        client._client = mock_client
        
        with pytest.raises(ConnectionError, match="Connection error"):
            await client._request("get", "/api/test")


class TestFortiManagerClientAPIMethods:
    """Test FortiManagerClient API methods."""

    async def test_get_basic(self):
        """Test get method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": [{"name": "device1"}]}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        result = await client.get("/dvmdb/device")
        
        assert result == [{"name": "device1"}]
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "get"
        assert payload["params"][0]["url"] == "/dvmdb/device"
        assert payload["params"][0]["loadsub"] == 1

    async def test_get_with_fields(self):
        """Test get method with fields filter."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"name": "device1"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.get("/dvmdb/device/device1", fields=["name", "ip"])
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["params"][0]["fields"] == ["name", "ip"]

    async def test_get_with_filter(self):
        """Test get method with filter."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": []}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.get("/dvmdb/device", filter=["os_ver", "==", "7.0"])
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["params"][0]["filter"] == ["os_ver", "==", "7.0"]

    async def test_get_with_loadsub(self):
        """Test get method with loadsub parameter."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.get("/dvmdb/device", loadsub=0)
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["params"][0]["loadsub"] == 0

    async def test_add(self):
        """Test add method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"name": "new-obj"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        result = await client.add(
            "/pm/config/adom/root/obj/firewall/address",
            data={"name": "new-obj", "subnet": "10.0.0.0/8"},
        )
        
        assert result == {"name": "new-obj"}
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "add"
        assert payload["params"][0]["data"] == {"name": "new-obj", "subnet": "10.0.0.0/8"}

    async def test_set(self):
        """Test set method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"name": "obj"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        result = await client.set(
            "/pm/config/adom/root/obj/firewall/address/obj",
            data={"comment": "Updated"},
        )
        
        assert result == {"name": "obj"}
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "set"
        assert payload["params"][0]["data"] == {"comment": "Updated"}

    async def test_update(self):
        """Test update method (alias for set)."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.update("/api/test", data={"value": "new"})
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "set"

    async def test_delete(self):
        """Test delete method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.delete("/pm/config/adom/root/obj/firewall/address/obj")
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "delete"

    async def test_execute(self):
        """Test execute method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"task": 123}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        result = await client.execute(
            "/securityconsole/install/device",
            data={"adom": "root", "scope": [{"name": "device1"}]},
        )
        
        assert result == {"task": 123}
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "exec"
        assert payload["params"][0]["data"]["adom"] == "root"

    async def test_execute_without_data(self):
        """Test execute method without data."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.execute("/api/test")
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "exec"
        assert "data" not in payload["params"][0] or payload["params"][0]["data"] is None

    async def test_exec_alias(self):
        """Test exec method (alias for execute)."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.exec("/api/test", data={"action": "run"})
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "exec"
        assert payload["params"][0]["data"] == {"action": "run"}

    async def test_clone(self):
        """Test clone method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"name": "cloned"}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        result = await client.clone("/api/test", data={"name": "cloned"})
        
        assert result == {"name": "cloned"}
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "clone"

    async def test_move(self):
        """Test move method."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.move(
            "/pm/config/adom/root/pkg/default/firewall/policy/10",
            data={"option": "after", "target": 5},
        )
        
        payload = mock_client.post.call_args[1]["json"]
        assert payload["method"] == "move"
        assert payload["params"][0]["data"] == {"option": "after", "target": 5}


class TestFortiManagerClientIntegration:
    """Test FortiManagerClient integration scenarios."""

    async def test_full_workflow_token_auth(self):
        """Test complete workflow with token auth."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": [{"name": "device1"}]}],
        }
        mock_response.raise_for_status = Mock()
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            # Connect
            await client.connect()
            assert client._client is not None
            assert client._session_id is None
            
            # Make request
            result = await client.get("/dvmdb/device")
            assert result == [{"name": "device1"}]
            
            # Disconnect
            await client.disconnect()
            assert client._client is None

    async def test_full_workflow_session_auth(self):
        """Test complete workflow with session auth."""
        client = FortiManagerClient(
            host="fmg.example.com",
            username="admin",
            password="password",
        )
        
        login_response = Mock()
        login_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}}],
            "session": "test-session",
        }
        login_response.raise_for_status = Mock()
        
        get_response = Mock()
        get_response.json.return_value = {
            "id": 2,
            "result": [{"status": {"code": 0}, "data": [{"name": "device1"}]}],
        }
        get_response.raise_for_status = Mock()
        
        logout_response = Mock()
        logout_response.raise_for_status = Mock()
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.side_effect = [login_response, get_response, logout_response]
            mock_client_class.return_value = mock_client
            
            # Connect
            await client.connect()
            assert client._session_id == "test-session"
            
            # Make request
            result = await client.get("/dvmdb/device")
            assert result == [{"name": "device1"}]
            
            # Disconnect
            await client.disconnect()
            assert client._session_id is None

    async def test_context_manager_workflow(self):
        """Test using client as context manager."""
        mock_get_response = Mock()
        mock_get_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {"test": "value"}}],
        }
        mock_get_response.raise_for_status = Mock()
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_get_response
            mock_client_class.return_value = mock_client
            
            async with FortiManagerClient(
                host="fmg.example.com",
                api_token="test-token",
            ) as client:
                result = await client.get("/api/test")
                assert result == {"test": "value"}
            
            # Client should be closed
            mock_client.aclose.assert_called_once()

    async def test_multiple_requests_increment_id(self):
        """Test multiple requests increment request ID."""
        client = FortiManagerClient(
            host="fmg.example.com",
            api_token="test-token",
        )
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": 1,
            "result": [{"status": {"code": 0}, "data": {}}],
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        client._client = mock_client
        
        await client.get("/api/test1")
        await client.get("/api/test2")
        await client.get("/api/test3")
        
        # Check request IDs increment
        calls = mock_client.post.call_args_list
        assert calls[0][1]["json"]["id"] == 1
        assert calls[1][1]["json"]["id"] == 2
        assert calls[2][1]["json"]["id"] == 3
