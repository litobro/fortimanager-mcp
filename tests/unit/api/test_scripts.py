"""Unit tests for api.scripts module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.scripts import ScriptAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    client.update = AsyncMock()
    client.exec = AsyncMock()
    return client


@pytest.fixture
def script_api(mock_client):
    """Create ScriptAPI instance with mock client."""
    return ScriptAPI(mock_client)


class TestScriptAPIInit:
    """Test ScriptAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = ScriptAPI(mock_client)
        assert api.client == mock_client


class TestListScripts:
    """Test script listing operations."""

    @pytest.mark.asyncio
    async def test_list_scripts(self, script_api, mock_client):
        """Test listing CLI scripts."""
        mock_data = [
            {"name": "script1", "type": "cli", "target": "device_database"},
            {"name": "script2", "type": "jinja", "target": "remote_device"},
        ]
        mock_client.get.return_value = mock_data

        result = await script_api.list_scripts(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/root/script")

    @pytest.mark.asyncio
    async def test_list_scripts_empty(self, script_api, mock_client):
        """Test listing scripts with empty result."""
        mock_client.get.return_value = []

        result = await script_api.list_scripts(adom="custom")

        assert result == []
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_scripts_single_item(self, script_api, mock_client):
        """Test listing scripts with single item result."""
        mock_data = {"name": "script1", "type": "cli"}
        mock_client.get.return_value = mock_data

        result = await script_api.list_scripts(adom="root")

        assert result == [mock_data]


class TestGetScript:
    """Test script retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_script(self, script_api, mock_client):
        """Test getting script details."""
        mock_data = {
            "name": "script1",
            "type": "cli",
            "target": "device_database",
            "content": "config system interface\nend",
        }
        mock_client.get.return_value = mock_data

        result = await script_api.get_script("script1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/root/script/script1")

    @pytest.mark.asyncio
    async def test_get_script_not_found(self, script_api, mock_client):
        """Test getting non-existent script."""
        mock_client.get.return_value = None

        result = await script_api.get_script("nonexistent", adom="root")

        assert result == {}


class TestCreateScript:
    """Test script creation operations."""

    @pytest.mark.asyncio
    async def test_create_script_cli(self, script_api, mock_client):
        """Test creating CLI script."""
        mock_result = {"name": "script1"}
        mock_client.add.return_value = mock_result

        result = await script_api.create_script(
            name="script1",
            content="config system interface\nend",
            target="device_database",
            adom="root",
            script_type="cli",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/dvmdb/adom/root/script"
        assert call_args[0][1]["name"] == "script1"
        assert call_args[0][1]["type"] == "cli"
        assert call_args[0][1]["target"] == "device_database"

    @pytest.mark.asyncio
    async def test_create_script_with_description(self, script_api, mock_client):
        """Test creating script with description."""
        mock_result = {"name": "script1"}
        mock_client.add.return_value = mock_result

        result = await script_api.create_script(
            name="script1",
            content="config system interface\nend",
            target="device_database",
            adom="root",
            description="Test script",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[0][1]["desc"] == "Test script"

    @pytest.mark.asyncio
    async def test_create_script_jinja(self, script_api, mock_client):
        """Test creating Jinja script."""
        mock_result = {"name": "script2"}
        mock_client.add.return_value = mock_result

        result = await script_api.create_script(
            name="script2",
            content="config system interface\n{% for port in ports %}\nedit {{port}}\nend",
            target="remote_device",
            adom="root",
            script_type="jinja",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[0][1]["type"] == "jinja"


class TestUpdateScript:
    """Test script update operations."""

    @pytest.mark.asyncio
    async def test_update_script_content(self, script_api, mock_client):
        """Test updating script content."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await script_api.update_script(
            name="script1",
            adom="root",
            content="config system global\nend",
        )

        assert result == mock_result
        mock_client.update.assert_called_once()
        call_args = mock_client.update.call_args
        assert "script1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_update_script_description(self, script_api, mock_client):
        """Test updating script description."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await script_api.update_script(
            name="script1",
            adom="root",
            description="Updated description",
        )

        assert result == mock_result
        call_args = mock_client.update.call_args
        assert "script1" in call_args[0][0]


class TestDeleteScript:
    """Test script deletion operations."""

    @pytest.mark.asyncio
    async def test_delete_script(self, script_api, mock_client):
        """Test deleting script."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await script_api.delete_script("script1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once_with("/dvmdb/adom/root/script/script1")


class TestExecuteScript:
    """Test script execution operations."""

    @pytest.mark.asyncio
    async def test_execute_script(self, script_api, mock_client):
        """Test executing script."""
        mock_result = {"task": 123}
        mock_client.exec.return_value = mock_result

        result = await script_api.execute_script(
            script="script1",
            adom="root",
            scope=[{"name": "FortiGate-1", "vdom": "root"}],
        )

        assert result == mock_result
        mock_client.exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_with_package(self, script_api, mock_client):
        """Test executing script with package."""
        mock_result = {"task": 124}
        mock_client.exec.return_value = mock_result

        result = await script_api.execute_script(
            script="script1",
            adom="root",
            package="pkg1",
            scope=[{"name": "FortiGate-1", "vdom": "root"}],
        )

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert call_args[0][1]["package"] == "pkg1"


class TestScriptHistory:
    """Test script history operations."""

    @pytest.mark.asyncio
    async def test_list_script_history(self, script_api, mock_client):
        """Test listing script execution history."""
        mock_data = [
            {"id": 1, "script": "script1", "device": "FortiGate-1", "status": "success"},
            {"id": 2, "script": "script1", "device": "FortiGate-2", "status": "failed"},
        ]
        mock_client.get.return_value = mock_data

        result = await script_api.list_script_history(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_script_history(self, script_api, mock_client):
        """Test getting specific script execution history."""
        mock_data = [
            {"id": 1, "status": "success"},
            {"id": 2, "status": "failed"},
        ]
        mock_client.get.return_value = mock_data

        result = await script_api.get_script_history(script_name="script1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
