"""Unit tests for api.installation module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.installation import InstallationAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.execute = AsyncMock()
    return client


@pytest.fixture
def installation_api(mock_client):
    """Create InstallationAPI instance with mock client."""
    return InstallationAPI(mock_client)


class TestInstallationAPIInit:
    """Test InstallationAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = InstallationAPI(mock_client)
        assert api.client == mock_client


class TestInstallDeviceSettings:
    """Test device settings installation operations."""

    @pytest.mark.asyncio
    async def test_install_device_settings(self, installation_api, mock_client):
        """Test installing device settings."""
        mock_result = {"task": 123, "status": "pending"}
        mock_client.execute.return_value = mock_result

        result = await installation_api.install_device_settings(
            device="FortiGate-1",
            adom="root",
            vdom="root",
        )

        assert result == mock_result
        mock_client.execute.assert_called_once()
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/securityconsole/install/device"
        assert call_args[1]["data"]["adom"] == "root"
        assert call_args[1]["data"]["scope"][0]["name"] == "FortiGate-1"
        assert call_args[1]["data"]["scope"][0]["vdom"] == "root"

    @pytest.mark.asyncio
    async def test_install_device_settings_with_comments(self, installation_api, mock_client):
        """Test installing device settings with comments."""
        mock_result = {"task": 124}
        mock_client.execute.return_value = mock_result

        result = await installation_api.install_device_settings(
            device="FortiGate-1",
            adom="root",
            vdom="root",
            comments="System update",
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[1]["data"]["dev_rev_comments"] == "System update"

    @pytest.mark.asyncio
    async def test_install_device_settings_with_flags(self, installation_api, mock_client):
        """Test installing device settings with flags."""
        mock_result = {"task": 125}
        mock_client.execute.return_value = mock_result

        result = await installation_api.install_device_settings(
            device="FortiGate-1",
            adom="root",
            vdom="root",
            flags=["preview"],
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[1]["data"]["flags"] == ["preview"]


class TestInstallPolicyPackage:
    """Test policy package installation operations."""

    @pytest.mark.asyncio
    async def test_install_policy_package(self, installation_api, mock_client):
        """Test installing policy package."""
        mock_result = {"task": 126, "status": "pending"}
        mock_client.execute.return_value = mock_result

        result = await installation_api.install_policy_package(
            package="default",
            device="FortiGate-1",
            adom="root",
            vdom="root",
        )

        assert result == mock_result
        mock_client.execute.assert_called_once()
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/securityconsole/install/package"
        assert call_args[1]["data"]["adom"] == "root"
        assert call_args[1]["data"]["pkg"] == "default"
        assert call_args[1]["data"]["scope"][0]["name"] == "FortiGate-1"

    @pytest.mark.asyncio
    async def test_install_policy_package_with_flags(self, installation_api, mock_client):
        """Test installing policy package with flags."""
        mock_result = {"task": 127}
        mock_client.execute.return_value = mock_result

        result = await installation_api.install_policy_package(
            package="default",
            device="FortiGate-1",
            adom="root",
            vdom="root",
            flags=["auto_lock_ws"],
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[1]["data"]["flags"] == ["auto_lock_ws"]


class TestInstallMultipleDevices:
    """Test installation on multiple devices."""

    @pytest.mark.asyncio
    async def test_install_to_multiple_devices(self, installation_api, mock_client):
        """Test installing to multiple devices."""
        mock_result = {"task": 128}
        mock_client.execute.return_value = mock_result

        devices = [
            {"name": "FortiGate-1", "vdom": "root"},
            {"name": "FortiGate-2", "vdom": "root"},
        ]

        result = await installation_api.install_to_multiple_devices(
            package="default",
            devices=devices,
            adom="root",
        )

        assert result == mock_result
        mock_client.execute.assert_called_once()
        call_args = mock_client.execute.call_args
        assert len(call_args[1]["data"]["scope"]) == 2
        assert call_args[1]["data"]["scope"][0]["name"] == "FortiGate-1"
        assert call_args[1]["data"]["scope"][1]["name"] == "FortiGate-2"


class TestPreview:
    """Test installation preview operations."""

    @pytest.mark.asyncio
    async def test_check_install_preview(self, installation_api, mock_client):
        """Test checking install preview."""
        mock_result = {"changes": ["interface wan1", "set ip 192.168.1.1"]}
        mock_client.execute.return_value = mock_result

        result = await installation_api.check_install_preview(
            package="default",
            device="FortiGate-1",
            adom="root",
            vdom="root",
        )

        assert result == mock_result
        mock_client.execute.assert_called_once()


class TestInstallationHistory:
    """Test installation history operations."""

    @pytest.mark.asyncio
    async def test_get_install_history(self, installation_api, mock_client):
        """Test getting installation history for a device."""
        mock_data = [
            {"task": 123, "status": "success", "timestamp": "2023-01-01"},
            {"task": 122, "status": "success", "timestamp": "2023-01-02"},
        ]
        mock_client.get.return_value = mock_data

        result = await installation_api.get_install_history(
            device="FortiGate-1",
            adom="root",
        )

        assert result == mock_data
        mock_client.get.assert_called_once()


class TestAbortInstallation:
    """Test aborting installation operations."""

    @pytest.mark.asyncio
    async def test_abort_install(self, installation_api, mock_client):
        """Test aborting installation."""
        mock_result = {"status": "aborted"}
        mock_client.execute.return_value = mock_result

        result = await installation_api.abort_install(task_id=123)

        assert result == mock_result
        mock_client.execute.assert_called_once()
