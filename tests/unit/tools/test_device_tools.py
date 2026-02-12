"""Unit tests for tools.device_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.api.models import Device, ADOM
from fortimanager_mcp.tools import device_tools


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    client.exec = AsyncMock()
    return client


@pytest.fixture
def mock_device_api(mock_client):
    """Create mock DeviceAPI instance."""
    with patch('fortimanager_mcp.tools.device_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.list_devices = AsyncMock()
        api.get_device = AsyncMock()
        api.install_device_settings = AsyncMock()
        api.add_real_device = AsyncMock()
        api.rename_device = AsyncMock()
        api.refresh_device = AsyncMock()
        api.get_device_oid = AsyncMock()
        api.get_unauthorized_devices = AsyncMock()
        api.authorize_device = AsyncMock()
        api.change_device_serial_number = AsyncMock()
        api.get_available_timezones = AsyncMock()
        api.get_full_device_db_syntax = AsyncMock()
        api.get_supported_model_devices = AsyncMock()
        api.create_model_device = AsyncMock()
        api.list_model_devices = AsyncMock()
        api.enable_device_auto_link = AsyncMock()
        api.disable_device_auto_link = AsyncMock()
        api.create_device_group = AsyncMock()
        api.delete_device_group = AsyncMock()
        api.add_device_to_group = AsyncMock()
        api.remove_device_from_group = AsyncMock()
        api.list_device_groups = AsyncMock()
        
        with patch('fortimanager_mcp.tools.device_tools.DeviceAPI', return_value=api):
            yield api


@pytest.fixture
def mock_adom_api():
    """Create mock ADOMAPI instance."""
    with patch('fortimanager_mcp.tools.device_tools.get_fmg_client') as mock_get_client:
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        
        api = MagicMock()
        api.list_adoms = AsyncMock()
        
        with patch('fortimanager_mcp.tools.device_tools.ADOMAPI', return_value=api):
            yield api


class TestListDevices:
    """Test list_devices tool."""

    @pytest.mark.asyncio
    async def test_list_devices_success(self, mock_device_api):
        """Test listing devices successfully."""
        device1 = Device(
            name="FGT-01",
            ip="192.168.1.1",
            os_ver="7.4.0",
            platform_str="FortiGate-100F",
            sn="FGT01234567890",
            conn_status=1,
        )
        device2 = Device(
            name="FGT-02",
            ip="192.168.1.2",
            os_ver="7.2.5",
            platform_str="FortiGate-60F",
            sn="FGT09876543210",
            conn_status=0,
        )
        mock_device_api.list_devices.return_value = [device1, device2]

        result = await device_tools.list_devices()

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["devices"]) == 2
        assert result["devices"][0]["name"] == "FGT-01"
        assert result["devices"][0]["ip"] == "192.168.1.1"
        assert result["devices"][1]["name"] == "FGT-02"
        mock_device_api.list_devices.assert_called_once_with(adom=None)

    @pytest.mark.asyncio
    async def test_list_devices_with_adom(self, mock_device_api):
        """Test listing devices with ADOM filter."""
        device = Device(name="FGT-01", ip="192.168.1.1")
        mock_device_api.list_devices.return_value = [device]

        result = await device_tools.list_devices(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_device_api.list_devices.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_devices_error(self, mock_device_api):
        """Test listing devices with error."""
        mock_device_api.list_devices.side_effect = Exception("API Error")

        result = await device_tools.list_devices()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestGetDeviceDetails:
    """Test get_device_details tool."""

    @pytest.mark.asyncio
    async def test_get_device_details_success(self, mock_device_api):
        """Test getting device details successfully."""
        device = Device(
            name="FGT-01",
            ip="192.168.1.1",
            os_type="FortiGate",
            os_ver="7.4.0",
            mr=1,
            build=123,
            platform_str="FortiGate-100F",
            sn="FGT01234567890",
            conn_status=1,
            ha_mode=0,
        )
        mock_device_api.get_device.return_value = device

        result = await device_tools.get_device_details(name="FGT-01")

        assert result["status"] == "success"
        assert result["device"]["name"] == "FGT-01"
        assert result["device"]["ip"] == "192.168.1.1"
        assert result["device"]["os_type"] == "FortiGate"
        mock_device_api.get_device.assert_called_once_with(name="FGT-01", adom=None)

    @pytest.mark.asyncio
    async def test_get_device_details_with_adom(self, mock_device_api):
        """Test getting device details with ADOM."""
        device = Device(name="FGT-01", ip="192.168.1.1")
        mock_device_api.get_device.return_value = device

        result = await device_tools.get_device_details(name="FGT-01", adom="root")

        assert result["status"] == "success"
        mock_device_api.get_device.assert_called_once_with(name="FGT-01", adom="root")

    @pytest.mark.asyncio
    async def test_get_device_details_error(self, mock_device_api):
        """Test getting device details with error."""
        mock_device_api.get_device.side_effect = Exception("Device not found")

        result = await device_tools.get_device_details(name="FGT-01")

        assert result["status"] == "error"
        assert "Device not found" in result["message"]


class TestInstallDeviceSettings:
    """Test install_device_settings tool."""

    @pytest.mark.asyncio
    async def test_install_device_settings_success(self, mock_device_api):
        """Test installing device settings successfully."""
        mock_device_api.install_device_settings.return_value = {"task_id": 123}

        result = await device_tools.install_device_settings(
            devices=["FGT-01", "FGT-02"],
            adom="root"
        )

        assert result["status"] == "success"
        assert "task_id" in result
        mock_device_api.install_device_settings.assert_called_once_with(
            devices=["FGT-01", "FGT-02"],
            adom="root",
            vdoms=None,
            flags=None
        )

    @pytest.mark.asyncio
    async def test_install_device_settings_with_vdoms(self, mock_device_api):
        """Test installing device settings with VDOMs."""
        mock_device_api.install_device_settings.return_value = {"task_id": 123}

        result = await device_tools.install_device_settings(
            devices=["FGT-01"],
            adom="root",
            vdoms=["root", "vdom1"]
        )

        assert result["status"] == "success"
        mock_device_api.install_device_settings.assert_called_once_with(
            devices=["FGT-01"],
            adom="root",
            vdoms=["root", "vdom1"],
            flags=None
        )

    @pytest.mark.asyncio
    async def test_install_device_settings_error(self, mock_device_api):
        """Test installing device settings with error."""
        mock_device_api.install_device_settings.side_effect = Exception("Install failed")

        result = await device_tools.install_device_settings(
            devices=["FGT-01"],
            adom="root"
        )

        assert result["status"] == "error"
        assert "Install failed" in result["message"]


class TestListAdoms:
    """Test list_adoms tool."""

    @pytest.mark.asyncio
    async def test_list_adoms_success(self, mock_adom_api):
        """Test listing ADOMs successfully."""
        adom1 = ADOM(name="root", status=1)
        adom2 = ADOM(name="branch", status=1)
        mock_adom_api.list_adoms.return_value = [adom1, adom2]

        result = await device_tools.list_adoms()

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["adoms"]) == 2
        assert result["adoms"][0]["name"] == "root"
        assert result["adoms"][1]["name"] == "branch"
        mock_adom_api.list_adoms.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_adoms_error(self, mock_adom_api):
        """Test listing ADOMs with error."""
        mock_adom_api.list_adoms.side_effect = Exception("API Error")

        result = await device_tools.list_adoms()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestAddRealDevice:
    """Test add_real_device tool."""

    @pytest.mark.asyncio
    async def test_add_real_device_success(self, mock_device_api):
        """Test adding real device successfully."""
        mock_device_api.add_real_device.return_value = {"status": "success"}

        result = await device_tools.add_real_device(
            name="FGT-NEW",
            ip="192.168.1.100",
            username="admin",
            password="password123",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.add_real_device.assert_called_once()
        call_kwargs = mock_device_api.add_real_device.call_args.kwargs
        assert call_kwargs["name"] == "FGT-NEW"
        assert call_kwargs["ip"] == "192.168.1.100"
        assert call_kwargs["username"] == "admin"
        assert call_kwargs["password"] == "password123"
        assert call_kwargs["adom"] == "root"

    @pytest.mark.asyncio
    async def test_add_real_device_error(self, mock_device_api):
        """Test adding real device with error."""
        mock_device_api.add_real_device.side_effect = Exception("Add failed")

        result = await device_tools.add_real_device(
            name="FGT-NEW",
            ip="192.168.1.100",
            username="admin",
            password="password123"
        )

        assert result["status"] == "error"
        assert "Add failed" in result["message"]


class TestRenameDevice:
    """Test rename_device tool."""

    @pytest.mark.asyncio
    async def test_rename_device_success(self, mock_device_api):
        """Test renaming device successfully."""
        mock_device_api.rename_device.return_value = {"status": "success"}

        result = await device_tools.rename_device(
            old_name="FGT-OLD",
            new_name="FGT-NEW",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.rename_device.assert_called_once_with(
            old_name="FGT-OLD",
            new_name="FGT-NEW",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_rename_device_error(self, mock_device_api):
        """Test renaming device with error."""
        mock_device_api.rename_device.side_effect = Exception("Rename failed")

        result = await device_tools.rename_device(
            old_name="FGT-OLD",
            new_name="FGT-NEW"
        )

        assert result["status"] == "error"
        assert "Rename failed" in result["message"]


class TestRefreshDevice:
    """Test refresh_device tool."""

    @pytest.mark.asyncio
    async def test_refresh_device_success(self, mock_device_api):
        """Test refreshing device successfully."""
        mock_device_api.refresh_device.return_value = {"status": "success"}

        result = await device_tools.refresh_device(device="FGT-01", adom="root")

        assert result["status"] == "success"
        mock_device_api.refresh_device.assert_called_once_with(
            device="FGT-01",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_refresh_device_error(self, mock_device_api):
        """Test refreshing device with error."""
        mock_device_api.refresh_device.side_effect = Exception("Refresh failed")

        result = await device_tools.refresh_device(device="FGT-01")

        assert result["status"] == "error"
        assert "Refresh failed" in result["message"]


class TestGetDeviceOid:
    """Test get_device_oid tool."""

    @pytest.mark.asyncio
    async def test_get_device_oid_success(self, mock_device_api):
        """Test getting device OID successfully."""
        mock_device_api.get_device_oid.return_value = 12345

        result = await device_tools.get_device_oid(device_name="FGT-01")

        assert result["status"] == "success"
        assert result["oid"] == 12345
        mock_device_api.get_device_oid.assert_called_once_with(device_name="FGT-01")

    @pytest.mark.asyncio
    async def test_get_device_oid_error(self, mock_device_api):
        """Test getting device OID with error."""
        mock_device_api.get_device_oid.side_effect = Exception("Device not found")

        result = await device_tools.get_device_oid(device_name="FGT-01")

        assert result["status"] == "error"
        assert "Device not found" in result["message"]


class TestGetUnauthorizedDevices:
    """Test get_unauthorized_devices tool."""

    @pytest.mark.asyncio
    async def test_get_unauthorized_devices_success(self, mock_device_api):
        """Test getting unauthorized devices successfully."""
        mock_device_api.get_unauthorized_devices.return_value = [
            {"name": "FGT-UNAUTH-01", "sn": "FGT123"},
            {"name": "FGT-UNAUTH-02", "sn": "FGT456"}
        ]

        result = await device_tools.get_unauthorized_devices()

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["devices"]) == 2
        mock_device_api.get_unauthorized_devices.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_unauthorized_devices_error(self, mock_device_api):
        """Test getting unauthorized devices with error."""
        mock_device_api.get_unauthorized_devices.side_effect = Exception("API Error")

        result = await device_tools.get_unauthorized_devices()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestAuthorizeDevice:
    """Test authorize_device tool."""

    @pytest.mark.asyncio
    async def test_authorize_device_success(self, mock_device_api):
        """Test authorizing device successfully."""
        mock_device_api.authorize_device.return_value = {"status": "success"}

        result = await device_tools.authorize_device(
            device_id=123,
            username="admin",
            password="password123"
        )

        assert result["status"] == "success"
        mock_device_api.authorize_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_authorize_device_error(self, mock_device_api):
        """Test authorizing device with error."""
        mock_device_api.authorize_device.side_effect = Exception("Auth failed")

        result = await device_tools.authorize_device(
            device_id=123,
            username="admin",
            password="password123"
        )

        assert result["status"] == "error"
        assert "Auth failed" in result["message"]


class TestChangeDeviceSerialNumber:
    """Test change_device_serial_number tool."""

    @pytest.mark.asyncio
    async def test_change_device_serial_number_success(self, mock_device_api):
        """Test changing device serial number successfully."""
        mock_device_api.change_device_serial_number.return_value = {"status": "success"}

        result = await device_tools.change_device_serial_number(
            device_name="FGT-01",
            new_serial="FGT999",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.change_device_serial_number.assert_called_once_with(
            device_name="FGT-01",
            new_serial="FGT999",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_change_device_serial_number_error(self, mock_device_api):
        """Test changing device serial number with error."""
        mock_device_api.change_device_serial_number.side_effect = Exception("Change failed")

        result = await device_tools.change_device_serial_number(
            device_name="FGT-01",
            new_serial="FGT999"
        )

        assert result["status"] == "error"
        assert "Change failed" in result["message"]


class TestGetAvailableTimezones:
    """Test get_available_timezones tool."""

    @pytest.mark.asyncio
    async def test_get_available_timezones_success(self, mock_device_api):
        """Test getting available timezones successfully."""
        mock_device_api.get_available_timezones.return_value = [
            {"id": 1, "name": "America/New_York"},
            {"id": 2, "name": "Europe/London"}
        ]

        result = await device_tools.get_available_timezones()

        assert result["status"] == "success"
        assert len(result["timezones"]) == 2
        mock_device_api.get_available_timezones.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_available_timezones_error(self, mock_device_api):
        """Test getting available timezones with error."""
        mock_device_api.get_available_timezones.side_effect = Exception("API Error")

        result = await device_tools.get_available_timezones()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestCreateModelDevice:
    """Test create_model_device tool."""

    @pytest.mark.asyncio
    async def test_create_model_device_success(self, mock_device_api):
        """Test creating model device successfully."""
        mock_device_api.create_model_device.return_value = {"status": "success"}

        result = await device_tools.create_model_device(
            name="FGT-MODEL",
            serial_number="FGT-MODEL-123",
            platform="FortiGate-100F",
            os_version="7.4.0",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.create_model_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_model_device_error(self, mock_device_api):
        """Test creating model device with error."""
        mock_device_api.create_model_device.side_effect = Exception("Create failed")

        result = await device_tools.create_model_device(
            name="FGT-MODEL",
            serial_number="FGT-MODEL-123",
            platform="FortiGate-100F",
            os_version="7.4.0"
        )

        assert result["status"] == "error"
        assert "Create failed" in result["message"]


class TestListModelDevices:
    """Test list_model_devices tool."""

    @pytest.mark.asyncio
    async def test_list_model_devices_success(self, mock_device_api):
        """Test listing model devices successfully."""
        device = Device(name="FGT-MODEL", sn="FGT-MODEL-123", os_ver="7.4.0")
        mock_device_api.list_model_devices.return_value = [device]

        result = await device_tools.list_model_devices(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_device_api.list_model_devices.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_model_devices_error(self, mock_device_api):
        """Test listing model devices with error."""
        mock_device_api.list_model_devices.side_effect = Exception("API Error")

        result = await device_tools.list_model_devices()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestDeviceAutoLink:
    """Test device auto-link tools."""

    @pytest.mark.asyncio
    async def test_enable_device_auto_link_success(self, mock_device_api):
        """Test enabling device auto-link successfully."""
        mock_device_api.enable_device_auto_link.return_value = {"status": "success"}

        result = await device_tools.enable_device_auto_link(
            device="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.enable_device_auto_link.assert_called_once_with(
            device="FGT-01",
            adom="root",
            policy_package=None,
            template_group=None
        )

    @pytest.mark.asyncio
    async def test_disable_device_auto_link_success(self, mock_device_api):
        """Test disabling device auto-link successfully."""
        mock_device_api.disable_device_auto_link.return_value = {"status": "success"}

        result = await device_tools.disable_device_auto_link(
            device="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.disable_device_auto_link.assert_called_once_with(
            device="FGT-01",
            adom="root"
        )


class TestDeviceGroups:
    """Test device group management tools."""

    @pytest.mark.asyncio
    async def test_create_device_group_success(self, mock_device_api):
        """Test creating device group successfully."""
        mock_device_api.create_device_group.return_value = {"status": "success"}

        result = await device_tools.create_device_group(
            name="Branch-Offices",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.create_device_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_device_groups_success(self, mock_device_api):
        """Test listing device groups successfully."""
        mock_device_api.list_device_groups.return_value = [
            {"name": "Group1"},
            {"name": "Group2"}
        ]

        result = await device_tools.list_device_groups(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_device_api.list_device_groups.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_add_device_to_group_success(self, mock_device_api):
        """Test adding device to group successfully."""
        mock_device_api.add_device_to_group.return_value = {"status": "success"}

        result = await device_tools.add_device_to_group(
            device="FGT-01",
            group="Branch-Offices",
            adom="root"
        )

        assert result["status"] == "success"
        mock_device_api.add_device_to_group.assert_called_once()
