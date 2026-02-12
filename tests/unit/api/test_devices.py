"""Unit tests for api.devices module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.devices import DeviceAPI
from fortimanager_mcp.api.models import Device
from fortimanager_mcp.utils.errors import APIError, ResourceNotFoundError


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
    client.update = AsyncMock()
    return client


@pytest.fixture
def device_api(mock_client):
    """Create DeviceAPI instance with mock client."""
    return DeviceAPI(mock_client)


class TestDeviceAPIInit:
    """Test DeviceAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = DeviceAPI(mock_client)
        assert api.client == mock_client


class TestListDevices:
    """Test device listing operations."""

    @pytest.mark.asyncio
    async def test_list_devices_no_adom(self, device_api, mock_client):
        """Test listing all devices without ADOM filter."""
        mock_data = [
            {
                "name": "device1",
                "ip": "192.168.1.1",
                "os_type": "FortiGate",
                "conn_status": 1,
            },
            {
                "name": "device2",
                "ip": "192.168.1.2",
                "os_type": "FortiGate",
                "conn_status": 0,
            },
        ]
        mock_client.get.return_value = mock_data

        result = await device_api.list_devices()

        assert len(result) == 2
        assert all(isinstance(dev, Device) for dev in result)
        assert result[0].name == "device1"
        assert result[1].name == "device2"
        mock_client.get.assert_called_once_with(
            "/dvmdb/device",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_devices_with_adom(self, device_api, mock_client):
        """Test listing devices filtered by ADOM."""
        mock_data = [{"name": "device1", "ip": "192.168.1.1"}]
        mock_client.get.return_value = mock_data

        result = await device_api.list_devices(adom="root")

        assert len(result) == 1
        mock_client.get.assert_called_once_with(
            "/dvmdb/adom/root/device",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_devices_with_fields(self, device_api, mock_client):
        """Test listing devices with specific fields."""
        mock_data = [{"name": "device1"}]
        mock_client.get.return_value = mock_data

        await device_api.list_devices(fields=["name", "ip", "conn_status"])

        mock_client.get.assert_called_once_with(
            "/dvmdb/device",
            fields=["name", "ip", "conn_status"],
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_devices_with_filter(self, device_api, mock_client):
        """Test listing devices with filter."""
        mock_data = [{"name": "device1"}]
        mock_client.get.return_value = mock_data
        filter_criteria = ["conn_status", "==", 1]

        await device_api.list_devices(filter=filter_criteria)

        mock_client.get.assert_called_once_with(
            "/dvmdb/device",
            fields=None,
            filter=filter_criteria,
        )

    @pytest.mark.asyncio
    async def test_list_devices_empty(self, device_api, mock_client):
        """Test listing devices returns empty list."""
        mock_client.get.return_value = []

        result = await device_api.list_devices()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_devices_single_dict(self, device_api, mock_client):
        """Test listing devices when single dict returned."""
        mock_data = {"name": "device1", "ip": "192.168.1.1"}
        mock_client.get.return_value = mock_data

        result = await device_api.list_devices()

        assert len(result) == 1
        assert isinstance(result[0], Device)

    @pytest.mark.asyncio
    async def test_list_devices_none(self, device_api, mock_client):
        """Test listing devices when None returned."""
        mock_client.get.return_value = None

        result = await device_api.list_devices()

        assert result == []


class TestGetDevice:
    """Test getting device details."""

    @pytest.mark.asyncio
    async def test_get_device_no_adom(self, device_api, mock_client):
        """Test getting device without ADOM."""
        mock_data = {
            "name": "device1",
            "ip": "192.168.1.1",
            "os_type": "FortiGate",
            "conn_status": 1,
            "sn": "FGT60E123456",
        }
        mock_client.get.return_value = mock_data

        result = await device_api.get_device("device1")

        assert isinstance(result, Device)
        assert result.name == "device1"
        assert result.ip == "192.168.1.1"
        assert result.sn == "FGT60E123456"
        mock_client.get.assert_called_once_with("/dvmdb/device/device1")

    @pytest.mark.asyncio
    async def test_get_device_with_adom(self, device_api, mock_client):
        """Test getting device with ADOM."""
        mock_data = {"name": "device1", "ip": "192.168.1.1"}
        mock_client.get.return_value = mock_data

        result = await device_api.get_device("device1", adom="root")

        assert isinstance(result, Device)
        mock_client.get.assert_called_once_with("/dvmdb/adom/root/device/device1")

    @pytest.mark.asyncio
    async def test_get_device_is_connected_property(self, device_api, mock_client):
        """Test device is_connected property."""
        mock_data = {"name": "device1", "conn_status": 1}
        mock_client.get.return_value = mock_data

        result = await device_api.get_device("device1")

        assert result.is_connected is True


class TestAddDevice:
    """Test adding devices."""

    @pytest.mark.asyncio
    async def test_add_device_success(self, device_api, mock_client):
        """Test adding device successfully."""
        mock_execute_result = {"taskid": 123}
        mock_device = {
            "name": "new_device",
            "ip": "192.168.1.10",
            "os_type": "FortiGate",
        }
        mock_client.execute.return_value = mock_execute_result
        mock_client.get.return_value = mock_device

        result = await device_api.add_device(
            name="new_device",
            ip="192.168.1.10",
            username="admin",
            password="password123",
            adom="root",
        )

        assert isinstance(result, Device)
        assert result.name == "new_device"

        # Verify execute was called with correct data
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvm/cmd/add/device"
        data = call_args[1]["data"]
        assert data["device action"] == "add_model"
        assert data["adom"] == "root"
        assert data["device"]["name"] == "new_device"
        assert data["device"]["ip"] == "192.168.1.10"
        assert data["device"]["adm_usr"] == "admin"
        assert data["device"]["adm_pass"] == "password123"
        assert data["flags"] == ["create_task"]

    @pytest.mark.asyncio
    async def test_add_device_with_kwargs(self, device_api, mock_client):
        """Test adding device with additional parameters."""
        mock_client.execute.return_value = {"taskid": 123}
        mock_client.get.return_value = {"name": "new_device"}

        await device_api.add_device(
            name="new_device",
            ip="192.168.1.10",
            username="admin",
            password="password123",
            mgmt_mode="fmg",
            platform_str="FortiGate-60E",
        )

        call_args = mock_client.execute.call_args
        device_data = call_args[1]["data"]["device"]
        assert device_data["mgmt_mode"] == "fmg"
        assert device_data["platform_str"] == "FortiGate-60E"

    @pytest.mark.asyncio
    async def test_add_device_different_adom(self, device_api, mock_client):
        """Test adding device to different ADOM."""
        mock_client.execute.return_value = {"taskid": 123}
        mock_client.get.return_value = {"name": "new_device"}

        await device_api.add_device(
            name="new_device",
            ip="192.168.1.10",
            username="admin",
            password="password123",
            adom="test_adom",
        )

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["adom"] == "test_adom"


class TestDeleteDevice:
    """Test deleting devices."""

    @pytest.mark.asyncio
    async def test_delete_device_success(self, device_api, mock_client):
        """Test deleting device."""
        await device_api.delete_device("device1", adom="root")

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvm/cmd/del/device"
        data = call_args[1]["data"]
        assert data["device"] == "device1"
        assert data["adom"] == "root"
        assert data["flags"] == ["create_task"]

    @pytest.mark.asyncio
    async def test_delete_device_different_adom(self, device_api, mock_client):
        """Test deleting device from different ADOM."""
        await device_api.delete_device("device1", adom="test_adom")

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["adom"] == "test_adom"


class TestDeviceConfig:
    """Test device configuration operations."""

    @pytest.mark.asyncio
    async def test_get_device_config_global(self, device_api, mock_client):
        """Test getting global device configuration."""
        mock_config = {"dns-primary": "8.8.8.8", "dns-secondary": "8.8.4.4"}
        mock_client.get.return_value = mock_config

        result = await device_api.get_device_config(
            device="device1",
            scope="global",
            path="system/dns",
        )

        assert result == mock_config
        mock_client.get.assert_called_once_with(
            "/pm/config/device/device1/global/system/dns"
        )

    @pytest.mark.asyncio
    async def test_get_device_config_vdom(self, device_api, mock_client):
        """Test getting VDOM device configuration."""
        mock_config = {"name": "root", "status": "enable"}
        mock_client.get.return_value = mock_config

        result = await device_api.get_device_config(
            device="device1",
            scope="vdom",
            path="system/settings",
            vdom="root",
        )

        assert result == mock_config
        mock_client.get.assert_called_once_with(
            "/pm/config/device/device1/vdom/root/system/settings"
        )

    @pytest.mark.asyncio
    async def test_get_device_config_vdom_without_name(self, device_api, mock_client):
        """Test getting VDOM config without VDOM name raises error."""
        with pytest.raises(ValueError, match="VDOM name required"):
            await device_api.get_device_config(
                device="device1",
                scope="vdom",
                path="system/settings",
            )

    @pytest.mark.asyncio
    async def test_get_device_config_invalid_scope(self, device_api, mock_client):
        """Test getting device config with invalid scope."""
        with pytest.raises(ValueError, match="Scope must be"):
            await device_api.get_device_config(
                device="device1",
                scope="invalid",
                path="system/dns",
            )

    @pytest.mark.asyncio
    async def test_set_device_config_global(self, device_api, mock_client):
        """Test setting global device configuration."""
        config_data = {"dns-primary": "1.1.1.1"}
        mock_client.set.return_value = {"status": "success"}

        result = await device_api.set_device_config(
            device="device1",
            scope="global",
            path="system/dns",
            data=config_data,
        )

        assert result == {"status": "success"}
        mock_client.set.assert_called_once_with(
            "/pm/config/device/device1/global/system/dns",
            data=config_data,
        )

    @pytest.mark.asyncio
    async def test_set_device_config_vdom(self, device_api, mock_client):
        """Test setting VDOM device configuration."""
        config_data = {"status": "enable"}
        mock_client.set.return_value = {"status": "success"}

        result = await device_api.set_device_config(
            device="device1",
            scope="vdom",
            path="system/settings",
            data=config_data,
            vdom="root",
        )

        assert result == {"status": "success"}
        mock_client.set.assert_called_once_with(
            "/pm/config/device/device1/vdom/root/system/settings",
            data=config_data,
        )

    @pytest.mark.asyncio
    async def test_set_device_config_vdom_without_name(self, device_api, mock_client):
        """Test setting VDOM config without VDOM name raises error."""
        with pytest.raises(ValueError, match="VDOM name required"):
            await device_api.set_device_config(
                device="device1",
                scope="vdom",
                path="system/settings",
                data={},
            )

    @pytest.mark.asyncio
    async def test_set_device_config_invalid_scope(self, device_api, mock_client):
        """Test setting device config with invalid scope."""
        with pytest.raises(ValueError, match="Scope must be"):
            await device_api.set_device_config(
                device="device1",
                scope="invalid",
                path="system/dns",
                data={},
            )


class TestInstallDeviceSettings:
    """Test device settings installation."""

    @pytest.mark.asyncio
    async def test_install_device_settings_basic(self, device_api, mock_client):
        """Test installing device settings."""
        mock_result = {"taskid": 456, "status": "success"}
        mock_client.execute.return_value = mock_result

        result = await device_api.install_device_settings(
            device="device1",
            adom="root",
            vdom="root",
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/securityconsole/install/device"
        data = call_args[1]["data"]
        assert data["adom"] == "root"
        assert data["scope"] == [{"name": "device1", "vdom": "root"}]
        assert data["flags"] == ["none"]

    @pytest.mark.asyncio
    async def test_install_device_settings_with_comments(self, device_api, mock_client):
        """Test installing device settings with comments."""
        mock_client.execute.return_value = {"taskid": 456}

        await device_api.install_device_settings(
            device="device1",
            comments="Security policy update",
        )

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["dev_rev_comments"] == "Security policy update"


class TestAddRealDevice:
    """Test adding real (physical) devices."""

    @pytest.mark.asyncio
    async def test_add_real_device_basic(self, device_api, mock_client):
        """Test adding real device with basic parameters."""
        mock_result = {"taskid": 789}
        mock_client.exec.return_value = mock_result

        result = await device_api.add_real_device(
            name="fg60e",
            ip="10.0.0.1",
            username="admin",
            password="fortinet",
        )

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert call_args[0][0] == "/dvm/cmd/add/device"
        data = call_args[1]["data"]
        assert data["adom"] == "root"
        assert data["device"]["name"] == "fg60e"
        assert data["device"]["ip"] == "10.0.0.1"
        assert data["device"]["adm_usr"] == "admin"
        assert data["device"]["adm_pass"] == "fortinet"
        assert data["device"]["mgmt_mode"] == "fmg"
        assert data["flags"] == ["create_task", "nonblocking"]

    @pytest.mark.asyncio
    async def test_add_real_device_with_mgmt_mode(self, device_api, mock_client):
        """Test adding real device with custom management mode."""
        mock_client.exec.return_value = {"taskid": 789}

        await device_api.add_real_device(
            name="fg60e",
            ip="10.0.0.1",
            username="admin",
            password="fortinet",
            mgmt_mode="fmgfaz",
        )

        call_args = mock_client.exec.call_args
        device_data = call_args[1]["data"]["device"]
        assert device_data["mgmt_mode"] == "fmgfaz"

    @pytest.mark.asyncio
    async def test_add_real_device_with_kwargs(self, device_api, mock_client):
        """Test adding real device with additional parameters."""
        mock_client.exec.return_value = {"taskid": 789}

        await device_api.add_real_device(
            name="fg60e",
            ip="10.0.0.1",
            username="admin",
            password="fortinet",
            platform_str="FortiGate-60E",
            os_ver="7.0",
        )

        call_args = mock_client.exec.call_args
        device_data = call_args[1]["data"]["device"]
        assert device_data["platform_str"] == "FortiGate-60E"
        assert device_data["os_ver"] == "7.0"


class TestRenameDevice:
    """Test renaming devices."""

    @pytest.mark.asyncio
    async def test_rename_device_no_adom(self, device_api, mock_client):
        """Test renaming device without ADOM."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await device_api.rename_device(
            current_name="old_name",
            new_name="new_name",
        )

        assert result == mock_result
        assert mock_client.update.called

    @pytest.mark.asyncio
    async def test_rename_device_with_adom(self, device_api, mock_client):
        """Test renaming device with ADOM."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await device_api.rename_device(
            current_name="old_name",
            new_name="new_name",
            adom="root",
        )

        assert result == mock_result
        assert mock_client.update.called


class TestRefreshDevice:
    """Test refreshing devices."""

    @pytest.mark.asyncio
    async def test_refresh_device_basic(self, device_api, mock_client):
        """Test refreshing device metadata."""
        mock_result = {"taskid": 999}
        mock_client.exec.return_value = mock_result

        result = await device_api.refresh_device(
            device="device1",
            adom="root",
        )

        assert result == mock_result
        assert mock_client.exec.called


class TestGetDeviceOID:
    """Test getting device OID."""

    @pytest.mark.asyncio
    async def test_get_device_oid_success(self, device_api, mock_client):
        """Test getting device OID."""
        # Mock the device lookup with oid field
        mock_data = {"oid": 12345}
        mock_client.get.return_value = mock_data

        result = await device_api.get_device_oid(device_name="device1")

        assert result == 12345

    @pytest.mark.asyncio
    async def test_get_device_oid_not_found(self, device_api, mock_client):
        """Test getting device OID when not found."""
        mock_client.get.side_effect = Exception("Device not found")

        with pytest.raises(Exception):
            await device_api.get_device_oid(device_name="device1")

    @pytest.mark.asyncio
    async def test_get_device_oid_no_oid_field(self, device_api, mock_client):
        """Test getting device OID when OID field missing."""
        # This would be an implementation detail of the actual method
        pass


class TestUnauthorizedDevices:
    """Test unauthorized device operations."""

    @pytest.mark.asyncio
    async def test_get_unauthorized_devices(self, device_api, mock_client):
        """Test getting list of unauthorized devices."""
        mock_data = [
            {"name": "device1", "ip": "10.0.0.1", "sn": "FGT123"},
            {"name": "device2", "ip": "10.0.0.2", "sn": "FGT456"},
        ]
        mock_client.get.return_value = mock_data

        result = await device_api.get_unauthorized_devices()

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/dvmdb/device"
        assert call_args[1]["filter"] == ["mgmt_mode", "==", "unreg"]

    @pytest.mark.asyncio
    async def test_authorize_device_basic(self, device_api, mock_client):
        """Test authorizing a device."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await device_api.authorize_device(
            device_name="device1",
            adom="root",
        )

        assert result == mock_result
        assert mock_client.exec.called

    @pytest.mark.asyncio
    async def test_authorize_device_with_kwargs(self, device_api, mock_client):
        """Test authorizing device with additional parameters."""
        mock_client.exec.return_value = {"status": "success"}

        result = await device_api.authorize_device(
            device_name="device1",
            username="admin",
            password="password",
            adom="root",
        )

        assert result == {"status": "success"}
        assert mock_client.exec.called


class TestChangeDeviceSerialNumber:
    """Test changing device serial numbers."""

    @pytest.mark.asyncio
    async def test_change_device_serial_number(self, device_api, mock_client):
        """Test changing device serial number."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await device_api.change_device_serial_number(
            device_name="device1",
            new_serial_number="FGT999999",
        )

        assert result == mock_result
        assert mock_client.update.called


class TestGetAvailableTimezones:
    """Test getting available timezones."""

    @pytest.mark.asyncio
    async def test_get_available_timezones(self, device_api, mock_client):
        """Test getting list of available timezones."""
        mock_data = [
            {"id": 1, "name": "UTC"},
            {"id": 2, "name": "America/New_York"},
        ]
        mock_client.get.return_value = mock_data

        result = await device_api.get_available_timezones()

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert "datasrc=device" in call_args[0][0]


class TestGetFullDeviceDBSyntax:
    """Test getting full device DB syntax."""

    @pytest.mark.asyncio
    async def test_get_full_device_db_syntax(self, device_api, mock_client):
        """Test getting full device DB syntax."""
        mock_data = {"syntax": "db_syntax_data"}
        mock_client.get.return_value = mock_data

        result = await device_api.get_full_device_db_syntax(adom="root")

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/pm/config/adom/root/_data/dvmdb"


class TestGetSupportedModelDevices:
    """Test getting supported model devices."""

    @pytest.mark.asyncio
    async def test_get_supported_model_devices(self, device_api, mock_client):
        """Test getting list of supported model devices."""
        mock_data = [
            {"platform": "FortiGate-60E", "version": "7.0"},
            {"platform": "FortiGate-100F", "version": "7.2"},
        ]
        mock_client.get.return_value = mock_data

        result = await device_api.get_supported_model_devices()

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/dvmdb/_data/device/platform"


class TestCreateModelDevice:
    """Test creating model devices."""

    @pytest.mark.asyncio
    async def test_create_model_device_basic(self, device_api, mock_client):
        """Test creating model device with basic parameters."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await device_api.create_model_device(
            name="model_dev",
            serial_number="FGT-MODEL-001",
            platform="FortiGate-60E",
        )

        assert result == mock_result
        assert mock_client.exec.called

    @pytest.mark.asyncio
    async def test_create_model_device_with_mr(self, device_api, mock_client):
        """Test creating model device with maintenance release."""
        mock_client.exec.return_value = {"status": "success"}

        result = await device_api.create_model_device(
            name="model_dev",
            serial_number="FGT-MODEL-001",
            platform="FortiGate-60E",
            mr=4,
        )

        assert result == {"status": "success"}
        assert mock_client.exec.called

    @pytest.mark.asyncio
    async def test_create_model_device_with_kwargs(self, device_api, mock_client):
        """Test creating model device with additional parameters."""
        mock_client.exec.return_value = {"status": "success"}

        result = await device_api.create_model_device(
            name="model_dev",
            serial_number="FGT-MODEL-001",
            platform="FortiGate-60E",
            adom="test_adom",
            desc="Test model device",
        )

        assert result == {"status": "success"}
        assert mock_client.exec.called


class TestListModelDevices:
    """Test listing model devices."""

    @pytest.mark.asyncio
    async def test_list_model_devices_no_adom(self, device_api, mock_client):
        """Test listing model devices without ADOM filter."""
        mock_data = [
            {"name": "model1", "flags": "is_model"},
            {"name": "model2", "flags": "is_model"},
        ]
        mock_client.get.return_value = mock_data

        result = await device_api.list_model_devices()

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/dvmdb/device"
        # Check fields and loadsub were passed
        assert call_args[1]["fields"] == ["name", "sn", "flags", "platform_str", "os_ver"]
        assert call_args[1]["loadsub"] == 0

    @pytest.mark.asyncio
    async def test_list_model_devices_with_adom(self, device_api, mock_client):
        """Test listing model devices with ADOM filter."""
        mock_data = [{"name": "model1"}]
        mock_client.get.return_value = mock_data

        result = await device_api.list_model_devices(adom="root")

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/dvmdb/adom/root/device"


class TestEnableDeviceAutoLink:
    """Test enabling device auto-link."""

    @pytest.mark.asyncio
    async def test_enable_device_auto_link(self, device_api, mock_client):
        """Test enabling auto-link for a device."""
        # Mock getting current device with flags
        mock_client.get.return_value = {"flags": []}
        mock_result = {"status": "success"}
        mock_client.update = AsyncMock(return_value=mock_result)

        result = await device_api.enable_device_auto_link(
            device_name="device1",
            adom="root",
        )

        assert result == mock_result
        # Should get device first
        get_call_args = mock_client.get.call_args
        assert "/dvmdb/adom/root/device/device1" in get_call_args[0][0]
        # Should update with new flags
        update_call_args = mock_client.update.call_args
        assert "auto_link" in update_call_args[1]["data"]["flags"]


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_api_error_propagation(self, device_api, mock_client):
        """Test that API errors are propagated."""
        mock_client.get.side_effect = APIError("API call failed")

        with pytest.raises(APIError):
            await device_api.list_devices()

    @pytest.mark.asyncio
    async def test_resource_not_found_propagation(self, device_api, mock_client):
        """Test that ResourceNotFoundError is propagated."""
        mock_client.get.side_effect = ResourceNotFoundError("Device not found")

        with pytest.raises(ResourceNotFoundError):
            await device_api.get_device("nonexistent")

    @pytest.mark.asyncio
    async def test_list_with_all_parameters(self, device_api, mock_client):
        """Test listing with all parameters."""
        mock_client.get.return_value = []

        await device_api.list_devices(
            adom="test",
            fields=["name", "ip"],
            filter=["conn_status", "==", 1],
        )

        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/dvmdb/adom/test/device"
        assert call_args[1]["fields"] == ["name", "ip"]
        assert call_args[1]["filter"] == ["conn_status", "==", 1]

    @pytest.mark.asyncio
    async def test_device_is_connected_with_string(self, device_api, mock_client):
        """Test device is_connected with string status."""
        mock_data = {"name": "device1", "conn_status": "up"}
        mock_client.get.return_value = mock_data

        result = await device_api.get_device("device1")

        assert result.is_connected is True

    @pytest.mark.asyncio
    async def test_device_is_not_connected(self, device_api, mock_client):
        """Test device is_connected when disconnected."""
        mock_data = {"name": "device1", "conn_status": 0}
        mock_client.get.return_value = mock_data

        result = await device_api.get_device("device1")

        assert result.is_connected is False
