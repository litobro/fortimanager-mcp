"""Unit tests for tools.system_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.tools import system_tools


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.set = AsyncMock()
    client.execute = AsyncMock()
    return client


@pytest.fixture
def mock_system_api(mock_client):
    """Create mock SystemAPI instance."""
    with patch('fortimanager_mcp.tools.system_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.list_admin_users = AsyncMock()
        api.get_admin_user = AsyncMock()
        api.get_system_global_settings = AsyncMock()
        api.get_system_status = AsyncMock()
        api.get_ha_configuration = AsyncMock()
        api.get_ha_status = AsyncMock()
        api.list_system_interfaces = AsyncMock()
        api.get_system_interface = AsyncMock()
        api.get_log_settings = AsyncMock()
        api.get_backup_settings = AsyncMock()
        api.list_system_certificates = AsyncMock()
        api.list_ca_certificates = AsyncMock()
        api.get_certificate_details = AsyncMock()
        api.get_license_status = AsyncMock()
        api.get_system_performance = AsyncMock()
        api.get_disk_usage = AsyncMock()
        api.list_admin_sessions = AsyncMock()
        api.get_api_user_info = AsyncMock()
        api.list_system_administrators = AsyncMock()
        api.get_system_dns_settings = AsyncMock()
        api.get_system_ntp_settings = AsyncMock()
        api.get_system_routes = AsyncMock()
        api.get_system_interfaces = AsyncMock()
        api.get_snmp_config = AsyncMock()
        api.get_syslog_config = AsyncMock()
        api.get_email_server_config = AsyncMock()
        api.get_global_system_config = AsyncMock()
        api.get_admin_config = AsyncMock()
        api.get_log_config = AsyncMock()
        
        with patch('fortimanager_mcp.tools.system_tools.SystemAPI', return_value=api):
            yield api


class TestListAdminUsers:
    """Test list_admin_users tool."""

    @pytest.mark.asyncio
    async def test_list_admin_users_success(self, mock_system_api):
        """Test listing admin users successfully."""
        mock_system_api.list_admin_users.return_value = [
            {"userid": "admin", "profileid": "Super_User"},
            {"userid": "user1", "profileid": "Standard_User"}
        ]

        result = await system_tools.list_admin_users()

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["users"]) == 2
        mock_system_api.list_admin_users.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_admin_users_empty(self, mock_system_api):
        """Test listing admin users with empty result."""
        mock_system_api.list_admin_users.return_value = []

        result = await system_tools.list_admin_users()

        assert result["status"] == "success"
        assert result["count"] == 0


class TestGetAdminUser:
    """Test get_admin_user tool."""

    @pytest.mark.asyncio
    async def test_get_admin_user_success(self, mock_system_api):
        """Test getting admin user successfully."""
        mock_system_api.get_admin_user.return_value = {
            "userid": "admin",
            "profileid": "Super_User",
            "trusthost1": "0.0.0.0/0"
        }

        result = await system_tools.get_admin_user(username="admin")

        assert result["status"] == "success"
        assert result["user"]["userid"] == "admin"
        mock_system_api.get_admin_user.assert_called_once_with(username="admin")


class TestGetSystemGlobalSettings:
    """Test get_system_global_settings tool."""

    @pytest.mark.asyncio
    async def test_get_system_global_settings_success(self, mock_system_api):
        """Test getting system global settings successfully."""
        mock_system_api.get_system_global_settings.return_value = {
            "hostname": "FMG-01",
            "admin-timeout": 480,
            "timezone": "04"
        }

        result = await system_tools.get_system_global_settings()

        assert result["status"] == "success"
        assert "settings" in result
        mock_system_api.get_system_global_settings.assert_called_once()


class TestGetSystemStatus:
    """Test get_system_status tool."""

    @pytest.mark.asyncio
    async def test_get_system_status_success(self, mock_system_api):
        """Test getting system status successfully."""
        mock_system_api.get_system_status.return_value = {
            "version": "7.4.0",
            "serial": "FMG12345",
            "hostname": "FMG-01"
        }

        result = await system_tools.get_system_status()

        assert result["status"] == "success"
        assert "system_status" in result
        mock_system_api.get_system_status.assert_called_once()


class TestHAConfiguration:
    """Test HA configuration tools."""

    @pytest.mark.asyncio
    async def test_get_ha_configuration_success(self, mock_system_api):
        """Test getting HA configuration successfully."""
        mock_system_api.get_ha_configuration.return_value = {
            "mode": "standalone",
            "group-id": 0
        }

        result = await system_tools.get_ha_configuration()

        assert result["status"] == "success"
        assert "ha_config" in result
        mock_system_api.get_ha_configuration.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ha_status_success(self, mock_system_api):
        """Test getting HA status successfully."""
        mock_system_api.get_ha_status.return_value = {
            "status": "standalone"
        }

        result = await system_tools.get_ha_status()

        assert result["status"] == "success"
        assert "ha_status" in result
        mock_system_api.get_ha_status.assert_called_once()


class TestSystemInterfaces:
    """Test system interface tools."""

    @pytest.mark.asyncio
    async def test_list_system_interfaces_success(self, mock_system_api):
        """Test listing system interfaces successfully."""
        mock_system_api.list_system_interfaces.return_value = [
            {"name": "port1", "ip": "192.168.1.1"},
            {"name": "port2", "ip": "192.168.2.1"}
        ]

        result = await system_tools.list_system_interfaces()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_system_api.list_system_interfaces.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_interface_success(self, mock_system_api):
        """Test getting system interface successfully."""
        mock_system_api.get_system_interface.return_value = {
            "name": "port1",
            "ip": "192.168.1.1",
            "allowaccess": ["ping", "https", "ssh"]
        }

        result = await system_tools.get_system_interface(name="port1")

        assert result["status"] == "success"
        assert result["interface"]["name"] == "port1"
        mock_system_api.get_system_interface.assert_called_once_with(name="port1")


class TestLogSettings:
    """Test log settings tools."""

    @pytest.mark.asyncio
    async def test_get_log_settings_success(self, mock_system_api):
        """Test getting log settings successfully."""
        mock_system_api.get_log_settings.return_value = {
            "status": "enable",
            "log-forward": "enable"
        }

        result = await system_tools.get_log_settings()

        assert result["status"] == "success"
        assert "log_settings" in result
        mock_system_api.get_log_settings.assert_called_once()


class TestBackupSettings:
    """Test backup settings tools."""

    @pytest.mark.asyncio
    async def test_get_backup_settings_success(self, mock_system_api):
        """Test getting backup settings successfully."""
        mock_system_api.get_backup_settings.return_value = {
            "status": "enable",
            "schedule": "daily"
        }

        result = await system_tools.get_backup_settings()

        assert result["status"] == "success"
        assert "backup_settings" in result
        mock_system_api.get_backup_settings.assert_called_once()


class TestCertificates:
    """Test certificate tools."""

    @pytest.mark.asyncio
    async def test_list_system_certificates_success(self, mock_system_api):
        """Test listing system certificates successfully."""
        mock_system_api.list_system_certificates.return_value = [
            {"name": "cert1", "subject": "CN=FMG-01"},
            {"name": "cert2", "subject": "CN=FMG-02"}
        ]

        result = await system_tools.list_system_certificates()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_system_api.list_system_certificates.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_ca_certificates_success(self, mock_system_api):
        """Test listing CA certificates successfully."""
        mock_system_api.list_ca_certificates.return_value = [
            {"name": "ca1", "subject": "CN=CA-01"}
        ]

        result = await system_tools.list_ca_certificates()

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_system_api.list_ca_certificates.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_certificate_details_success(self, mock_system_api):
        """Test getting certificate details successfully."""
        mock_system_api.get_certificate_details.return_value = {
            "name": "cert1",
            "subject": "CN=FMG-01",
            "issuer": "CN=CA-01",
            "valid_from": "2024-01-01",
            "valid_to": "2025-01-01"
        }

        result = await system_tools.get_certificate_details(name="cert1")

        assert result["status"] == "success"
        assert result["certificate"]["name"] == "cert1"
        mock_system_api.get_certificate_details.assert_called_once_with(name="cert1")


class TestLicenseStatus:
    """Test license status tools."""

    @pytest.mark.asyncio
    async def test_get_license_status_success(self, mock_system_api):
        """Test getting license status successfully."""
        mock_system_api.get_license_status.return_value = {
            "status": "valid",
            "expiry": "2025-12-31"
        }

        result = await system_tools.get_license_status()

        assert result["status"] == "success"
        assert "license" in result
        mock_system_api.get_license_status.assert_called_once()


class TestSystemPerformance:
    """Test system performance tools."""

    @pytest.mark.asyncio
    async def test_get_system_performance_success(self, mock_system_api):
        """Test getting system performance successfully."""
        mock_system_api.get_system_performance.return_value = {
            "cpu_usage": 25.5,
            "memory_usage": 45.2
        }

        result = await system_tools.get_system_performance()

        assert result["status"] == "success"
        assert "performance" in result
        mock_system_api.get_system_performance.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_disk_usage_success(self, mock_system_api):
        """Test getting disk usage successfully."""
        mock_system_api.get_disk_usage.return_value = {
            "total": 100000,
            "used": 45000,
            "available": 55000
        }

        result = await system_tools.get_disk_usage()

        assert result["status"] == "success"
        assert "disk_usage" in result
        mock_system_api.get_disk_usage.assert_called_once()


class TestAdminSessions:
    """Test admin session tools."""

    @pytest.mark.asyncio
    async def test_list_admin_sessions_success(self, mock_system_api):
        """Test listing admin sessions successfully."""
        mock_system_api.list_admin_sessions.return_value = [
            {"user": "admin", "from": "192.168.1.100"},
            {"user": "user1", "from": "192.168.1.101"}
        ]

        result = await system_tools.list_admin_sessions()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_system_api.list_admin_sessions.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_api_user_info_success(self, mock_system_api):
        """Test getting API user info successfully."""
        mock_system_api.get_api_user_info.return_value = {
            "user": "api_user",
            "profile": "Read_Only"
        }

        result = await system_tools.get_api_user_info()

        assert result["status"] == "success"
        assert "user_info" in result
        mock_system_api.get_api_user_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_system_administrators_success(self, mock_system_api):
        """Test listing system administrators successfully."""
        mock_system_api.list_system_administrators.return_value = [
            {"userid": "admin"},
            {"userid": "user1"}
        ]

        result = await system_tools.list_system_administrators()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_system_api.list_system_administrators.assert_called_once()


class TestNetworkSettings:
    """Test network settings tools."""

    @pytest.mark.asyncio
    async def test_get_system_dns_settings_success(self, mock_system_api):
        """Test getting system DNS settings successfully."""
        mock_system_api.get_system_dns_settings.return_value = {
            "primary": "8.8.8.8",
            "secondary": "8.8.4.4"
        }

        result = await system_tools.get_system_dns_settings()

        assert result["status"] == "success"
        assert "dns_settings" in result
        mock_system_api.get_system_dns_settings.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_ntp_settings_success(self, mock_system_api):
        """Test getting system NTP settings successfully."""
        mock_system_api.get_system_ntp_settings.return_value = {
            "server": "pool.ntp.org",
            "sync-interval": 60
        }

        result = await system_tools.get_system_ntp_settings()

        assert result["status"] == "success"
        assert "ntp_settings" in result
        mock_system_api.get_system_ntp_settings.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_routes_success(self, mock_system_api):
        """Test getting system routes successfully."""
        mock_system_api.get_system_routes.return_value = [
            {"destination": "0.0.0.0/0", "gateway": "192.168.1.1"},
            {"destination": "10.0.0.0/8", "gateway": "192.168.1.2"}
        ]

        result = await system_tools.get_system_routes()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_system_api.get_system_routes.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_interfaces_success(self, mock_system_api):
        """Test getting system interfaces successfully."""
        mock_system_api.get_system_interfaces.return_value = [
            {"name": "port1"},
            {"name": "port2"}
        ]

        result = await system_tools.get_system_interfaces()

        assert result["status"] == "success"
        mock_system_api.get_system_interfaces.assert_called_once()


class TestSystemConfig:
    """Test system configuration tools."""

    @pytest.mark.asyncio
    async def test_get_snmp_config_success(self, mock_system_api):
        """Test getting SNMP config successfully."""
        mock_system_api.get_snmp_config.return_value = {
            "status": "enable",
            "location": "Datacenter"
        }

        result = await system_tools.get_snmp_config()

        assert result["status"] == "success"
        mock_system_api.get_snmp_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_syslog_config_success(self, mock_system_api):
        """Test getting syslog config successfully."""
        mock_system_api.get_syslog_config.return_value = {
            "status": "enable",
            "server": "syslog.example.com"
        }

        result = await system_tools.get_syslog_config()

        assert result["status"] == "success"
        mock_system_api.get_syslog_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_email_server_config_success(self, mock_system_api):
        """Test getting email server config successfully."""
        mock_system_api.get_email_server_config.return_value = {
            "server": "smtp.example.com",
            "port": 25
        }

        result = await system_tools.get_email_server_config()

        assert result["status"] == "success"
        mock_system_api.get_email_server_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_global_system_config_success(self, mock_system_api):
        """Test getting global system config successfully."""
        mock_system_api.get_global_system_config.return_value = {
            "hostname": "FMG-01",
            "timezone": "04"
        }

        result = await system_tools.get_global_system_config()

        assert result["status"] == "success"
        mock_system_api.get_global_system_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_admin_config_success(self, mock_system_api):
        """Test getting admin config successfully."""
        mock_system_api.get_admin_config.return_value = {
            "admin-timeout": 480
        }

        result = await system_tools.get_admin_config()

        assert result["status"] == "success"
        mock_system_api.get_admin_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_log_config_success(self, mock_system_api):
        """Test getting log config successfully."""
        mock_system_api.get_log_config.return_value = {
            "status": "enable"
        }

        result = await system_tools.get_log_config()

        assert result["status"] == "success"
        mock_system_api.get_log_config.assert_called_once()


class TestGetSystemApiError:
    """Test _get_system_api error handling."""

    @pytest.mark.asyncio
    async def test_get_system_api_no_client(self):
        """Test _get_system_api with no client."""
        with patch('fortimanager_mcp.tools.system_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                system_tools._get_system_api()
