"""Unit tests for api.system module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.system import SystemAPI


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
def system_api(mock_client):
    """Create SystemAPI instance with mock client."""
    return SystemAPI(mock_client)


class TestSystemAPIInit:
    """Test SystemAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = SystemAPI(mock_client)
        assert api.client == mock_client


class TestAdminUserMethods:
    """Test admin user management methods."""

    @pytest.mark.asyncio
    async def test_list_admin_users_success(self, system_api, mock_client):
        """Test listing admin users successfully."""
        mock_data = [
            {"userid": "admin", "profile": "super_admin"},
            {"userid": "user1", "profile": "restricted"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.list_admin_users()

        assert len(result) == 2
        assert result[0]["userid"] == "admin"
        mock_client.get.assert_called_once_with("/cli/global/system/admin/user")

    @pytest.mark.asyncio
    async def test_list_admin_users_single_result(self, system_api, mock_client):
        """Test listing admin users with single result."""
        mock_data = {"userid": "admin"}
        mock_client.get.return_value = mock_data

        result = await system_api.list_admin_users()

        assert len(result) == 1
        assert result[0]["userid"] == "admin"

    @pytest.mark.asyncio
    async def test_list_admin_users_empty(self, system_api, mock_client):
        """Test listing admin users with empty result."""
        mock_client.get.return_value = None

        result = await system_api.list_admin_users()

        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_admin_user_success(self, system_api, mock_client):
        """Test getting specific admin user."""
        mock_data = {"userid": "admin", "profile": "super_admin"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_admin_user("admin")

        assert result["userid"] == "admin"
        mock_client.get.assert_called_once_with("/cli/global/system/admin/user/admin")

    @pytest.mark.asyncio
    async def test_get_admin_user_not_dict(self, system_api, mock_client):
        """Test getting admin user with non-dict result."""
        mock_client.get.return_value = "invalid"

        result = await system_api.get_admin_user("admin")

        assert result == {}


class TestSystemGlobalSettings:
    """Test system global settings methods."""

    @pytest.mark.asyncio
    async def test_get_system_global_settings(self, system_api, mock_client):
        """Test getting system global settings."""
        mock_data = {"hostname": "FMG-001", "timezone": "UTC"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_system_global_settings()

        assert result["hostname"] == "FMG-001"
        mock_client.get.assert_called_once_with("/cli/global/system/global")

    @pytest.mark.asyncio
    async def test_get_system_global_settings_empty(self, system_api, mock_client):
        """Test getting system global settings with empty result."""
        mock_client.get.return_value = None

        result = await system_api.get_system_global_settings()

        assert result == {}

    @pytest.mark.asyncio
    async def test_get_system_status(self, system_api, mock_client):
        """Test getting system status."""
        mock_data = {
            "version": "7.2.0",
            "license": "valid",
            "uptime": 123456,
        }
        mock_client.get.return_value = mock_data

        result = await system_api.get_system_status()

        assert result["version"] == "7.2.0"
        mock_client.get.assert_called_once_with("/sys/status")

    @pytest.mark.asyncio
    async def test_get_system_status_empty(self, system_api, mock_client):
        """Test getting system status with empty result."""
        mock_client.get.return_value = []

        result = await system_api.get_system_status()

        assert result == {}


class TestHighAvailability:
    """Test HA methods."""

    @pytest.mark.asyncio
    async def test_get_ha_config(self, system_api, mock_client):
        """Test getting HA configuration."""
        mock_data = {"mode": "master", "group-id": 1}
        mock_client.get.return_value = mock_data

        result = await system_api.get_ha_config()

        assert result["mode"] == "master"
        mock_client.get.assert_called_once_with("/cli/global/system/ha")

    @pytest.mark.asyncio
    async def test_get_ha_status(self, system_api, mock_client):
        """Test getting HA status."""
        mock_data = {"status": "healthy", "peer": "connected"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_ha_status()

        assert result["status"] == "healthy"
        mock_client.get.assert_called_once_with("/sys/ha/status")


class TestSystemInterfaces:
    """Test system interface methods."""

    @pytest.mark.asyncio
    async def test_list_system_interfaces(self, system_api, mock_client):
        """Test listing system interfaces."""
        mock_data = [
            {"name": "port1", "ip": "192.168.1.1"},
            {"name": "port2", "ip": "10.0.0.1"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.list_system_interfaces()

        assert len(result) == 2
        assert result[0]["name"] == "port1"
        mock_client.get.assert_called_once_with("/cli/global/system/interface")

    @pytest.mark.asyncio
    async def test_list_system_interfaces_single(self, system_api, mock_client):
        """Test listing system interfaces with single result."""
        mock_data = {"name": "port1"}
        mock_client.get.return_value = mock_data

        result = await system_api.list_system_interfaces()

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_system_interface(self, system_api, mock_client):
        """Test getting specific system interface."""
        mock_data = {"name": "port1", "ip": "192.168.1.1"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_system_interface("port1")

        assert result["name"] == "port1"
        mock_client.get.assert_called_once_with("/cli/global/system/interface/port1")


class TestLoggingSettings:
    """Test logging settings methods."""

    @pytest.mark.asyncio
    async def test_get_log_settings(self, system_api, mock_client):
        """Test getting log settings."""
        mock_data = {"log-level": "information", "retention": 30}
        mock_client.get.return_value = mock_data

        result = await system_api.get_log_settings()

        assert result["log-level"] == "information"
        mock_client.get.assert_called_once_with("/cli/global/system/log/settings")


class TestBackupSettings:
    """Test backup settings methods."""

    @pytest.mark.asyncio
    async def test_get_backup_settings(self, system_api, mock_client):
        """Test getting backup settings."""
        mock_data = {"schedule": "daily", "destination": "/backup"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_backup_settings()

        assert result["schedule"] == "daily"
        mock_client.get.assert_called_once_with("/cli/global/system/backup/all-settings")


class TestCertificateManagement:
    """Test certificate management methods."""

    @pytest.mark.asyncio
    async def test_list_certificates(self, system_api, mock_client):
        """Test listing certificates."""
        mock_data = [
            {"name": "cert1", "valid": True},
            {"name": "cert2", "valid": False},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.list_certificates()

        assert len(result) == 2
        assert result[0]["name"] == "cert1"
        mock_client.get.assert_called_once_with("/cli/global/system/certificate/local")

    @pytest.mark.asyncio
    async def test_list_ca_certificates(self, system_api, mock_client):
        """Test listing CA certificates."""
        mock_data = [{"name": "ca-cert1"}]
        mock_client.get.return_value = mock_data

        result = await system_api.list_ca_certificates()

        assert len(result) == 1
        mock_client.get.assert_called_once_with("/cli/global/system/certificate/ca")

    @pytest.mark.asyncio
    async def test_get_certificate_details(self, system_api, mock_client):
        """Test getting certificate details."""
        mock_data = {"name": "cert1", "subject": "CN=Test"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_certificate_details("cert1")

        assert result["name"] == "cert1"
        mock_client.get.assert_called_once_with(
            "/cli/global/system/certificate/local/cert1"
        )


class TestSystemStatus:
    """Test system status operations."""

    @pytest.mark.asyncio
    async def test_get_license_status(self, system_api, mock_client):
        """Test getting license status."""
        mock_data = {"status": "valid", "expiry": "2025-12-31"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_license_status()

        assert result["status"] == "valid"
        mock_client.get.assert_called_once_with("/sys/license/forticare")

    @pytest.mark.asyncio
    async def test_get_system_performance(self, system_api, mock_client):
        """Test getting system performance metrics."""
        mock_data = {"cpu": 45, "memory": 60, "disk": 30}
        mock_client.get.return_value = mock_data

        result = await system_api.get_system_performance()

        assert result["cpu"] == 45
        mock_client.get.assert_called_once_with("/sys/performance")

    @pytest.mark.asyncio
    async def test_get_disk_usage(self, system_api, mock_client):
        """Test getting disk usage information."""
        mock_data = {"disk": {"total": 1000, "used": 300}}
        mock_client.get.return_value = mock_data

        result = await system_api.get_disk_usage()

        assert result["disk"]["used"] == 300
        mock_client.get.assert_called_once_with("/cli/global/system/status")


class TestAdminOperations:
    """Test admin operations methods."""

    @pytest.mark.asyncio
    async def test_list_admin_sessions(self, system_api, mock_client):
        """Test listing active admin sessions."""
        mock_data = [
            {"user": "admin", "ip": "192.168.1.100"},
            {"user": "user1", "ip": "192.168.1.101"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.list_admin_sessions()

        assert len(result) == 2
        assert result[0]["user"] == "admin"
        mock_client.get.assert_called_once_with("/sys/session")

    @pytest.mark.asyncio
    async def test_get_api_user_info(self, system_api, mock_client):
        """Test getting API user info."""
        mock_data = {"user": "api-user", "permissions": ["read", "write"]}
        mock_client.get.return_value = mock_data

        result = await system_api.get_api_user_info()

        assert result["user"] == "api-user"
        mock_client.get.assert_called_once_with("/sys/api/user")

    @pytest.mark.asyncio
    async def test_list_system_admins(self, system_api, mock_client):
        """Test listing system administrators."""
        mock_data = [{"userid": "admin"}, {"userid": "readonly"}]
        mock_client.get.return_value = mock_data

        result = await system_api.list_system_admins()

        assert len(result) == 2
        mock_client.get.assert_called_once_with("/cli/global/system/admin/user")


class TestNetworkSettings:
    """Test network settings methods."""

    @pytest.mark.asyncio
    async def test_get_dns_settings(self, system_api, mock_client):
        """Test getting DNS settings."""
        mock_data = {"primary": "8.8.8.8", "secondary": "8.8.4.4"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_dns_settings()

        assert result["primary"] == "8.8.8.8"
        mock_client.get.assert_called_once_with("/cli/global/system/dns")

    @pytest.mark.asyncio
    async def test_get_ntp_settings(self, system_api, mock_client):
        """Test getting NTP settings."""
        mock_data = {"server": "time.nist.gov", "sync": True}
        mock_client.get.return_value = mock_data

        result = await system_api.get_ntp_settings()

        assert result["server"] == "time.nist.gov"
        mock_client.get.assert_called_once_with("/cli/global/system/ntp")

    @pytest.mark.asyncio
    async def test_get_route_settings(self, system_api, mock_client):
        """Test getting route settings."""
        mock_data = [
            {"destination": "0.0.0.0/0", "gateway": "192.168.1.1"},
            {"destination": "10.0.0.0/8", "gateway": "192.168.1.254"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.get_route_settings()

        assert len(result) == 2
        assert result[0]["destination"] == "0.0.0.0/0"
        mock_client.get.assert_called_once_with("/cli/global/system/route")


class TestAdvancedSystemOperations:
    """Test advanced system operations."""

    @pytest.mark.asyncio
    async def test_get_interface_settings(self, system_api, mock_client):
        """Test getting interface settings."""
        mock_data = [{"name": "port1", "ip": "192.168.1.1"}]
        mock_client.get.return_value = mock_data

        result = await system_api.get_interface_settings()

        assert len(result) == 1
        mock_client.get.assert_called_once_with("/cli/global/system/interface")

    @pytest.mark.asyncio
    async def test_get_snmp_settings(self, system_api, mock_client):
        """Test getting SNMP settings."""
        mock_data = {"community": "public", "trap": True}
        mock_client.get.return_value = mock_data

        result = await system_api.get_snmp_settings()

        assert result["community"] == "public"
        mock_client.get.assert_called_once_with("/cli/global/system/snmp/sysinfo")

    @pytest.mark.asyncio
    async def test_get_syslog_settings(self, system_api, mock_client):
        """Test getting syslog settings."""
        mock_data = [{"server": "syslog1.example.com", "port": 514}]
        mock_client.get.return_value = mock_data

        result = await system_api.get_syslog_settings()

        assert len(result) == 1
        mock_client.get.assert_called_once_with("/cli/global/system/syslog")

    @pytest.mark.asyncio
    async def test_get_email_settings(self, system_api, mock_client):
        """Test getting email settings."""
        mock_data = {"smtp-server": "mail.example.com", "port": 25}
        mock_client.get.return_value = mock_data

        result = await system_api.get_email_settings()

        assert result["smtp-server"] == "mail.example.com"
        mock_client.get.assert_called_once_with("/cli/global/system/email-server")

    @pytest.mark.asyncio
    async def test_get_global_settings(self, system_api, mock_client):
        """Test getting global settings."""
        mock_data = {"hostname": "FMG-001", "timezone": "PST"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_global_settings()

        assert result["hostname"] == "FMG-001"
        mock_client.get.assert_called_once_with("/cli/global/system/global")

    @pytest.mark.asyncio
    async def test_get_admin_settings(self, system_api, mock_client):
        """Test getting admin settings."""
        mock_data = {"timeout": 300, "lockout": 5}
        mock_client.get.return_value = mock_data

        result = await system_api.get_admin_settings()

        assert result["timeout"] == 300
        mock_client.get.assert_called_once_with("/cli/global/system/admin/setting")

    @pytest.mark.asyncio
    async def test_get_fmupdate_settings(self, system_api, mock_client):
        """Test getting FortiManager update settings."""
        mock_data = {"fortiguard": "enabled", "schedule": "daily"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_fmupdate_settings()

        assert result["fortiguard"] == "enabled"
        mock_client.get.assert_called_once_with("/cli/global/fmupdate/service")

    @pytest.mark.asyncio
    async def test_get_sql_settings(self, system_api, mock_client):
        """Test getting SQL settings."""
        mock_data = {"database": "fmg-db", "size": 1000}
        mock_client.get.return_value = mock_data

        result = await system_api.get_sql_settings()

        assert result["database"] == "fmg-db"
        mock_client.get.assert_called_once_with("/cli/global/system/sql")

    @pytest.mark.asyncio
    async def test_get_alert_console_settings(self, system_api, mock_client):
        """Test getting alert console settings."""
        mock_data = {"enabled": True, "threshold": 80}
        mock_client.get.return_value = mock_data

        result = await system_api.get_alert_console_settings()

        assert result["enabled"] is True
        mock_client.get.assert_called_once_with("/cli/global/system/alertconsole")


class TestAdditionalSystemOperations:
    """Test additional system operations from Phase 44."""

    @pytest.mark.asyncio
    async def test_get_backup_status(self, system_api, mock_client):
        """Test getting backup status."""
        mock_data = {"last_backup": "2024-01-01", "status": "success"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_backup_status()

        assert result["status"] == "success"
        mock_client.get.assert_called_once_with("/sys/status/backup")

    @pytest.mark.asyncio
    async def test_get_auto_update_status(self, system_api, mock_client):
        """Test getting auto-update status."""
        mock_data = {"enabled": True, "schedule": "weekly"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_auto_update_status()

        assert result["enabled"] is True
        mock_client.get.assert_called_once_with("/cli/global/system/autoupdate/schedule")

    @pytest.mark.asyncio
    async def test_get_workspace_mode_status(self, system_api, mock_client):
        """Test getting workspace mode status."""
        mock_data = {"workflow-mode": "enable"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_workspace_mode_status()

        assert result["workflow-mode"] == "enable"
        mock_client.get.assert_called_once_with("/cli/global/system/workflow")

    @pytest.mark.asyncio
    async def test_list_connector_types(self, system_api, mock_client):
        """Test listing connector types."""
        mock_data = [{"type": "aws"}, {"type": "azure"}]
        mock_client.get.return_value = mock_data

        result = await system_api.list_connector_types()

        assert len(result) == 2
        mock_client.get.assert_called_once_with("/sys/connector/types")

    @pytest.mark.asyncio
    async def test_get_gui_settings(self, system_api, mock_client):
        """Test getting GUI settings."""
        mock_data = {"theme": "dark", "language": "en"}
        mock_client.get.return_value = mock_data

        result = await system_api.get_gui_settings()

        assert result["theme"] == "dark"
        mock_client.get.assert_called_once_with("/cli/global/system/global")


class TestFinalSystemOperations:
    """Test final system operations from Phase 50."""

    @pytest.mark.asyncio
    async def test_list_tacacs_servers(self, system_api, mock_client):
        """Test listing TACACS+ servers."""
        mock_data = [
            {"name": "tacacs1", "server": "10.0.0.10"},
            {"name": "tacacs2", "server": "10.0.0.11"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.list_tacacs_servers()

        assert len(result) == 2
        assert result[0]["name"] == "tacacs1"
        mock_client.get.assert_called_once_with("/cli/global/system/admin/tacacs")

    @pytest.mark.asyncio
    async def test_get_tacacs_server(self, system_api, mock_client):
        """Test getting specific TACACS+ server."""
        mock_data = {"name": "tacacs1", "server": "10.0.0.10", "port": 49}
        mock_client.get.return_value = mock_data

        result = await system_api.get_tacacs_server("tacacs1")

        assert result["name"] == "tacacs1"
        assert result["port"] == 49
        mock_client.get.assert_called_once_with(
            "/cli/global/system/admin/tacacs/tacacs1"
        )

    @pytest.mark.asyncio
    async def test_get_user_sessions(self, system_api, mock_client):
        """Test getting user sessions."""
        mock_data = [
            {"user": "admin", "ip": "192.168.1.100", "method": "GUI"},
            {"user": "api-user", "ip": "192.168.1.101", "method": "API"},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.get_user_sessions()

        assert len(result) == 2
        assert result[0]["method"] == "GUI"
        mock_client.get.assert_called_once_with("/sys/session")

    @pytest.mark.asyncio
    async def test_create_adom_in_fortianalyzer(self, system_api, mock_client):
        """Test creating ADOM in FortiAnalyzer."""
        mock_client.add.return_value = {"status": {"code": 0}}

        result = await system_api.create_adom_in_fortianalyzer(
            "test-adom", description="Test ADOM"
        )

        assert result["status"]["code"] == 0
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/dvmdb/adom"
        assert call_args[1]["data"]["name"] == "test-adom"
        assert call_args[1]["data"]["desc"] == "Test ADOM"

    @pytest.mark.asyncio
    async def test_create_adom_in_fortianalyzer_no_description(
        self, system_api, mock_client
    ):
        """Test creating ADOM in FortiAnalyzer without description."""
        mock_client.add.return_value = {"status": {"code": 0}}

        await system_api.create_adom_in_fortianalyzer("new-adom")

        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["desc"] == ""

    @pytest.mark.asyncio
    async def test_get_api_user_details(self, system_api, mock_client):
        """Test getting API user details."""
        mock_data = {
            "user": "api-admin",
            "type": "api",
            "permissions": ["read", "write"],
        }
        mock_client.get.return_value = mock_data

        result = await system_api.get_api_user_details()

        assert result["user"] == "api-admin"
        assert result["type"] == "api"
        mock_client.get.assert_called_once_with("/sys/api/user/current")

    @pytest.mark.asyncio
    async def test_reboot_fortimanager_immediate(self, system_api, mock_client):
        """Test rebooting FortiManager immediately."""
        mock_client.execute.return_value = {"status": {"code": 0}}

        result = await system_api.reboot_fortimanager(delay=0)

        assert result["status"]["code"] == 0
        mock_client.execute.assert_called_once_with("/sys/reboot", {"delay": 0})

    @pytest.mark.asyncio
    async def test_reboot_fortimanager_with_delay(self, system_api, mock_client):
        """Test rebooting FortiManager with delay."""
        mock_client.execute.return_value = {"status": {"code": 0}}

        await system_api.reboot_fortimanager(delay=300)

        call_args = mock_client.execute.call_args
        assert call_args[0] == ("/sys/reboot", {"delay": 300})

    @pytest.mark.asyncio
    async def test_backup_fortimanager_config(self, system_api, mock_client):
        """Test backing up FortiManager configuration."""
        mock_client.execute.return_value = {
            "status": {"code": 0},
            "task_id": "12345",
        }

        result = await system_api.backup_fortimanager_config()

        assert result["status"]["code"] == 0
        assert "task_id" in result
        mock_client.execute.assert_called_once_with("/sys/backup", {})

    @pytest.mark.asyncio
    async def test_restore_fortimanager_config(self, system_api, mock_client):
        """Test restoring FortiManager configuration."""
        mock_client.execute.return_value = {
            "status": {"code": 0},
            "task_id": "67890",
        }

        result = await system_api.restore_fortimanager_config(
            "/backup/config-2024-01-01.dat"
        )

        assert result["status"]["code"] == 0
        mock_client.execute.assert_called_once()
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/sys/restore"
        assert call_args[0][1]["file"] == "/backup/config-2024-01-01.dat"

    @pytest.mark.asyncio
    async def test_get_fortiguard_upstream_servers_list_dict(
        self, system_api, mock_client
    ):
        """Test getting FortiGuard upstream servers with dict result."""
        mock_data = {"server": "fortiguard.fortinet.com", "port": 443}
        mock_client.get.return_value = mock_data

        result = await system_api.get_fortiguard_upstream_servers_list()

        assert len(result) == 1
        assert result[0]["server"] == "fortiguard.fortinet.com"
        mock_client.get.assert_called_once_with("/cli/global/system/fortiguard")

    @pytest.mark.asyncio
    async def test_get_fortiguard_upstream_servers_list_list(
        self, system_api, mock_client
    ):
        """Test getting FortiGuard upstream servers with list result."""
        mock_data = [
            {"server": "fg1.fortinet.com", "port": 443},
            {"server": "fg2.fortinet.com", "port": 443},
        ]
        mock_client.get.return_value = mock_data

        result = await system_api.get_fortiguard_upstream_servers_list()

        assert len(result) == 2
        assert result[0]["server"] == "fg1.fortinet.com"

    @pytest.mark.asyncio
    async def test_get_fortiguard_upstream_servers_list_empty(
        self, system_api, mock_client
    ):
        """Test getting FortiGuard upstream servers with empty result."""
        mock_client.get.return_value = None

        result = await system_api.get_fortiguard_upstream_servers_list()

        assert len(result) == 0


class TestSystemErrorHandling:
    """Test system error handling scenarios."""

    @pytest.mark.asyncio
    async def test_get_admin_user_api_error(self, system_api, mock_client):
        """Test handling API error when getting admin user."""
        mock_client.get.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            await system_api.get_admin_user("admin")

    @pytest.mark.asyncio
    async def test_reboot_unauthorized(self, system_api, mock_client):
        """Test handling unauthorized reboot attempt."""
        mock_client.execute.return_value = {
            "status": {"code": -3, "message": "Permission denied"}
        }

        result = await system_api.reboot_fortimanager()

        assert result["status"]["code"] == -3


class TestSystemWorkflows:
    """Test typical system operation workflows."""

    @pytest.mark.asyncio
    async def test_backup_workflow(self, system_api, mock_client):
        """Test typical backup workflow."""
        mock_client.execute.return_value = {"status": {"code": 0}, "task_id": "123"}
        mock_client.get.return_value = {"status": "success"}

        # Trigger backup
        backup_result = await system_api.backup_fortimanager_config()
        # Check backup status
        status = await system_api.get_backup_status()

        assert backup_result["status"]["code"] == 0
        assert status["status"] == "success"

    @pytest.mark.asyncio
    async def test_system_health_check_workflow(self, system_api, mock_client):
        """Test system health check workflow."""
        mock_client.get.return_value = {"status": "ok"}

        # Check various system components
        status = await system_api.get_system_status()
        ha_status = await system_api.get_ha_status()
        license = await system_api.get_license_status()
        performance = await system_api.get_system_performance()

        assert mock_client.get.call_count == 4

    @pytest.mark.asyncio
    async def test_admin_audit_workflow(self, system_api, mock_client):
        """Test admin audit workflow."""
        mock_client.get.return_value = [{"user": "admin"}]

        # Audit admin operations
        users = await system_api.list_admin_users()
        sessions = await system_api.list_admin_sessions()
        admins = await system_api.list_system_admins()

        assert mock_client.get.call_count == 3
