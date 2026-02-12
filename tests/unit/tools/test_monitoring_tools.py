"""Unit tests for tools.monitoring_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.api.models import SystemStatus, TaskStatus
from fortimanager_mcp.tools import monitoring_tools


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.execute = AsyncMock()
    return client


@pytest.fixture
def mock_monitoring_api(mock_client):
    """Create mock MonitoringAPI instance."""
    with patch('fortimanager_mcp.tools.monitoring_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.get_system_status = AsyncMock()
        api.list_tasks = AsyncMock()
        api.get_task_status = AsyncMock()
        api.wait_for_task_completion = AsyncMock()
        api.check_device_connectivity = AsyncMock()
        api.list_adom_revisions = AsyncMock()
        api.get_adom_revision = AsyncMock()
        api.create_adom_revision = AsyncMock()
        api.list_global_firewall_addresses = AsyncMock()
        api.get_global_firewall_address = AsyncMock()
        api.list_global_firewall_services = AsyncMock()
        api.get_global_firewall_service = AsyncMock()
        api.list_global_address_groups = AsyncMock()
        api.get_task_details = AsyncMock()
        api.get_system_performance_stats = AsyncMock()
        api.get_device_connectivity_status = AsyncMock()
        api.get_log_statistics = AsyncMock()
        api.get_threat_statistics = AsyncMock()
        api.get_policy_hit_count = AsyncMock()
        api.get_bandwidth_statistics = AsyncMock()
        api.get_session_statistics = AsyncMock()
        api.get_alert_history = AsyncMock()
        api.get_backup_status = AsyncMock()
        api.get_ha_sync_status = AsyncMock()
        
        with patch('fortimanager_mcp.tools.monitoring_tools.MonitoringAPI', return_value=api):
            yield api


class TestGetSystemStatus:
    """Test get_system_status tool."""

    @pytest.mark.asyncio
    async def test_get_system_status_success(self, mock_monitoring_api):
        """Test getting system status successfully."""
        status = SystemStatus(
            version="7.4.0",
            hostname="FMG-01",
            serial="FMG12345",
            admin_domain="root",
            ha_mode="standalone",
            license_status="valid"
        )
        mock_monitoring_api.get_system_status.return_value = status

        result = await monitoring_tools.get_system_status()

        assert result["status"] == "success"
        assert result["system"]["version"] == "7.4.0"
        assert result["system"]["hostname"] == "FMG-01"
        assert result["system"]["serial_number"] == "FMG12345"
        mock_monitoring_api.get_system_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_status_error(self, mock_monitoring_api):
        """Test getting system status with error."""
        mock_monitoring_api.get_system_status.side_effect = Exception("API Error")

        result = await monitoring_tools.get_system_status()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestListTasks:
    """Test list_tasks tool."""

    @pytest.mark.asyncio
    async def test_list_tasks_success(self, mock_monitoring_api):
        """Test listing tasks successfully."""
        task1 = TaskStatus(
            id=1,
            title="Install Policy",
            state="done",
            percent=100,
            num_done=1,
            num_lines=1,
            num_err=0,
            num_warn=0
        )
        task2 = TaskStatus(
            id=2,
            title="Install Device",
            state="running",
            percent=50,
            num_done=0,
            num_lines=1,
            num_err=0,
            num_warn=0
        )
        mock_monitoring_api.list_tasks.return_value = [task1, task2]

        result = await monitoring_tools.list_tasks(limit=10)

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["tasks"]) == 2
        assert result["tasks"][0]["task_id"] == 1
        assert result["tasks"][0]["state"] == "done"
        assert result["tasks"][1]["task_id"] == 2
        mock_monitoring_api.list_tasks.assert_called_once_with(limit=10)

    @pytest.mark.asyncio
    async def test_list_tasks_no_limit(self, mock_monitoring_api):
        """Test listing tasks without limit."""
        mock_monitoring_api.list_tasks.return_value = []

        result = await monitoring_tools.list_tasks()

        assert result["status"] == "success"
        assert result["count"] == 0
        mock_monitoring_api.list_tasks.assert_called_once_with(limit=None)

    @pytest.mark.asyncio
    async def test_list_tasks_error(self, mock_monitoring_api):
        """Test listing tasks with error."""
        mock_monitoring_api.list_tasks.side_effect = Exception("API Error")

        result = await monitoring_tools.list_tasks()

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestListRecentTasks:
    """Test list_recent_tasks tool."""

    @pytest.mark.asyncio
    async def test_list_recent_tasks_success(self, mock_monitoring_api):
        """Test listing recent tasks successfully."""
        task = TaskStatus(id=1, title="Recent TaskStatus", state="done", percent=100)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.list_recent_tasks(limit=10)

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_monitoring_api.list_tasks.assert_called_once_with(limit=10)


class TestGetTaskStatus:
    """Test get_task_status tool."""

    @pytest.mark.asyncio
    async def test_get_task_status_success(self, mock_monitoring_api):
        """Test getting task status successfully."""
        task = TaskStatus(
            id=123,
            title="Install Policy",
            state="done",
            percent=100,
            num_done=1,
            num_lines=1,
            num_err=0,
            num_warn=0
        )
        mock_monitoring_api.get_task_status.return_value = task

        result = await monitoring_tools.get_task_status(task_id=123)

        assert result["status"] == "success"
        assert result["task"]["task_id"] == 123
        assert result["task"]["state"] == "done"
        assert result["task"]["progress"] == 100
        mock_monitoring_api.get_task_status.assert_called_once_with(task_id=123)

    @pytest.mark.asyncio
    async def test_get_task_status_error(self, mock_monitoring_api):
        """Test getting task status with error."""
        mock_monitoring_api.get_task_status.side_effect = Exception("TaskStatus not found")

        result = await monitoring_tools.get_task_status(task_id=999)

        assert result["status"] == "error"
        assert "TaskStatus not found" in result["message"]


class TestWaitForTaskCompletion:
    """Test wait_for_task_completion tool."""

    @pytest.mark.asyncio
    async def test_wait_for_task_completion_success(self, mock_monitoring_api):
        """Test waiting for task completion successfully."""
        task = TaskStatus(id=123, title="TaskStatus", state="done", percent=100)
        mock_monitoring_api.wait_for_task_completion.return_value = task

        result = await monitoring_tools.wait_for_task_completion(
            task_id=123,
            timeout=300
        )

        assert result["status"] == "success"
        assert result["task"]["state"] == "done"
        mock_monitoring_api.wait_for_task_completion.assert_called_once_with(
            task_id=123,
            timeout=300,
            poll_interval=5
        )

    @pytest.mark.asyncio
    async def test_wait_for_task_completion_custom_interval(self, mock_monitoring_api):
        """Test waiting for task completion with custom poll interval."""
        task = TaskStatus(id=123, title="TaskStatus", state="done", percent=100)
        mock_monitoring_api.wait_for_task_completion.return_value = task

        result = await monitoring_tools.wait_for_task_completion(
            task_id=123,
            timeout=300,
            poll_interval=10
        )

        assert result["status"] == "success"
        mock_monitoring_api.wait_for_task_completion.assert_called_once_with(
            task_id=123,
            timeout=300,
            poll_interval=10
        )

    @pytest.mark.asyncio
    async def test_wait_for_task_completion_error(self, mock_monitoring_api):
        """Test waiting for task completion with error."""
        mock_monitoring_api.wait_for_task_completion.side_effect = Exception("Timeout")

        result = await monitoring_tools.wait_for_task_completion(task_id=123)

        assert result["status"] == "error"
        assert "Timeout" in result["message"]


class TestCheckDeviceConnectivity:
    """Test check_device_connectivity tool."""

    @pytest.mark.asyncio
    async def test_check_device_connectivity_success(self, mock_monitoring_api):
        """Test checking device connectivity successfully."""
        mock_monitoring_api.check_device_connectivity.return_value = {
            "connected": True,
            "status": "online"
        }

        result = await monitoring_tools.check_device_connectivity(
            device="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        assert "connectivity" in result
        mock_monitoring_api.check_device_connectivity.assert_called_once_with(
            device="FGT-01",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_check_device_connectivity_error(self, mock_monitoring_api):
        """Test checking device connectivity with error."""
        mock_monitoring_api.check_device_connectivity.side_effect = Exception("Device not found")

        result = await monitoring_tools.check_device_connectivity(device="FGT-01")

        assert result["status"] == "error"
        assert "Device not found" in result["message"]


class TestAdomRevisions:
    """Test ADOM revision tools."""

    @pytest.mark.asyncio
    async def test_list_adom_revisions_success(self, mock_monitoring_api):
        """Test listing ADOM revisions successfully."""
        mock_monitoring_api.list_adom_revisions.return_value = [
            {"name": "rev1", "created_time": "2024-01-01"},
            {"name": "rev2", "created_time": "2024-01-02"}
        ]

        result = await monitoring_tools.list_adom_revisions(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_monitoring_api.list_adom_revisions.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_adom_revision_success(self, mock_monitoring_api):
        """Test getting ADOM revision successfully."""
        mock_monitoring_api.get_adom_revision.return_value = {
            "name": "rev1",
            "created_time": "2024-01-01",
            "description": "Test revision"
        }

        result = await monitoring_tools.get_adom_revision(
            revision_name="rev1",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["revision"]["name"] == "rev1"
        mock_monitoring_api.get_adom_revision.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_adom_revision_success(self, mock_monitoring_api):
        """Test creating ADOM revision successfully."""
        mock_monitoring_api.create_adom_revision.return_value = {"name": "new_rev"}

        result = await monitoring_tools.create_adom_revision(
            name="new_rev",
            adom="root",
            description="New revision"
        )

        assert result["status"] == "success"
        mock_monitoring_api.create_adom_revision.assert_called_once()


class TestGlobalObjects:
    """Test global object tools."""

    @pytest.mark.asyncio
    async def test_list_global_firewall_addresses_success(self, mock_monitoring_api):
        """Test listing global firewall addresses successfully."""
        mock_monitoring_api.list_global_firewall_addresses.return_value = [
            {"name": "addr1"},
            {"name": "addr2"}
        ]

        result = await monitoring_tools.list_global_firewall_addresses()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_monitoring_api.list_global_firewall_addresses.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_global_firewall_address_success(self, mock_monitoring_api):
        """Test getting global firewall address successfully."""
        mock_monitoring_api.get_global_firewall_address.return_value = {
            "name": "addr1",
            "subnet": "10.0.0.0/8"
        }

        result = await monitoring_tools.get_global_firewall_address(name="addr1")

        assert result["status"] == "success"
        assert result["address"]["name"] == "addr1"
        mock_monitoring_api.get_global_firewall_address.assert_called_once_with(name="addr1")

    @pytest.mark.asyncio
    async def test_list_global_firewall_services_success(self, mock_monitoring_api):
        """Test listing global firewall services successfully."""
        mock_monitoring_api.list_global_firewall_services.return_value = [
            {"name": "HTTP"},
            {"name": "HTTPS"}
        ]

        result = await monitoring_tools.list_global_firewall_services()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_monitoring_api.list_global_firewall_services.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_global_firewall_service_success(self, mock_monitoring_api):
        """Test getting global firewall service successfully."""
        mock_monitoring_api.get_global_firewall_service.return_value = {
            "name": "HTTP",
            "tcp_portrange": "80"
        }

        result = await monitoring_tools.get_global_firewall_service(name="HTTP")

        assert result["status"] == "success"
        assert result["service"]["name"] == "HTTP"
        mock_monitoring_api.get_global_firewall_service.assert_called_once_with(name="HTTP")

    @pytest.mark.asyncio
    async def test_list_global_address_groups_success(self, mock_monitoring_api):
        """Test listing global address groups successfully."""
        mock_monitoring_api.list_global_address_groups.return_value = [
            {"name": "group1"},
            {"name": "group2"}
        ]

        result = await monitoring_tools.list_global_address_groups()

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_monitoring_api.list_global_address_groups.assert_called_once()


class TestTaskManagement:
    """Test advanced task management tools."""

    @pytest.mark.asyncio
    async def test_list_all_tasks_success(self, mock_monitoring_api):
        """Test listing all tasks successfully."""
        task = TaskStatus(id=1, title="TaskStatus", state="done", percent=100)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.list_all_tasks(limit=100)

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_monitoring_api.list_tasks.assert_called_once_with(limit=100)

    @pytest.mark.asyncio
    async def test_get_task_details_success(self, mock_monitoring_api):
        """Test getting task details successfully."""
        mock_monitoring_api.get_task_details.return_value = {
            "id": 123,
            "title": "TaskStatus",
            "state": "done"
        }

        result = await monitoring_tools.get_task_details(task_id=123)

        assert result["status"] == "success"
        assert result["task"]["id"] == 123
        mock_monitoring_api.get_task_details.assert_called_once_with(task_id=123)

    @pytest.mark.asyncio
    async def test_list_running_tasks_success(self, mock_monitoring_api):
        """Test listing running tasks successfully."""
        task = TaskStatus(id=1, title="Running", state="running", percent=50)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.list_running_tasks(limit=50)

        assert result["status"] == "success"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_list_failed_tasks_success(self, mock_monitoring_api):
        """Test listing failed tasks successfully."""
        task = TaskStatus(id=1, title="Failed", state="error", percent=0, num_err=1)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.list_failed_tasks(limit=50)

        assert result["status"] == "success"
        assert result["count"] == 1


class TestGetTaskHistory:
    """Test get_task_history tool."""

    @pytest.mark.asyncio
    async def test_get_task_history_success(self, mock_monitoring_api):
        """Test getting task history successfully."""
        task = TaskStatus(id=1, title="TaskStatus", state="done", percent=100)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.get_task_history(limit=100)

        assert result["status"] == "success"
        mock_monitoring_api.list_tasks.assert_called_once_with(limit=100)

    @pytest.mark.asyncio
    async def test_get_task_history_with_filter(self, mock_monitoring_api):
        """Test getting task history with filter."""
        task = TaskStatus(id=1, title="Install", state="done", percent=100)
        mock_monitoring_api.list_tasks.return_value = [task]

        result = await monitoring_tools.get_task_history(
            limit=100,
            filter_type="install"
        )

        assert result["status"] == "success"


class TestPerformanceAndStatistics:
    """Test performance and statistics tools."""

    @pytest.mark.asyncio
    async def test_get_system_performance_stats_success(self, mock_monitoring_api):
        """Test getting system performance stats successfully."""
        mock_monitoring_api.get_system_performance_stats.return_value = {
            "cpu_usage": 25.5,
            "memory_usage": 45.2
        }

        result = await monitoring_tools.get_system_performance_stats()

        assert result["status"] == "success"
        mock_monitoring_api.get_system_performance_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_device_connectivity_status_success(self, mock_monitoring_api):
        """Test getting device connectivity status successfully."""
        mock_monitoring_api.get_device_connectivity_status.return_value = {
            "total": 10,
            "connected": 8
        }

        result = await monitoring_tools.get_device_connectivity_status(adom="root")

        assert result["status"] == "success"
        mock_monitoring_api.get_device_connectivity_status.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_log_statistics_success(self, mock_monitoring_api):
        """Test getting log statistics successfully."""
        mock_monitoring_api.get_log_statistics.return_value = {
            "total_logs": 10000
        }

        result = await monitoring_tools.get_log_statistics(adom="root")

        assert result["status"] == "success"
        mock_monitoring_api.get_log_statistics.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_threat_statistics_success(self, mock_monitoring_api):
        """Test getting threat statistics successfully."""
        mock_monitoring_api.get_threat_statistics.return_value = {
            "threats_blocked": 100
        }

        result = await monitoring_tools.get_threat_statistics(
            adom="root",
            time_range="24h"
        )

        assert result["status"] == "success"
        mock_monitoring_api.get_threat_statistics.assert_called_once_with(
            adom="root",
            time_range="24h"
        )

    @pytest.mark.asyncio
    async def test_get_policy_hit_count_success(self, mock_monitoring_api):
        """Test getting policy hit count successfully."""
        mock_monitoring_api.get_policy_hit_count.return_value = {
            "policy_hits": 5000
        }

        result = await monitoring_tools.get_policy_hit_count(
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_monitoring_api.get_policy_hit_count.assert_called_once_with(
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_get_bandwidth_statistics_success(self, mock_monitoring_api):
        """Test getting bandwidth statistics successfully."""
        mock_monitoring_api.get_bandwidth_statistics.return_value = {
            "inbound": 1000000,
            "outbound": 2000000
        }

        result = await monitoring_tools.get_bandwidth_statistics(
            device="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_monitoring_api.get_bandwidth_statistics.assert_called_once_with(
            device="FGT-01",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_get_session_statistics_success(self, mock_monitoring_api):
        """Test getting session statistics successfully."""
        mock_monitoring_api.get_session_statistics.return_value = {
            "active_sessions": 1000
        }

        result = await monitoring_tools.get_session_statistics(
            device="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_monitoring_api.get_session_statistics.assert_called_once_with(
            device="FGT-01",
            adom="root"
        )


class TestAlertAndBackup:
    """Test alert and backup tools."""

    @pytest.mark.asyncio
    async def test_get_alert_history_success(self, mock_monitoring_api):
        """Test getting alert history successfully."""
        mock_monitoring_api.get_alert_history.return_value = [
            {"id": 1, "message": "Alert 1"},
            {"id": 2, "message": "Alert 2"}
        ]

        result = await monitoring_tools.get_alert_history(limit=100)

        assert result["status"] == "success"
        mock_monitoring_api.get_alert_history.assert_called_once_with(limit=100)

    @pytest.mark.asyncio
    async def test_get_backup_status_success(self, mock_monitoring_api):
        """Test getting backup status successfully."""
        mock_monitoring_api.get_backup_status.return_value = {
            "last_backup": "2024-01-01",
            "status": "success"
        }

        result = await monitoring_tools.get_backup_status()

        assert result["status"] == "success"
        mock_monitoring_api.get_backup_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ha_sync_status_success(self, mock_monitoring_api):
        """Test getting HA sync status successfully."""
        mock_monitoring_api.get_ha_sync_status.return_value = {
            "sync_status": "in_sync"
        }

        result = await monitoring_tools.get_ha_sync_status()

        assert result["status"] == "success"
        mock_monitoring_api.get_ha_sync_status.assert_called_once()


class TestGetMonitoringApiError:
    """Test _get_monitoring_api error handling."""

    @pytest.mark.asyncio
    async def test_get_monitoring_api_no_client(self):
        """Test _get_monitoring_api with no client."""
        with patch('fortimanager_mcp.tools.monitoring_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                monitoring_tools._get_monitoring_api()
