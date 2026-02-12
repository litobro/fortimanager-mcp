"""Unit tests for api.advanced_objects module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.advanced_objects import AdvancedObjectsAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.update = AsyncMock()
    return client


@pytest.fixture
def advanced_objects_api(mock_client):
    """Create AdvancedObjectsAPI instance with mock client."""
    return AdvancedObjectsAPI(mock_client)


class TestAdvancedObjectsAPIInit:
    """Test AdvancedObjectsAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = AdvancedObjectsAPI(mock_client)
        assert api.client == mock_client


class TestVIPs:
    """Test Virtual IP (VIP) operations."""

    @pytest.mark.asyncio
    async def test_list_vips(self, advanced_objects_api, mock_client):
        """Test listing VIPs."""
        mock_data = [
            {"name": "vip1", "extip": "203.0.113.10", "mappedip": "192.168.1.10"},
            {"name": "vip2", "extip": "203.0.113.20", "mappedip": "192.168.1.20"},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_vips(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/vip"
        )

    @pytest.mark.asyncio
    async def test_list_vips_empty(self, advanced_objects_api, mock_client):
        """Test listing VIPs with empty result."""
        mock_client.get.return_value = []

        result = await advanced_objects_api.list_vips(adom="custom")

        assert result == []

    @pytest.mark.asyncio
    async def test_list_vips_single_item(self, advanced_objects_api, mock_client):
        """Test listing VIPs with single item result."""
        mock_data = {"name": "vip1", "extip": "203.0.113.10"}
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_vips(adom="root")

        assert result == [mock_data]

    @pytest.mark.asyncio
    async def test_get_vip(self, advanced_objects_api, mock_client):
        """Test getting VIP details."""
        mock_data = {
            "name": "vip1",
            "extip": "203.0.113.10",
            "mappedip": "192.168.1.10",
            "portforward": "enable",
        }
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.get_vip("vip1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/vip/vip1"
        )

    @pytest.mark.asyncio
    async def test_create_vip_basic(self, advanced_objects_api, mock_client):
        """Test creating basic VIP."""
        mock_result = {"name": "vip1"}
        mock_client.add.return_value = mock_result

        result = await advanced_objects_api.create_vip(
            name="vip1",
            extip="203.0.113.10",
            mappedip="192.168.1.10",
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/vip"
        assert call_args[1]["data"]["name"] == "vip1"
        assert call_args[1]["data"]["extip"] == ["203.0.113.10"]
        assert call_args[1]["data"]["mappedip"] == ["192.168.1.10"]

    @pytest.mark.asyncio
    async def test_create_vip_with_port_forwarding(self, advanced_objects_api, mock_client):
        """Test creating VIP with port forwarding."""
        mock_result = {"name": "web-vip"}
        mock_client.add.return_value = mock_result

        result = await advanced_objects_api.create_vip(
            name="web-vip",
            extip="203.0.113.10",
            mappedip="192.168.1.10",
            adom="root",
            portforward="enable",
            protocol="tcp",
            extport="443",
            mappedport="8443",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["portforward"] == "enable"
        assert call_args[1]["data"]["protocol"] == "tcp"
        assert call_args[1]["data"]["extport"] == "443"

    @pytest.mark.asyncio
    async def test_update_vip(self, advanced_objects_api, mock_client):
        """Test updating VIP."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await advanced_objects_api.update_vip(
            name="vip1",
            adom="root",
            mappedip="192.168.1.20",
        )

        assert result == mock_result
        mock_client.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_vip(self, advanced_objects_api, mock_client):
        """Test deleting VIP."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await advanced_objects_api.delete_vip("vip1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()


class TestIPPools:
    """Test IP Pool operations."""

    @pytest.mark.asyncio
    async def test_list_ip_pools(self, advanced_objects_api, mock_client):
        """Test listing IP pools."""
        mock_data = [
            {"name": "pool1", "startip": "203.0.113.100", "endip": "203.0.113.199"},
            {"name": "pool2", "startip": "203.0.113.200", "endip": "203.0.113.255"},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_ip_pools(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ip_pool(self, advanced_objects_api, mock_client):
        """Test getting IP pool details."""
        mock_data = {
            "name": "pool1",
            "startip": "203.0.113.100",
            "endip": "203.0.113.199",
            "type": "overload",
        }
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.get_ip_pool("pool1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_ip_pool(self, advanced_objects_api, mock_client):
        """Test creating IP pool."""
        mock_result = {"name": "pool1"}
        mock_client.add.return_value = mock_result

        result = await advanced_objects_api.create_ip_pool(
            name="pool1",
            startip="203.0.113.100",
            endip="203.0.113.199",
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_ip_pool(self, advanced_objects_api, mock_client):
        """Test deleting IP pool."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await advanced_objects_api.delete_ip_pool("pool1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()


class TestSchedules:
    """Test schedule operations."""

    @pytest.mark.asyncio
    async def test_list_schedules_recurring(self, advanced_objects_api, mock_client):
        """Test listing recurring schedules."""
        mock_data = [
            {"name": "business-hours", "type": "recurring"},
            {"name": "weekends", "type": "recurring"},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_schedules_recurring(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_schedules_onetime(self, advanced_objects_api, mock_client):
        """Test listing one-time schedules."""
        mock_data = [
            {"name": "maintenance", "type": "onetime"},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_schedules_onetime(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_schedules_group(self, advanced_objects_api, mock_client):
        """Test listing schedule groups."""
        mock_data = [
            {"name": "work-hours-group", "member": ["business-hours"]},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_schedules_group(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_schedule_recurring(self, advanced_objects_api, mock_client):
        """Test creating recurring schedule."""
        mock_result = {"name": "business-hours"}
        mock_client.add.return_value = mock_result

        result = await advanced_objects_api.create_schedule_recurring(
            name="business-hours",
            adom="root",
            day=["monday", "tuesday"],
            start="08:00",
            end="18:00",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_schedule_recurring(self, advanced_objects_api, mock_client):
        """Test deleting recurring schedule."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await advanced_objects_api.delete_schedule_recurring("business-hours", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()


class TestVIPGroups:
    """Test VIP Group operations."""

    @pytest.mark.asyncio
    async def test_list_vip_groups(self, advanced_objects_api, mock_client):
        """Test listing VIP groups."""
        mock_data = [
            {"name": "vipgrp1", "member": ["vip1", "vip2"]},
            {"name": "vipgrp2", "member": ["vip3"]},
        ]
        mock_client.get.return_value = mock_data

        result = await advanced_objects_api.list_vip_groups(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_vip_group(self, advanced_objects_api, mock_client):
        """Test creating VIP group."""
        mock_result = {"name": "vipgrp1"}
        mock_client.add.return_value = mock_result

        result = await advanced_objects_api.create_vip_group(
            name="vipgrp1",
            members=["vip1", "vip2"],
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_vip_group(self, advanced_objects_api, mock_client):
        """Test deleting VIP group."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await advanced_objects_api.delete_vip_group("vipgrp1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()
