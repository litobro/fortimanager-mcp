"""Unit tests for api.sdwan module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.sdwan import SdwanAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    return client


@pytest.fixture
def sdwan_api(mock_client):
    """Create SdwanAPI instance with mock client."""
    return SdwanAPI(mock_client)


class TestSdwanAPIInit:
    """Test SdwanAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = SdwanAPI(mock_client)
        assert api.client == mock_client


class TestSdwanZones:
    """Test SD-WAN zone operations."""

    @pytest.mark.asyncio
    async def test_list_sdwan_zones(self, sdwan_api, mock_client):
        """Test listing SD-WAN zones."""
        mock_data = [
            {"name": "virtual-wan-link", "service-sla-tie-break": "cfg-order"},
            {"name": "zone1", "advpn-select": "enable"},
        ]
        mock_client.get.return_value = mock_data

        result = await sdwan_api.list_sdwan_zones(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdwan/zone"
        )

    @pytest.mark.asyncio
    async def test_list_sdwan_zones_empty(self, sdwan_api, mock_client):
        """Test listing SD-WAN zones with empty result."""
        mock_client.get.return_value = []

        result = await sdwan_api.list_sdwan_zones(adom="custom")

        assert result == []
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_sdwan_zones_single_item(self, sdwan_api, mock_client):
        """Test listing SD-WAN zones with single item result."""
        mock_data = {"name": "virtual-wan-link"}
        mock_client.get.return_value = mock_data

        result = await sdwan_api.list_sdwan_zones(adom="root")

        assert result == [mock_data]

    @pytest.mark.asyncio
    async def test_get_sdwan_zone(self, sdwan_api, mock_client):
        """Test getting SD-WAN zone details."""
        mock_data = {
            "name": "virtual-wan-link",
            "service-sla-tie-break": "cfg-order",
        }
        mock_client.get.return_value = mock_data

        result = await sdwan_api.get_sdwan_zone("virtual-wan-link", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdwan/zone/virtual-wan-link"
        )

    @pytest.mark.asyncio
    async def test_create_sdwan_zone(self, sdwan_api, mock_client):
        """Test creating SD-WAN zone."""
        mock_result = {"name": "zone1"}
        mock_client.add.return_value = mock_result

        result = await sdwan_api.create_sdwan_zone(
            name="zone1",
            adom="root",
            advpn_select="enable",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/system/sdwan/zone"
        assert call_args[0][1]["name"] == "zone1"
        assert call_args[0][1]["advpn_select"] == "enable"

    @pytest.mark.asyncio
    async def test_delete_sdwan_zone(self, sdwan_api, mock_client):
        """Test deleting SD-WAN zone."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await sdwan_api.delete_sdwan_zone("zone1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdwan/zone/zone1"
        )


class TestHealthChecks:
    """Test SD-WAN health check operations."""

    @pytest.mark.asyncio
    async def test_list_sdwan_health_checks(self, sdwan_api, mock_client):
        """Test listing SD-WAN health checks."""
        mock_data = [
            {"name": "health1", "server": "8.8.8.8", "protocol": "ping"},
            {"name": "health2", "server": "1.1.1.1", "protocol": "http"},
        ]
        mock_client.get.return_value = mock_data

        result = await sdwan_api.list_sdwan_health_checks(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdwan/health-check"
        )

    @pytest.mark.asyncio
    async def test_get_sdwan_health_check(self, sdwan_api, mock_client):
        """Test getting SD-WAN health check details."""
        mock_data = {
            "name": "health1",
            "server": "8.8.8.8",
            "protocol": "ping",
            "interval": 500,
        }
        mock_client.get.return_value = mock_data

        result = await sdwan_api.get_sdwan_health_check("health1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdwan/health-check/health1"
        )

    @pytest.mark.asyncio
    async def test_create_sdwan_health_check_ping(self, sdwan_api, mock_client):
        """Test creating SD-WAN health check with ping."""
        mock_result = {"name": "health1"}
        mock_client.add.return_value = mock_result

        result = await sdwan_api.create_sdwan_health_check(
            name="health1",
            server="8.8.8.8",
            protocol="ping",
            adom="root",
            interval=500,
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][1]["name"] == "health1"
        assert call_args[0][1]["server"] == "8.8.8.8"
        assert call_args[0][1]["protocol"] == "ping"
        assert call_args[0][1]["interval"] == 500

    @pytest.mark.asyncio
    async def test_create_sdwan_health_check_http(self, sdwan_api, mock_client):
        """Test creating SD-WAN health check with HTTP."""
        mock_result = {"name": "health2"}
        mock_client.add.return_value = mock_result

        result = await sdwan_api.create_sdwan_health_check(
            name="health2",
            server="1.1.1.1",
            protocol="http",
            adom="root",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[0][1]["protocol"] == "http"

    @pytest.mark.asyncio
    async def test_delete_sdwan_health_check(self, sdwan_api, mock_client):
        """Test deleting SD-WAN health check."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await sdwan_api.delete_sdwan_health_check("health1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()


class TestSdwanMembers:
    """Test SD-WAN member operations."""

    @pytest.mark.asyncio
    async def test_list_sdwan_members(self, sdwan_api, mock_client):
        """Test listing SD-WAN members."""
        mock_data = [
            {"seq-num": 1, "interface": "wan1", "zone": "virtual-wan-link"},
            {"seq-num": 2, "interface": "wan2", "zone": "virtual-wan-link"},
        ]
        mock_client.get.return_value = mock_data

        result = await sdwan_api.list_sdwan_members(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()


class TestSdwanServices:
    """Test SD-WAN service operations."""

    @pytest.mark.asyncio
    async def test_list_sdwan_services(self, sdwan_api, mock_client):
        """Test listing SD-WAN services."""
        mock_data = [
            {"id": 1, "name": "service1", "mode": "sla"},
            {"id": 2, "name": "service2", "mode": "manual"},
        ]
        mock_client.get.return_value = mock_data

        result = await sdwan_api.list_sdwan_services(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_sdwan_service(self, sdwan_api, mock_client):
        """Test getting SD-WAN service details."""
        mock_data = {
            "id": 1,
            "name": "service1",
            "mode": "sla",
            "dst": ["all"],
        }
        mock_client.get.return_value = mock_data

        result = await sdwan_api.get_sdwan_service(1, adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_sdwan_service(self, sdwan_api, mock_client):
        """Test creating SD-WAN service."""
        mock_result = {"id": 1}
        mock_client.add.return_value = mock_result

        result = await sdwan_api.create_sdwan_service(
            name="service1",
            mode="sla",
            dst=["all"],
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_sdwan_service(self, sdwan_api, mock_client):
        """Test deleting SD-WAN service."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await sdwan_api.delete_sdwan_service(1, adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()
