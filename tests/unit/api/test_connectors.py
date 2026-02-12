"""Unit tests for api.connectors module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.connectors import ConnectorAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.exec = AsyncMock()
    return client


@pytest.fixture
def connector_api(mock_client):
    """Create ConnectorAPI instance with mock client."""
    return ConnectorAPI(mock_client)


class TestConnectorAPIInit:
    """Test ConnectorAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = ConnectorAPI(mock_client)
        assert api.client == mock_client


class TestSDNConnectors:
    """Test SDN connector operations."""

    @pytest.mark.asyncio
    async def test_list_sdn_connectors(self, connector_api, mock_client):
        """Test listing SDN connectors."""
        mock_data = [
            {"name": "aws-connector", "type": "aws", "status": "connected"},
            {"name": "azure-connector", "type": "azure", "status": "connected"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.list_sdn_connectors(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdn-connector"
        )

    @pytest.mark.asyncio
    async def test_list_sdn_connectors_empty(self, connector_api, mock_client):
        """Test listing SDN connectors with empty result."""
        mock_client.get.return_value = []

        result = await connector_api.list_sdn_connectors(adom="custom")

        assert result == []

    @pytest.mark.asyncio
    async def test_list_sdn_connectors_single_item(self, connector_api, mock_client):
        """Test listing SDN connectors with single item result."""
        mock_data = {"name": "aws-connector", "type": "aws"}
        mock_client.get.return_value = mock_data

        result = await connector_api.list_sdn_connectors(adom="root")

        assert result == [mock_data]

    @pytest.mark.asyncio
    async def test_get_sdn_connector(self, connector_api, mock_client):
        """Test getting SDN connector details."""
        mock_data = {
            "name": "aws-connector",
            "type": "aws",
            "access-key": "AKIA...",
            "region": "us-east-1",
        }
        mock_client.get.return_value = mock_data

        result = await connector_api.get_sdn_connector("aws-connector", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/sdn-connector/aws-connector"
        )

    @pytest.mark.asyncio
    async def test_get_sdn_connector_not_found(self, connector_api, mock_client):
        """Test getting non-existent SDN connector."""
        mock_client.get.return_value = None

        result = await connector_api.get_sdn_connector("nonexistent", adom="root")

        assert result == {}

    @pytest.mark.asyncio
    async def test_refresh_sdn_connector(self, connector_api, mock_client):
        """Test refreshing SDN connector."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await connector_api.refresh_sdn_connector("aws-connector", adom="root")

        assert result == mock_result
        mock_client.exec.assert_called_once()
        call_args = mock_client.exec.call_args
        assert "aws-connector" in call_args[0][0]
        assert "refresh" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_sdn_connector_status(self, connector_api, mock_client):
        """Test getting SDN connector status."""
        mock_data = {
            "status": "connected",
            "last-update": "2023-01-01 12:00:00",
        }
        mock_client.get.return_value = mock_data

        result = await connector_api.get_sdn_connector_status("aws-connector", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "status" in call_args[0][0]


class TestCloudConnectors:
    """Test cloud connector operations."""

    @pytest.mark.asyncio
    async def test_list_cloud_connectors(self, connector_api, mock_client):
        """Test listing cloud connectors."""
        mock_data = [
            {"name": "cloud1", "platform": "aws"},
            {"name": "cloud2", "platform": "azure"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.list_cloud_connectors(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/cloud-connector"
        )

    @pytest.mark.asyncio
    async def test_list_cloud_connectors_empty(self, connector_api, mock_client):
        """Test listing cloud connectors with empty result."""
        mock_client.get.return_value = []

        result = await connector_api.list_cloud_connectors(adom="root")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_cloud_connector_services(self, connector_api, mock_client):
        """Test getting cloud connector services."""
        mock_data = [
            {"name": "service1", "type": "firewall"},
            {"name": "service2", "type": "vpn"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.get_cloud_connector_services("cloud1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "cloud1" in call_args[0][0]
        assert "services" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_cloud_connector_services_single_item(self, connector_api, mock_client):
        """Test getting cloud connector services with single item."""
        mock_data = {"name": "service1", "type": "firewall"}
        mock_client.get.return_value = mock_data

        result = await connector_api.get_cloud_connector_services("cloud1", adom="root")

        assert result == [mock_data]


class TestFabricConnectors:
    """Test fabric connector operations."""

    @pytest.mark.asyncio
    async def test_list_fabric_connectors(self, connector_api, mock_client):
        """Test listing fabric connectors."""
        mock_data = [
            {"name": "fabric1", "type": "fortianalyzer"},
            {"name": "fabric2", "type": "fortisandbox"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.list_fabric_connectors(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/fabric-connector"
        )

    @pytest.mark.asyncio
    async def test_list_fabric_connectors_empty(self, connector_api, mock_client):
        """Test listing fabric connectors with empty result."""
        mock_client.get.return_value = []

        result = await connector_api.list_fabric_connectors(adom="root")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_fabric_connector_devices(self, connector_api, mock_client):
        """Test getting fabric connector devices."""
        mock_data = [
            {"name": "device1", "serial": "FG100E1234567890"},
            {"name": "device2", "serial": "FG200E0987654321"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.get_fabric_connector_devices("fabric1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "fabric1" in call_args[0][0]
        assert "devices" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_fabric_connector_devices_single_item(self, connector_api, mock_client):
        """Test getting fabric connector devices with single item."""
        mock_data = {"name": "device1", "serial": "FG100E1234567890"}
        mock_client.get.return_value = mock_data

        result = await connector_api.get_fabric_connector_devices("fabric1", adom="root")

        assert result == [mock_data]


class TestConnectorOperations:
    """Test connector operations."""

    @pytest.mark.asyncio
    async def test_test_connector_connectivity_sdn(self, connector_api, mock_client):
        """Test testing SDN connector connectivity."""
        mock_result = {"status": "success", "message": "Connected"}
        mock_client.exec.return_value = mock_result

        result = await connector_api.test_connector_connectivity(
            connector_name="aws-connector",
            connector_type="sdn",
            adom="root",
        )

        assert result == mock_result
        mock_client.exec.assert_called_once()
        call_args = mock_client.exec.call_args
        assert "sdn-connector" in call_args[0][0]
        assert "test" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_test_connector_connectivity_cloud(self, connector_api, mock_client):
        """Test testing cloud connector connectivity."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await connector_api.test_connector_connectivity(
            connector_name="cloud1",
            connector_type="cloud",
            adom="root",
        )

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert "cloud-connector" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_sync_connector_objects(self, connector_api, mock_client):
        """Test syncing connector objects."""
        mock_result = {"status": "success", "objects": 150}
        mock_client.exec.return_value = mock_result

        result = await connector_api.sync_connector_objects("aws-connector", adom="root")

        assert result == mock_result
        mock_client.exec.assert_called_once()
        call_args = mock_client.exec.call_args
        assert "aws-connector" in call_args[0][0]
        assert "sync" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_connector_route_table(self, connector_api, mock_client):
        """Test getting connector route table."""
        mock_data = [
            {"destination": "10.0.0.0/8", "gateway": "192.168.1.1"},
            {"destination": "172.16.0.0/12", "gateway": "192.168.1.1"},
        ]
        mock_client.get.return_value = mock_data

        result = await connector_api.get_connector_route_table("aws-connector", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "aws-connector" in call_args[0][0]
        assert "route-table" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_connector_route_table_single_item(self, connector_api, mock_client):
        """Test getting connector route table with single item."""
        mock_data = {"destination": "10.0.0.0/8", "gateway": "192.168.1.1"}
        mock_client.get.return_value = mock_data

        result = await connector_api.get_connector_route_table("aws-connector", adom="root")

        assert result == [mock_data]

    @pytest.mark.asyncio
    async def test_get_connector_route_table_empty(self, connector_api, mock_client):
        """Test getting connector route table with empty result."""
        mock_client.get.return_value = []

        result = await connector_api.get_connector_route_table("aws-connector", adom="root")

        assert result == []
