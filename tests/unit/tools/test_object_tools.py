"""Unit tests for tools.object_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.api.models import FirewallAddress, FirewallAddressGroup, FirewallService
from fortimanager_mcp.tools import object_tools


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
def mock_object_api(mock_client):
    """Create mock ObjectAPI instance."""
    with patch('fortimanager_mcp.tools.object_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.list_addresses = AsyncMock()
        api.create_address = AsyncMock()
        api.update_address = AsyncMock()
        api.delete_address = AsyncMock()
        api.list_address_groups = AsyncMock()
        api.create_address_group = AsyncMock()
        api.list_services = AsyncMock()
        api.create_service = AsyncMock()
        api.get_object_metadata = AsyncMock()
        api.set_object_metadata = AsyncMock()
        api.delete_object_metadata = AsyncMock()
        api.assign_metadata_to_objects = AsyncMock()
        api.list_objects_by_metadata = AsyncMock()
        api.get_address_where_used = AsyncMock()
        api.get_service_where_used = AsyncMock()
        api.get_object_dependencies = AsyncMock()
        api.list_zones = AsyncMock()
        api.get_zone = AsyncMock()
        api.create_zone = AsyncMock()
        api.delete_zone = AsyncMock()
        api.list_virtual_ips = AsyncMock()
        api.get_virtual_ip = AsyncMock()
        api.create_virtual_ip = AsyncMock()
        api.delete_virtual_ip = AsyncMock()
        api.list_dynamic_addresses = AsyncMock()
        api.list_fabric_connector_addresses = AsyncMock()
        api.list_address_filters = AsyncMock()
        api.list_interface_addresses = AsyncMock()
        api.list_wildcard_fqdn_addresses = AsyncMock()
        
        with patch('fortimanager_mcp.tools.object_tools.ObjectAPI', return_value=api):
            yield api


class TestListFirewallAddresses:
    """Test list_firewall_addresses tool."""

    @pytest.mark.asyncio
    async def test_list_firewall_addresses_success(self, mock_object_api):
        """Test listing firewall addresses successfully."""
        addr1 = FirewallAddress(
            name="internal_net",
            type="ipmask",
            subnet="10.0.0.0/8",
            comment="Internal network"
        )
        addr2 = FirewallAddress(
            name="dmz_net",
            type="ipmask",
            subnet="172.16.0.0/16",
            comment="DMZ network"
        )
        mock_object_api.list_addresses.return_value = [addr1, addr2]

        result = await object_tools.list_firewall_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["addresses"]) == 2
        assert result["addresses"][0]["name"] == "internal_net"
        assert result["addresses"][1]["name"] == "dmz_net"
        mock_object_api.list_addresses.assert_called_once_with(adom="root", filter=None)

    @pytest.mark.asyncio
    async def test_list_firewall_addresses_with_filter(self, mock_object_api):
        """Test listing firewall addresses with name filter."""
        addr = FirewallAddress(name="internal_subnet", type="ipmask", subnet="10.0.1.0/24")
        mock_object_api.list_addresses.return_value = [addr]

        result = await object_tools.list_firewall_addresses(
            adom="root",
            filter_name="internal"
        )

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_object_api.list_addresses.assert_called_once_with(
            adom="root",
            filter=["name", "like", "internal"]
        )

    @pytest.mark.asyncio
    async def test_list_firewall_addresses_error(self, mock_object_api):
        """Test listing firewall addresses with error."""
        mock_object_api.list_addresses.side_effect = Exception("API Error")

        result = await object_tools.list_firewall_addresses(adom="root")

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestCreateFirewallAddress:
    """Test create_firewall_address tool."""

    @pytest.mark.asyncio
    async def test_create_firewall_address_success(self, mock_object_api):
        """Test creating firewall address successfully."""
        mock_object_api.create_address.return_value = {"name": "new_address"}

        result = await object_tools.create_firewall_address(
            name="new_address",
            subnet="192.168.1.0/24",
            adom="root",
            comment="Test address"
        )

        assert result["status"] == "success"
        assert "address" in result
        mock_object_api.create_address.assert_called_once()
        call_kwargs = mock_object_api.create_address.call_args.kwargs
        assert call_kwargs["name"] == "new_address"
        assert call_kwargs["subnet"] == "192.168.1.0/24"
        assert call_kwargs["adom"] == "root"

    @pytest.mark.asyncio
    async def test_create_firewall_address_error(self, mock_object_api):
        """Test creating firewall address with error."""
        mock_object_api.create_address.side_effect = Exception("Create failed")

        result = await object_tools.create_firewall_address(
            name="new_address",
            subnet="192.168.1.0/24"
        )

        assert result["status"] == "error"
        assert "Create failed" in result["message"]


class TestUpdateFirewallAddress:
    """Test update_firewall_address tool."""

    @pytest.mark.asyncio
    async def test_update_firewall_address_success(self, mock_object_api):
        """Test updating firewall address successfully."""
        mock_object_api.update_address.return_value = {"status": "success"}

        result = await object_tools.update_firewall_address(
            name="existing_address",
            subnet="192.168.2.0/24",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.update_address.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_firewall_address_error(self, mock_object_api):
        """Test updating firewall address with error."""
        mock_object_api.update_address.side_effect = Exception("Update failed")

        result = await object_tools.update_firewall_address(
            name="existing_address",
            subnet="192.168.2.0/24"
        )

        assert result["status"] == "error"
        assert "Update failed" in result["message"]


class TestDeleteFirewallAddress:
    """Test delete_firewall_address tool."""

    @pytest.mark.asyncio
    async def test_delete_firewall_address_success(self, mock_object_api):
        """Test deleting firewall address successfully."""
        mock_object_api.delete_address.return_value = {"status": "success"}

        result = await object_tools.delete_firewall_address(
            name="old_address",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.delete_address.assert_called_once_with(
            name="old_address",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_delete_firewall_address_error(self, mock_object_api):
        """Test deleting firewall address with error."""
        mock_object_api.delete_address.side_effect = Exception("Delete failed")

        result = await object_tools.delete_firewall_address(name="old_address")

        assert result["status"] == "error"
        assert "Delete failed" in result["message"]


class TestListAddressGroups:
    """Test list_address_groups tool."""

    @pytest.mark.asyncio
    async def test_list_address_groups_success(self, mock_object_api):
        """Test listing address groups successfully."""
        group1 = FirewallAddressGroup(
            name="internal_networks",
            member=["net1", "net2"],
            comment="Internal networks group"
        )
        group2 = FirewallAddressGroup(
            name="dmz_networks",
            member=["dmz1"],
            comment="DMZ networks group"
        )
        mock_object_api.list_address_groups.return_value = [group1, group2]

        result = await object_tools.list_address_groups(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["groups"]) == 2
        assert result["groups"][0]["name"] == "internal_networks"
        assert result["groups"][1]["name"] == "dmz_networks"
        mock_object_api.list_address_groups.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_address_groups_error(self, mock_object_api):
        """Test listing address groups with error."""
        mock_object_api.list_address_groups.side_effect = Exception("API Error")

        result = await object_tools.list_address_groups(adom="root")

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestCreateAddressGroup:
    """Test create_address_group tool."""

    @pytest.mark.asyncio
    async def test_create_address_group_success(self, mock_object_api):
        """Test creating address group successfully."""
        mock_object_api.create_address_group.return_value = {"name": "new_group"}

        result = await object_tools.create_address_group(
            name="new_group",
            members=["addr1", "addr2"],
            adom="root",
            comment="Test group"
        )

        assert result["status"] == "success"
        assert "group" in result
        mock_object_api.create_address_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_address_group_error(self, mock_object_api):
        """Test creating address group with error."""
        mock_object_api.create_address_group.side_effect = Exception("Create failed")

        result = await object_tools.create_address_group(
            name="new_group",
            members=["addr1"]
        )

        assert result["status"] == "error"
        assert "Create failed" in result["message"]


class TestListFirewallServices:
    """Test list_firewall_services tool."""

    @pytest.mark.asyncio
    async def test_list_firewall_services_success(self, mock_object_api):
        """Test listing firewall services successfully."""
        svc1 = FirewallService(
            name="HTTP",
            protocol="TCP/UDP/SCTP",
            tcp_portrange="80",
            comment="Web traffic"
        )
        svc2 = FirewallService(
            name="HTTPS",
            protocol="TCP/UDP/SCTP",
            tcp_portrange="443",
            comment="Secure web"
        )
        mock_object_api.list_services.return_value = [svc1, svc2]

        result = await object_tools.list_firewall_services(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["services"]) == 2
        assert result["services"][0]["name"] == "HTTP"
        assert result["services"][1]["name"] == "HTTPS"
        mock_object_api.list_services.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_firewall_services_error(self, mock_object_api):
        """Test listing firewall services with error."""
        mock_object_api.list_services.side_effect = Exception("API Error")

        result = await object_tools.list_firewall_services(adom="root")

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestCreateFirewallService:
    """Test create_firewall_service tool."""

    @pytest.mark.asyncio
    async def test_create_firewall_service_tcp_success(self, mock_object_api):
        """Test creating TCP firewall service successfully."""
        mock_object_api.create_service.return_value = {"name": "custom_tcp"}

        result = await object_tools.create_firewall_service(
            name="custom_tcp",
            protocol="tcp",
            tcp_port_range="8080-8090",
            adom="root",
            comment="Custom TCP service"
        )

        assert result["status"] == "success"
        assert "service" in result
        mock_object_api.create_service.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_firewall_service_udp_success(self, mock_object_api):
        """Test creating UDP firewall service successfully."""
        mock_object_api.create_service.return_value = {"name": "custom_udp"}

        result = await object_tools.create_firewall_service(
            name="custom_udp",
            protocol="udp",
            udp_port_range="5000",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.create_service.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_firewall_service_error(self, mock_object_api):
        """Test creating firewall service with error."""
        mock_object_api.create_service.side_effect = Exception("Create failed")

        result = await object_tools.create_firewall_service(
            name="custom_svc",
            protocol="tcp",
            tcp_port_range="9000"
        )

        assert result["status"] == "error"
        assert "Create failed" in result["message"]


class TestObjectMetadata:
    """Test object metadata tools."""

    @pytest.mark.asyncio
    async def test_get_object_metadata_success(self, mock_object_api):
        """Test getting object metadata successfully."""
        mock_object_api.get_object_metadata.return_value = {
            "field1": "value1",
            "field2": "value2"
        }

        result = await object_tools.get_object_metadata(
            object_type="firewall.address",
            object_name="test_addr",
            adom="root"
        )

        assert result["status"] == "success"
        assert "metadata" in result
        mock_object_api.get_object_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_object_metadata_success(self, mock_object_api):
        """Test setting object metadata successfully."""
        mock_object_api.set_object_metadata.return_value = {"status": "success"}

        result = await object_tools.set_object_metadata(
            object_type="firewall.address",
            object_name="test_addr",
            metadata={"owner": "admin"},
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.set_object_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_object_metadata_success(self, mock_object_api):
        """Test deleting object metadata successfully."""
        mock_object_api.delete_object_metadata.return_value = {"status": "success"}

        result = await object_tools.delete_object_metadata(
            object_type="firewall.address",
            object_name="test_addr",
            field_name="owner",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.delete_object_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_metadata_to_objects_success(self, mock_object_api):
        """Test assigning metadata to multiple objects successfully."""
        mock_object_api.assign_metadata_to_objects.return_value = {"status": "success"}

        result = await object_tools.assign_metadata_to_objects(
            object_type="firewall.address",
            object_names=["addr1", "addr2"],
            metadata={"owner": "admin"},
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.assign_metadata_to_objects.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_objects_by_metadata_success(self, mock_object_api):
        """Test listing objects by metadata successfully."""
        mock_object_api.list_objects_by_metadata.return_value = [
            {"name": "addr1"},
            {"name": "addr2"}
        ]

        result = await object_tools.list_objects_by_metadata(
            object_type="firewall.address",
            metadata_filter={"owner": "admin"},
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_object_api.list_objects_by_metadata.assert_called_once()


class TestObjectDependencies:
    """Test object dependency tools."""

    @pytest.mark.asyncio
    async def test_get_address_where_used_success(self, mock_object_api):
        """Test getting address where-used information successfully."""
        mock_object_api.get_address_where_used.return_value = {
            "policies": ["policy1", "policy2"],
            "address_groups": ["group1"]
        }

        result = await object_tools.get_address_where_used(
            address_name="test_addr",
            adom="root"
        )

        assert result["status"] == "success"
        assert "usage" in result
        mock_object_api.get_address_where_used.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_service_where_used_success(self, mock_object_api):
        """Test getting service where-used information successfully."""
        mock_object_api.get_service_where_used.return_value = {
            "policies": ["policy1"]
        }

        result = await object_tools.get_service_where_used(
            service_name="HTTP",
            adom="root"
        )

        assert result["status"] == "success"
        assert "usage" in result
        mock_object_api.get_service_where_used.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_object_dependencies_success(self, mock_object_api):
        """Test getting object dependencies successfully."""
        mock_object_api.get_object_dependencies.return_value = {
            "depends_on": ["addr1", "addr2"],
            "used_by": ["policy1"]
        }

        result = await object_tools.get_object_dependencies(
            object_type="firewall.addrgrp",
            object_name="test_group",
            adom="root"
        )

        assert result["status"] == "success"
        assert "dependencies" in result
        mock_object_api.get_object_dependencies.assert_called_once()


class TestFirewallZones:
    """Test firewall zone tools."""

    @pytest.mark.asyncio
    async def test_list_firewall_zones_success(self, mock_object_api):
        """Test listing firewall zones successfully."""
        mock_object_api.list_zones.return_value = [
            {"name": "zone1", "interface": ["port1"]},
            {"name": "zone2", "interface": ["port2"]}
        ]

        result = await object_tools.list_firewall_zones(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_object_api.list_zones.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_firewall_zone_success(self, mock_object_api):
        """Test getting firewall zone successfully."""
        mock_object_api.get_zone.return_value = {
            "name": "dmz_zone",
            "interface": ["port1", "port2"]
        }

        result = await object_tools.get_firewall_zone(
            zone_name="dmz_zone",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["zone"]["name"] == "dmz_zone"
        mock_object_api.get_zone.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_firewall_zone_success(self, mock_object_api):
        """Test creating firewall zone successfully."""
        mock_object_api.create_zone.return_value = {"name": "new_zone"}

        result = await object_tools.create_firewall_zone(
            name="new_zone",
            interfaces=["port1"],
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.create_zone.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_firewall_zone_success(self, mock_object_api):
        """Test deleting firewall zone successfully."""
        mock_object_api.delete_zone.return_value = {"status": "success"}

        result = await object_tools.delete_firewall_zone(
            zone_name="old_zone",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.delete_zone.assert_called_once()


class TestVirtualIps:
    """Test virtual IP tools."""

    @pytest.mark.asyncio
    async def test_list_virtual_ips_success(self, mock_object_api):
        """Test listing virtual IPs successfully."""
        mock_object_api.list_virtual_ips.return_value = [
            {"name": "vip1", "extip": "1.2.3.4"},
            {"name": "vip2", "extip": "5.6.7.8"}
        ]

        result = await object_tools.list_virtual_ips(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_object_api.list_virtual_ips.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_virtual_ip_success(self, mock_object_api):
        """Test getting virtual IP successfully."""
        mock_object_api.get_virtual_ip.return_value = {
            "name": "vip1",
            "extip": "1.2.3.4",
            "mappedip": ["10.0.0.1"]
        }

        result = await object_tools.get_virtual_ip(
            vip_name="vip1",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["vip"]["name"] == "vip1"
        mock_object_api.get_virtual_ip.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_virtual_ip_success(self, mock_object_api):
        """Test creating virtual IP successfully."""
        mock_object_api.create_virtual_ip.return_value = {"name": "new_vip"}

        result = await object_tools.create_virtual_ip(
            name="new_vip",
            external_ip="1.2.3.4",
            mapped_ip="10.0.0.1",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.create_virtual_ip.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_virtual_ip_success(self, mock_object_api):
        """Test deleting virtual IP successfully."""
        mock_object_api.delete_virtual_ip.return_value = {"status": "success"}

        result = await object_tools.delete_virtual_ip(
            vip_name="old_vip",
            adom="root"
        )

        assert result["status"] == "success"
        mock_object_api.delete_virtual_ip.assert_called_once()


class TestDynamicAddresses:
    """Test dynamic address tools."""

    @pytest.mark.asyncio
    async def test_list_dynamic_firewall_addresses_success(self, mock_object_api):
        """Test listing dynamic firewall addresses successfully."""
        mock_object_api.list_dynamic_addresses.return_value = [
            {"name": "dyn1"},
            {"name": "dyn2"}
        ]

        result = await object_tools.list_dynamic_firewall_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_object_api.list_dynamic_addresses.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_fabric_connector_addresses_success(self, mock_object_api):
        """Test listing fabric connector addresses successfully."""
        mock_object_api.list_fabric_connector_addresses.return_value = [
            {"name": "fabric1"}
        ]

        result = await object_tools.list_fabric_connector_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_object_api.list_fabric_connector_addresses.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_address_filters_success(self, mock_object_api):
        """Test listing address filters successfully."""
        mock_object_api.list_address_filters.return_value = [
            {"name": "filter1"}
        ]

        result = await object_tools.list_address_filters(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_object_api.list_address_filters.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_interface_addresses_success(self, mock_object_api):
        """Test listing interface addresses successfully."""
        mock_object_api.list_interface_addresses.return_value = [
            {"name": "intf1"}
        ]

        result = await object_tools.list_interface_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_object_api.list_interface_addresses.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_wildcard_fqdn_addresses_success(self, mock_object_api):
        """Test listing wildcard FQDN addresses successfully."""
        mock_object_api.list_wildcard_fqdn_addresses.return_value = [
            {"name": "wildcard1"}
        ]

        result = await object_tools.list_wildcard_fqdn_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_object_api.list_wildcard_fqdn_addresses.assert_called_once_with(adom="root")


class TestGetObjectApiError:
    """Test _get_object_api error handling."""

    @pytest.mark.asyncio
    async def test_get_object_api_no_client(self):
        """Test _get_object_api with no client."""
        with patch('fortimanager_mcp.tools.object_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                object_tools._get_object_api()
