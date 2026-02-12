"""Unit tests for api.objects module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.api.objects import ObjectAPI
from fortimanager_mcp.api.models import (
    FirewallAddress,
    FirewallAddressGroup,
    FirewallService,
)
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
    return client


@pytest.fixture
def object_api(mock_client):
    """Create ObjectAPI instance with mock client."""
    return ObjectAPI(mock_client)


class TestObjectAPIInit:
    """Test ObjectAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = ObjectAPI(mock_client)
        assert api.client == mock_client


class TestFirewallAddressOperations:
    """Test firewall address operations."""

    @pytest.mark.asyncio
    async def test_list_addresses_success(self, object_api, mock_client):
        """Test listing addresses successfully."""
        mock_data = [
            {
                "name": "addr1",
                "type": "ipmask",
                "subnet": ["192.168.1.0", "255.255.255.0"],
                "comment": "Test address 1",
            },
            {
                "name": "addr2",
                "type": "ipmask",
                "subnet": ["10.0.0.0", "255.0.0.0"],
            },
        ]
        mock_client.get.return_value = mock_data

        result = await object_api.list_addresses(adom="root")

        assert len(result) == 2
        assert all(isinstance(addr, FirewallAddress) for addr in result)
        assert result[0].name == "addr1"
        assert result[1].name == "addr2"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_addresses_with_fields(self, object_api, mock_client):
        """Test listing addresses with specific fields."""
        mock_data = [{"name": "addr1"}]
        mock_client.get.return_value = mock_data

        await object_api.list_addresses(adom="test", fields=["name", "subnet"])

        mock_client.get.assert_called_once_with(
            "/pm/config/adom/test/obj/firewall/address",
            fields=["name", "subnet"],
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_addresses_with_filter(self, object_api, mock_client):
        """Test listing addresses with filter."""
        mock_data = [{"name": "addr1"}]
        mock_client.get.return_value = mock_data
        filter_criteria = ["name", "==", "addr1"]

        await object_api.list_addresses(filter=filter_criteria)

        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address",
            fields=None,
            filter=filter_criteria,
        )

    @pytest.mark.asyncio
    async def test_list_addresses_empty(self, object_api, mock_client):
        """Test listing addresses returns empty list."""
        mock_client.get.return_value = []

        result = await object_api.list_addresses()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_addresses_single_dict(self, object_api, mock_client):
        """Test listing addresses when single dict returned."""
        mock_data = {"name": "addr1", "type": "ipmask"}
        mock_client.get.return_value = mock_data

        result = await object_api.list_addresses()

        assert len(result) == 1
        assert isinstance(result[0], FirewallAddress)
        assert result[0].name == "addr1"

    @pytest.mark.asyncio
    async def test_list_addresses_none(self, object_api, mock_client):
        """Test listing addresses when None returned."""
        mock_client.get.return_value = None

        result = await object_api.list_addresses()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_address_success(self, object_api, mock_client):
        """Test getting specific address."""
        mock_data = {
            "name": "addr1",
            "type": "ipmask",
            "subnet": ["192.168.1.0", "255.255.255.0"],
            "comment": "Test address",
        }
        mock_client.get.return_value = mock_data

        result = await object_api.get_address("addr1", adom="root")

        assert isinstance(result, FirewallAddress)
        assert result.name == "addr1"
        assert result.comment == "Test address"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address/addr1"
        )

    @pytest.mark.asyncio
    async def test_get_address_different_adom(self, object_api, mock_client):
        """Test getting address from different ADOM."""
        mock_data = {"name": "addr1"}
        mock_client.get.return_value = mock_data

        await object_api.get_address("addr1", adom="test_adom")

        mock_client.get.assert_called_once_with(
            "/pm/config/adom/test_adom/obj/firewall/address/addr1"
        )

    @pytest.mark.asyncio
    async def test_create_address_with_cidr(self, object_api, mock_client):
        """Test creating address with CIDR notation."""
        mock_data = {
            "name": "new_addr",
            "type": "ipmask",
            "subnet": ["192.168.1.0", "255.255.255.0"],
        }
        mock_client.get.return_value = mock_data

        result = await object_api.create_address(
            name="new_addr",
            subnet="192.168.1.0/24",
            adom="root",
        )

        assert isinstance(result, FirewallAddress)
        assert result.name == "new_addr"

        # Verify add was called with correct data
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/address"
        data = call_args[1]["data"]
        assert data["name"] == "new_addr"
        assert data["type"] == "ipmask"
        assert data["subnet"] == ["192.168.1.0", "255.255.255.0"]

    @pytest.mark.asyncio
    async def test_create_address_with_comment(self, object_api, mock_client):
        """Test creating address with comment."""
        mock_data = {"name": "new_addr"}
        mock_client.get.return_value = mock_data

        await object_api.create_address(
            name="new_addr",
            subnet="10.0.0.0/8",
            comment="Test comment",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["comment"] == "Test comment"

    @pytest.mark.asyncio
    async def test_create_address_with_kwargs(self, object_api, mock_client):
        """Test creating address with additional kwargs."""
        mock_data = {"name": "new_addr"}
        mock_client.get.return_value = mock_data

        await object_api.create_address(
            name="new_addr",
            subnet="10.0.0.0/8",
            visibility="enable",
            color=5,
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["visibility"] == "enable"
        assert data["color"] == 5

    @pytest.mark.asyncio
    async def test_create_address_various_cidr(self, object_api, mock_client):
        """Test creating addresses with various CIDR notations."""
        test_cases = [
            ("192.168.1.0/32", ["192.168.1.0", "255.255.255.255"]),
            ("10.0.0.0/8", ["10.0.0.0", "255.0.0.0"]),
            ("172.16.0.0/16", ["172.16.0.0", "255.255.0.0"]),
            ("192.168.100.0/22", ["192.168.100.0", "255.255.252.0"]),
        ]

        for subnet, expected in test_cases:
            mock_client.get.return_value = {"name": "test"}
            mock_client.add.reset_mock()

            await object_api.create_address(name="test", subnet=subnet)

            call_args = mock_client.add.call_args
            data = call_args[1]["data"]
            assert data["subnet"] == expected

    @pytest.mark.asyncio
    async def test_update_address_success(self, object_api, mock_client):
        """Test updating address."""
        mock_data = {"name": "addr1", "comment": "Updated comment"}
        mock_client.get.return_value = mock_data

        result = await object_api.update_address(
            name="addr1",
            adom="root",
            comment="Updated comment",
        )

        assert isinstance(result, FirewallAddress)
        assert result.name == "addr1"
        mock_client.set.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address/addr1",
            data={"comment": "Updated comment"},
        )

    @pytest.mark.asyncio
    async def test_update_address_multiple_fields(self, object_api, mock_client):
        """Test updating multiple address fields."""
        mock_data = {"name": "addr1"}
        mock_client.get.return_value = mock_data

        await object_api.update_address(
            name="addr1",
            comment="New comment",
            color=3,
            visibility="disable",
        )

        call_args = mock_client.set.call_args
        data = call_args[1]["data"]
        assert data["comment"] == "New comment"
        assert data["color"] == 3
        assert data["visibility"] == "disable"

    @pytest.mark.asyncio
    async def test_delete_address_success(self, object_api, mock_client):
        """Test deleting address."""
        await object_api.delete_address("addr1", adom="root")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address/addr1"
        )

    @pytest.mark.asyncio
    async def test_delete_address_different_adom(self, object_api, mock_client):
        """Test deleting address from different ADOM."""
        await object_api.delete_address("addr1", adom="test_adom")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/test_adom/obj/firewall/address/addr1"
        )


class TestFirewallAddressGroupOperations:
    """Test firewall address group operations."""

    @pytest.mark.asyncio
    async def test_list_address_groups_success(self, object_api, mock_client):
        """Test listing address groups."""
        mock_data = [
            {"name": "group1", "member": ["addr1", "addr2"]},
            {"name": "group2", "member": ["addr3"]},
        ]
        mock_client.get.return_value = mock_data

        result = await object_api.list_address_groups(adom="root")

        assert len(result) == 2
        assert all(isinstance(grp, FirewallAddressGroup) for grp in result)
        assert result[0].name == "group1"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/addrgrp",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_address_groups_empty(self, object_api, mock_client):
        """Test listing address groups returns empty list."""
        mock_client.get.return_value = []

        result = await object_api.list_address_groups()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_address_groups_single_dict(self, object_api, mock_client):
        """Test listing address groups when single dict returned."""
        mock_data = {"name": "group1", "member": ["addr1"]}
        mock_client.get.return_value = mock_data

        result = await object_api.list_address_groups()

        assert len(result) == 1
        assert isinstance(result[0], FirewallAddressGroup)

    @pytest.mark.asyncio
    async def test_create_address_group_success(self, object_api, mock_client):
        """Test creating address group."""
        mock_data = {"name": "new_group", "member": ["addr1", "addr2"]}
        mock_client.get.return_value = mock_data

        result = await object_api.create_address_group(
            name="new_group",
            members=["addr1", "addr2"],
            adom="root",
        )

        assert isinstance(result, FirewallAddressGroup)
        assert result.name == "new_group"

        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/addrgrp"
        data = call_args[1]["data"]
        assert data["name"] == "new_group"
        assert data["member"] == ["addr1", "addr2"]

    @pytest.mark.asyncio
    async def test_create_address_group_with_comment(self, object_api, mock_client):
        """Test creating address group with comment."""
        mock_data = {"name": "new_group"}
        mock_client.get.return_value = mock_data

        await object_api.create_address_group(
            name="new_group",
            members=["addr1"],
            comment="Test group",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["comment"] == "Test group"

    @pytest.mark.asyncio
    async def test_create_address_group_with_kwargs(self, object_api, mock_client):
        """Test creating address group with kwargs."""
        mock_data = {"name": "new_group"}
        mock_client.get.return_value = mock_data

        await object_api.create_address_group(
            name="new_group",
            members=["addr1"],
            color=2,
            visibility="enable",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["color"] == 2
        assert data["visibility"] == "enable"

    @pytest.mark.asyncio
    async def test_get_address_group_success(self, object_api, mock_client):
        """Test getting address group."""
        mock_data = {
            "name": "group1",
            "member": ["addr1", "addr2"],
            "comment": "Test group",
        }
        mock_client.get.return_value = mock_data

        result = await object_api.get_address_group("group1", adom="root")

        assert isinstance(result, FirewallAddressGroup)
        assert result.name == "group1"
        assert result.comment == "Test group"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/addrgrp/group1"
        )

    @pytest.mark.asyncio
    async def test_delete_address_group_success(self, object_api, mock_client):
        """Test deleting address group."""
        await object_api.delete_address_group("group1", adom="root")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/addrgrp/group1"
        )


class TestFirewallServiceOperations:
    """Test firewall service operations."""

    @pytest.mark.asyncio
    async def test_list_services_success(self, object_api, mock_client):
        """Test listing services."""
        mock_data = [
            {"name": "service1", "protocol": "TCP/UDP/SCTP", "tcp_portrange": "80"},
            {"name": "service2", "protocol": "TCP/UDP/SCTP", "tcp_portrange": "443"},
        ]
        mock_client.get.return_value = mock_data

        result = await object_api.list_services(adom="root")

        assert len(result) == 2
        assert all(isinstance(svc, FirewallService) for svc in result)
        assert result[0].name == "service1"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/service/custom",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_services_empty(self, object_api, mock_client):
        """Test listing services returns empty list."""
        mock_client.get.return_value = []

        result = await object_api.list_services()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_services_single_dict(self, object_api, mock_client):
        """Test listing services when single dict returned."""
        mock_data = {"name": "service1", "protocol": "TCP/UDP/SCTP"}
        mock_client.get.return_value = mock_data

        result = await object_api.list_services()

        assert len(result) == 1
        assert isinstance(result[0], FirewallService)

    @pytest.mark.asyncio
    async def test_create_service_tcp(self, object_api, mock_client):
        """Test creating TCP service."""
        mock_data = {
            "name": "custom_tcp",
            "protocol": "TCP",
            "tcp_portrange": "8080",
        }
        mock_client.get.return_value = mock_data

        result = await object_api.create_service(
            name="custom_tcp",
            protocol="TCP",
            port_range="8080",
            adom="root",
        )

        assert isinstance(result, FirewallService)
        assert result.name == "custom_tcp"

        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/service/custom"
        data = call_args[1]["data"]
        assert data["name"] == "custom_tcp"
        assert data["protocol"] == "TCP"
        assert data["tcp-portrange"] == "8080"

    @pytest.mark.asyncio
    async def test_create_service_udp(self, object_api, mock_client):
        """Test creating UDP service."""
        mock_data = {"name": "custom_udp"}
        mock_client.get.return_value = mock_data

        await object_api.create_service(
            name="custom_udp",
            protocol="UDP",
            port_range="53",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert "udp-portrange" in data
        assert data["udp-portrange"] == "53"

    @pytest.mark.asyncio
    async def test_create_service_with_comment(self, object_api, mock_client):
        """Test creating service with comment."""
        mock_data = {"name": "custom_svc"}
        mock_client.get.return_value = mock_data

        await object_api.create_service(
            name="custom_svc",
            protocol="TCP",
            port_range="9000",
            comment="Custom service",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["comment"] == "Custom service"

    @pytest.mark.asyncio
    async def test_create_service_with_kwargs(self, object_api, mock_client):
        """Test creating service with additional kwargs."""
        mock_data = {"name": "custom_svc"}
        mock_client.get.return_value = mock_data

        await object_api.create_service(
            name="custom_svc",
            protocol="TCP",
            port_range="8000-9000",
            visibility="enable",
            color=4,
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["visibility"] == "enable"
        assert data["color"] == 4

    @pytest.mark.asyncio
    async def test_get_service_success(self, object_api, mock_client):
        """Test getting service."""
        mock_data = {
            "name": "service1",
            "protocol": "TCP/UDP/SCTP",
            "tcp_portrange": "80",
            "comment": "HTTP service",
        }
        mock_client.get.return_value = mock_data

        result = await object_api.get_service("service1", adom="root")

        assert isinstance(result, FirewallService)
        assert result.name == "service1"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/service/custom/service1"
        )

    @pytest.mark.asyncio
    async def test_delete_service_success(self, object_api, mock_client):
        """Test deleting service."""
        await object_api.delete_service("service1", adom="root")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/service/custom/service1"
        )


class TestMetadataOperations:
    """Test object metadata operations."""

    @pytest.mark.asyncio
    async def test_get_object_metadata_success(self, object_api, mock_client):
        """Test getting object metadata."""
        mock_data = {"_meta_fields": {"field1": "value1", "field2": "value2"}}
        mock_client.get.return_value = mock_data

        result = await object_api.get_object_metadata(
            object_type="firewall/address",
            object_name="addr1",
            adom="root",
        )

        assert result == {"field1": "value1", "field2": "value2"}
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/address/addr1"
        assert call_args[1]["fields"] == ["_meta_fields"]

    @pytest.mark.asyncio
    async def test_set_object_metadata_success(self, object_api, mock_client):
        """Test setting object metadata."""
        metadata = {"priority": "high", "owner": "admin"}

        await object_api.set_object_metadata(
            object_type="firewall/address",
            object_name="addr1",
            metadata=metadata,
            adom="root",
        )

        mock_client.set.assert_called_once_with(
            "/pm/config/adom/root/obj/firewall/address/addr1",
            data={"_meta_fields": metadata},
        )

    @pytest.mark.asyncio
    async def test_delete_object_metadata_success(self, object_api, mock_client):
        """Test deleting object metadata."""
        # Mock getting current metadata
        mock_client.get.return_value = {
            "_meta_fields": {"priority": "high", "owner": "admin"}
        }

        await object_api.delete_object_metadata(
            object_type="firewall/address",
            object_name="addr1",
            metadata_key="priority",
            adom="root",
        )

        # Should get current metadata, then set updated metadata
        assert mock_client.get.called
        assert mock_client.set.called
        call_args = mock_client.set.call_args
        data = call_args[1]["data"]
        # Should only have 'owner' left
        assert "_meta_fields" in data
        assert "priority" not in data["_meta_fields"]
        assert "owner" in data["_meta_fields"]

    @pytest.mark.asyncio
    async def test_assign_object_metadata_success(self, object_api, mock_client):
        """Test assigning metadata to multiple objects."""
        # Mock getting current metadata for each object
        mock_client.get.return_value = {"_meta_fields": {}}

        await object_api.assign_object_metadata(
            object_type="firewall/address",
            object_names=["addr1", "addr2"],
            metadata_key="category",
            metadata_value="servers",
            adom="root",
        )

        # Should get and set metadata for each object
        assert mock_client.get.call_count == 2
        assert mock_client.set.call_count == 2
        
        # Verify the metadata was set correctly
        call_args = mock_client.set.call_args
        data = call_args[1]["data"]
        assert data["_meta_fields"]["category"] == "servers"

    @pytest.mark.asyncio
    async def test_list_objects_by_metadata_success(self, object_api, mock_client):
        """Test listing objects by metadata."""
        mock_data = [
            {"name": "addr1", "_meta_fields": {"priority": "high"}},
            {"name": "addr2", "_meta_fields": {"priority": "high"}},
            {"name": "addr3", "_meta_fields": {"priority": "low"}},
        ]
        mock_client.get.return_value = mock_data

        result = await object_api.list_objects_by_metadata(
            object_type="firewall/address",
            metadata_key="priority",
            metadata_value="high",
            adom="root",
        )

        assert len(result) == 2
        assert result[0]["name"] == "addr1"
        assert result[1]["name"] == "addr2"
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/firewall/address"


class TestWhereUsedOperations:
    """Test where-used operations."""

    @pytest.mark.asyncio
    async def test_get_address_where_used_success(self, object_api, mock_client):
        """Test getting address where-used."""
        mock_data = {
            "policies": [{"name": "policy1"}],
            "groups": [{"name": "group1"}],
        }
        mock_client.execute.return_value = mock_data

        result = await object_api.get_address_where_used(
            address_name="addr1",
            adom="root",
        )

        assert result == mock_data
        call_args = mock_client.execute.call_args
        assert "where-used" in call_args[0][0]
        data = call_args[1]["data"]
        assert data["mkey"] == "addr1"

    @pytest.mark.asyncio
    async def test_get_service_where_used_success(self, object_api, mock_client):
        """Test getting service where-used."""
        mock_data = {"policies": [{"name": "policy1"}]}
        mock_client.execute.return_value = mock_data

        result = await object_api.get_service_where_used(
            service_name="service1",
            adom="root",
        )

        assert result == mock_data
        call_args = mock_client.execute.call_args
        assert "where-used" in call_args[0][0]
        data = call_args[1]["data"]
        assert data["mkey"] == "service1"


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_create_address_non_cidr_subnet(self, object_api, mock_client):
        """Test creating address with non-CIDR subnet (raw value)."""
        mock_data = {"name": "addr1"}
        mock_client.get.return_value = mock_data

        # If subnet doesn't contain '/', it should be passed as-is
        await object_api.create_address(
            name="addr1",
            subnet=["192.168.1.0", "255.255.255.0"],
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        # Should be passed as provided
        assert data["subnet"] == ["192.168.1.0", "255.255.255.0"]

    @pytest.mark.asyncio
    async def test_api_error_handling(self, object_api, mock_client):
        """Test that API errors are propagated."""
        mock_client.get.side_effect = APIError("API call failed")

        with pytest.raises(APIError):
            await object_api.list_addresses()

    @pytest.mark.asyncio
    async def test_resource_not_found_handling(self, object_api, mock_client):
        """Test that ResourceNotFoundError is propagated."""
        mock_client.get.side_effect = ResourceNotFoundError("Address not found")

        with pytest.raises(ResourceNotFoundError):
            await object_api.get_address("nonexistent")

    @pytest.mark.asyncio
    async def test_list_with_none_filter(self, object_api, mock_client):
        """Test listing with None filter."""
        mock_client.get.return_value = []

        await object_api.list_addresses(filter=None)

        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert call_args[1]["filter"] is None

    @pytest.mark.asyncio
    async def test_different_adom_throughout(self, object_api, mock_client):
        """Test operations with different ADOM values."""
        test_adoms = ["root", "test", "production", "staging"]

        for adom in test_adoms:
            mock_client.get.return_value = []
            mock_client.get.reset_mock()

            await object_api.list_addresses(adom=adom)

            call_args = mock_client.get.call_args
            assert f"/adom/{adom}/" in call_args[0][0]
