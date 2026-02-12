"""Unit tests for api.subfetch module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.subfetch import SubFetchAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    return client


@pytest.fixture
def subfetch_api(mock_client):
    """Create SubFetchAPI instance with mock client."""
    return SubFetchAPI(mock_client)


class TestSubFetchAPIInit:
    """Test SubFetchAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = SubFetchAPI(mock_client)
        assert api.client == mock_client


class TestFetchSubObjects:
    """Test fetch sub-objects operations."""

    @pytest.mark.asyncio
    async def test_fetch_sub_objects(self, subfetch_api, mock_client):
        """Test fetching sub-objects from parent object."""
        mock_data = [
            {"name": "sub1", "value": "value1"},
            {"name": "sub2", "value": "value2"},
        ]
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_sub_objects(
            object_path="firewall/policy/1",
            sub_object_type="rtp-nat",
            adom="root",
        )

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "firewall/policy/1" in call_args[0][0]
        assert "rtp-nat" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_fetch_sub_objects_with_filters(self, subfetch_api, mock_client):
        """Test fetching sub-objects with filters."""
        mock_data = [{"name": "sub1"}]
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_sub_objects(
            object_path="firewall/policy/1",
            sub_object_type="application-list",
            adom="root",
            filters={"status": "enable"},
        )

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[1]["status"] == "enable"

    @pytest.mark.asyncio
    async def test_fetch_sub_objects_empty(self, subfetch_api, mock_client):
        """Test fetching sub-objects with empty result."""
        mock_client.get.return_value = []

        result = await subfetch_api.fetch_sub_objects(
            object_path="firewall/policy/1",
            sub_object_type="service",
            adom="root",
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_sub_objects_single_item(self, subfetch_api, mock_client):
        """Test fetching sub-objects with single item result."""
        mock_data = {"name": "sub1", "value": "value1"}
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_sub_objects(
            object_path="firewall/policy/1",
            sub_object_type="dstaddr",
            adom="root",
        )

        assert result == [mock_data]


class TestFetchNestedConfiguration:
    """Test fetch nested configuration operations."""

    @pytest.mark.asyncio
    async def test_fetch_nested_configuration_depth_1(self, subfetch_api, mock_client):
        """Test fetching nested configuration with depth 1."""
        mock_data = {
            "name": "policy1",
            "action": "accept",
            "srcaddr": [{"name": "addr1"}],
        }
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_nested_configuration(
            config_path="firewall/policy/1",
            depth=1,
            adom="root",
        )

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert call_args[1]["fetch-sub"] == 1

    @pytest.mark.asyncio
    async def test_fetch_nested_configuration_depth_3(self, subfetch_api, mock_client):
        """Test fetching nested configuration with depth 3."""
        mock_data = {
            "name": "policy1",
            "action": "accept",
            "srcaddr": [
                {
                    "name": "addrgrp1",
                    "member": [{"name": "addr1"}],
                }
            ],
        }
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_nested_configuration(
            config_path="firewall/policy/1",
            depth=3,
            adom="root",
        )

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert call_args[1]["fetch-sub"] == 3

    @pytest.mark.asyncio
    async def test_fetch_nested_configuration_empty(self, subfetch_api, mock_client):
        """Test fetching nested configuration with empty result."""
        mock_client.get.return_value = None

        result = await subfetch_api.fetch_nested_configuration(
            config_path="firewall/policy/999",
            depth=1,
            adom="root",
        )

        assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_nested_configuration_non_dict(self, subfetch_api, mock_client):
        """Test fetching nested configuration with non-dict result."""
        mock_client.get.return_value = []

        result = await subfetch_api.fetch_nested_configuration(
            config_path="firewall/policy/1",
            depth=1,
            adom="root",
        )

        assert result == {}


class TestFetchObjectMembers:
    """Test fetch object members operations."""

    @pytest.mark.asyncio
    async def test_fetch_object_members_address_group(self, subfetch_api, mock_client):
        """Test fetching address group members."""
        mock_data = [
            {"name": "addr1"},
            {"name": "addr2"},
            {"name": "addr3"},
        ]
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_object_members(
            object_type="firewall/addrgrp",
            object_name="group1",
            adom="root",
        )

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "firewall/addrgrp" in call_args[0][0]
        assert "group1" in call_args[0][0]
        assert "member" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_fetch_object_members_service_group(self, subfetch_api, mock_client):
        """Test fetching service group members."""
        mock_data = [
            {"name": "HTTP"},
            {"name": "HTTPS"},
        ]
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_object_members(
            object_type="firewall/service/group",
            object_name="web-services",
            adom="root",
        )

        assert result == mock_data

    @pytest.mark.asyncio
    async def test_fetch_object_members_empty(self, subfetch_api, mock_client):
        """Test fetching object members with empty result."""
        mock_client.get.return_value = []

        result = await subfetch_api.fetch_object_members(
            object_type="firewall/addrgrp",
            object_name="empty-group",
            adom="root",
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_object_members_single_item(self, subfetch_api, mock_client):
        """Test fetching object members with single item result."""
        mock_data = {"name": "addr1"}
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_object_members(
            object_type="firewall/addrgrp",
            object_name="single-member-group",
            adom="root",
        )

        assert result == [mock_data]


class TestComplexSubFetch:
    """Test complex sub-fetch scenarios."""

    @pytest.mark.asyncio
    async def test_fetch_policy_with_nested_groups(self, subfetch_api, mock_client):
        """Test fetching policy with nested address groups."""
        mock_data = {
            "name": "policy1",
            "srcaddr": [
                {"name": "group1", "type": "group"},
                {"name": "addr1", "type": "ipmask"},
            ],
        }
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_nested_configuration(
            config_path="firewall/policy/1",
            depth=2,
            adom="root",
        )

        assert result == mock_data
        assert len(result["srcaddr"]) == 2

    @pytest.mark.asyncio
    async def test_fetch_with_custom_adom(self, subfetch_api, mock_client):
        """Test fetching with custom ADOM."""
        mock_data = [{"name": "sub1"}]
        mock_client.get.return_value = mock_data

        result = await subfetch_api.fetch_sub_objects(
            object_path="firewall/policy/1",
            sub_object_type="service",
            adom="custom-adom",
        )

        assert result == mock_data
        call_args = mock_client.get.call_args
        assert "custom-adom" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_fetch_members_different_object_types(self, subfetch_api, mock_client):
        """Test fetching members from different object types."""
        mock_data = [{"name": "member1"}]
        mock_client.get.return_value = mock_data

        # Test with different object types
        for object_type in ["firewall/addrgrp", "firewall/service/group", "user/group"]:
            result = await subfetch_api.fetch_object_members(
                object_type=object_type,
                object_name="test-group",
                adom="root",
            )
            assert result == mock_data
