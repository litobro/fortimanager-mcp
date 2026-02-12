"""Unit tests for api.metafields module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.metafields import MetaFieldsAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    return client


@pytest.fixture
def metafields_api(mock_client):
    """Create MetaFieldsAPI instance with mock client."""
    return MetaFieldsAPI(mock_client)


class TestMetaFieldsAPIInit:
    """Test MetaFieldsAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = MetaFieldsAPI(mock_client)
        assert api.client == mock_client


class TestListMetaFields:
    """Test meta fields listing operations."""

    @pytest.mark.asyncio
    async def test_list_meta_fields(self, metafields_api, mock_client):
        """Test listing meta fields."""
        mock_data = [
            {"name": "environment", "type": "string"},
            {"name": "priority", "type": "integer"},
        ]
        mock_client.get.return_value = mock_data

        result = await metafields_api.list_meta_fields(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/meta"
        )

    @pytest.mark.asyncio
    async def test_list_meta_fields_empty(self, metafields_api, mock_client):
        """Test listing meta fields with empty result."""
        mock_client.get.return_value = []

        result = await metafields_api.list_meta_fields(adom="custom")

        assert result == []

    @pytest.mark.asyncio
    async def test_list_meta_fields_single_item(self, metafields_api, mock_client):
        """Test listing meta fields with single item result."""
        mock_data = {"name": "environment", "type": "string"}
        mock_client.get.return_value = mock_data

        result = await metafields_api.list_meta_fields(adom="root")

        assert result == [mock_data]


class TestGetMetaField:
    """Test meta field retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_meta_field(self, metafields_api, mock_client):
        """Test getting meta field details."""
        mock_data = {
            "name": "environment",
            "type": "string",
            "length": 255,
        }
        mock_client.get.return_value = mock_data

        result = await metafields_api.get_meta_field("environment", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/system/meta/environment"
        )

    @pytest.mark.asyncio
    async def test_get_meta_field_not_found(self, metafields_api, mock_client):
        """Test getting non-existent meta field."""
        mock_client.get.return_value = None

        result = await metafields_api.get_meta_field("nonexistent", adom="root")

        assert result == {}


class TestCreateMetaField:
    """Test meta field creation operations."""

    @pytest.mark.asyncio
    async def test_create_meta_field_string(self, metafields_api, mock_client):
        """Test creating string meta field."""
        mock_result = {"name": "environment"}
        mock_client.add.return_value = mock_result

        result = await metafields_api.create_meta_field(
            name="environment",
            field_type="string",
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/system/meta"
        assert call_args[1]["data"]["name"] == "environment"
        assert call_args[1]["data"]["type"] == "string"

    @pytest.mark.asyncio
    async def test_create_meta_field_integer(self, metafields_api, mock_client):
        """Test creating integer meta field."""
        mock_result = {"name": "priority"}
        mock_client.add.return_value = mock_result

        result = await metafields_api.create_meta_field(
            name="priority",
            field_type="integer",
            adom="root",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["type"] == "integer"

    @pytest.mark.asyncio
    async def test_create_meta_field_with_kwargs(self, metafields_api, mock_client):
        """Test creating meta field with additional parameters."""
        mock_result = {"name": "custom"}
        mock_client.add.return_value = mock_result

        result = await metafields_api.create_meta_field(
            name="custom",
            field_type="string",
            adom="root",
            length=100,
            importance="high",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["length"] == 100
        assert call_args[1]["data"]["importance"] == "high"


class TestDeleteMetaField:
    """Test meta field deletion operations."""

    @pytest.mark.asyncio
    async def test_delete_meta_field(self, metafields_api, mock_client):
        """Test deleting meta field."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await metafields_api.delete_meta_field("environment", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/system/meta/environment"
        )


class TestObjectMetaFields:
    """Test object meta field operations."""

    @pytest.mark.asyncio
    async def test_list_objects_with_meta_field(self, metafields_api, mock_client):
        """Test listing objects with meta field value."""
        mock_data = [
            {"name": "addr1", "meta-fields": {"environment": "production"}},
            {"name": "addr2", "meta-fields": {"environment": "production"}},
        ]
        mock_client.get.return_value = mock_data

        result = await metafields_api.list_objects_with_meta_field(
            field_name="environment",
            field_value="production",
            object_type="firewall/address",
            adom="root",
        )

        assert result == mock_data
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert "filter" in call_args[1]
        assert "environment==production" in call_args[1]["filter"]

    @pytest.mark.asyncio
    async def test_set_object_meta_field(self, metafields_api, mock_client):
        """Test setting meta field on object."""
        mock_client.set.return_value = None

        await metafields_api.set_object_meta_field(
            object_name="addr1",
            object_type="firewall/address",
            field_name="environment",
            field_value="staging",
            adom="root",
        )

        mock_client.set.assert_called_once()
        call_args = mock_client.set.call_args
        assert "addr1" in call_args[0][0]
        assert call_args[1]["data"]["meta-fields"]["environment"] == "staging"

    @pytest.mark.asyncio
    async def test_get_object_meta_fields(self, metafields_api, mock_client):
        """Test getting all meta fields from object."""
        mock_data = {
            "name": "addr1",
            "meta-fields": {
                "environment": "production",
                "priority": 10,
            },
        }
        mock_client.get.return_value = mock_data

        result = await metafields_api.get_object_meta_fields(
            object_name="addr1",
            object_type="firewall/address",
            adom="root",
        )

        assert result == {"environment": "production", "priority": 10}
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_object_meta_fields_none(self, metafields_api, mock_client):
        """Test getting meta fields from object with no fields."""
        mock_data = {"name": "addr1"}
        mock_client.get.return_value = mock_data

        result = await metafields_api.get_object_meta_fields(
            object_name="addr1",
            object_type="firewall/address",
            adom="root",
        )

        assert result == {}

    @pytest.mark.asyncio
    async def test_get_object_meta_fields_non_dict_response(self, metafields_api, mock_client):
        """Test getting meta fields with non-dict response."""
        mock_client.get.return_value = []

        result = await metafields_api.get_object_meta_fields(
            object_name="addr1",
            object_type="firewall/address",
            adom="root",
        )

        assert result == {}


class TestMetaFieldTypes:
    """Test different meta field types."""

    @pytest.mark.asyncio
    async def test_create_boolean_meta_field(self, metafields_api, mock_client):
        """Test creating boolean meta field."""
        mock_result = {"name": "is_active"}
        mock_client.add.return_value = mock_result

        result = await metafields_api.create_meta_field(
            name="is_active",
            field_type="boolean",
            adom="root",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["type"] == "boolean"

    @pytest.mark.asyncio
    async def test_set_object_meta_field_integer(self, metafields_api, mock_client):
        """Test setting integer meta field value."""
        mock_client.set.return_value = None

        await metafields_api.set_object_meta_field(
            object_name="addr1",
            object_type="firewall/address",
            field_name="priority",
            field_value=5,
            adom="root",
        )

        call_args = mock_client.set.call_args
        assert call_args[1]["data"]["meta-fields"]["priority"] == 5
