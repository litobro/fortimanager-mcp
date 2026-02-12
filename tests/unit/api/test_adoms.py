"""Unit tests for api.adoms module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.adoms import ADOMAPI
from fortimanager_mcp.api.models import ADOM
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
def adom_api(mock_client):
    """Create ADOMAPI instance with mock client."""
    return ADOMAPI(mock_client)


class TestADOMAPIInit:
    """Test ADOMAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = ADOMAPI(mock_client)
        assert api.client == mock_client


class TestListADOMs:
    """Test listing ADOMs."""

    @pytest.mark.asyncio
    async def test_list_adoms_success(self, adom_api, mock_client):
        """Test listing ADOMs successfully."""
        mock_data = [
            {
                "name": "root",
                "desc": "Root ADOM",
                "os_ver": "7.0",
                "mr": 4,
                "state": 1,
            },
            {
                "name": "test",
                "desc": "Test ADOM",
                "os_ver": "7.2",
                "mr": 0,
            },
        ]
        mock_client.get.return_value = mock_data

        result = await adom_api.list_adoms()

        assert len(result) == 2
        assert all(isinstance(adom, ADOM) for adom in result)
        assert result[0].name == "root"
        assert result[1].name == "test"
        mock_client.get.assert_called_once_with(
            "/dvmdb/adom",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_adoms_with_fields(self, adom_api, mock_client):
        """Test listing ADOMs with specific fields."""
        mock_data = [{"name": "root"}]
        mock_client.get.return_value = mock_data

        await adom_api.list_adoms(fields=["name", "os_ver"])

        mock_client.get.assert_called_once_with(
            "/dvmdb/adom",
            fields=["name", "os_ver"],
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_adoms_with_filter(self, adom_api, mock_client):
        """Test listing ADOMs with filter."""
        mock_data = [{"name": "test"}]
        mock_client.get.return_value = mock_data
        filter_criteria = ["os_ver", "==", "7.0"]

        await adom_api.list_adoms(filter=filter_criteria)

        mock_client.get.assert_called_once_with(
            "/dvmdb/adom",
            fields=None,
            filter=filter_criteria,
        )

    @pytest.mark.asyncio
    async def test_list_adoms_empty(self, adom_api, mock_client):
        """Test listing ADOMs returns empty list."""
        mock_client.get.return_value = []

        result = await adom_api.list_adoms()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_adoms_single_dict(self, adom_api, mock_client):
        """Test listing ADOMs when single dict returned."""
        mock_data = {"name": "root", "os_ver": "7.0"}
        mock_client.get.return_value = mock_data

        result = await adom_api.list_adoms()

        assert len(result) == 1
        assert isinstance(result[0], ADOM)

    @pytest.mark.asyncio
    async def test_list_adoms_none(self, adom_api, mock_client):
        """Test listing ADOMs when None returned."""
        mock_client.get.return_value = None

        result = await adom_api.list_adoms()

        assert result == []


class TestGetADOM:
    """Test getting specific ADOM."""

    @pytest.mark.asyncio
    async def test_get_adom_success(self, adom_api, mock_client):
        """Test getting ADOM successfully."""
        mock_data = {
            "name": "root",
            "desc": "Root ADOM",
            "os_ver": "7.0",
            "mr": 4,
            "state": 1,
            "oid": 123,
        }
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom("root")

        assert isinstance(result, ADOM)
        assert result.name == "root"
        assert result.desc == "Root ADOM"
        assert result.os_ver == "7.0"
        assert result.mr == 4
        mock_client.get.assert_called_once_with("/dvmdb/adom/root")

    @pytest.mark.asyncio
    async def test_get_adom_different_name(self, adom_api, mock_client):
        """Test getting ADOM with different name."""
        mock_data = {"name": "production"}
        mock_client.get.return_value = mock_data

        await adom_api.get_adom("production")

        mock_client.get.assert_called_once_with("/dvmdb/adom/production")


class TestCreateADOM:
    """Test creating ADOMs."""

    @pytest.mark.asyncio
    async def test_create_adom_basic(self, adom_api, mock_client):
        """Test creating ADOM with basic parameters."""
        mock_data = {"name": "new_adom", "os_ver": "7.0", "mr": 0}
        mock_client.get.return_value = mock_data

        result = await adom_api.create_adom(
            name="new_adom",
            os_ver="7.0",
            mr=0,
        )

        assert isinstance(result, ADOM)
        assert result.name == "new_adom"

        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/dvmdb/adom"
        data = call_args[1]["data"]
        assert data["name"] == "new_adom"
        assert data["os_ver"] == "7.0"
        assert data["mr"] == 0

    @pytest.mark.asyncio
    async def test_create_adom_with_description(self, adom_api, mock_client):
        """Test creating ADOM with description."""
        mock_data = {"name": "new_adom"}
        mock_client.get.return_value = mock_data

        await adom_api.create_adom(
            name="new_adom",
            description="Test ADOM",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["desc"] == "Test ADOM"

    @pytest.mark.asyncio
    async def test_create_adom_with_kwargs(self, adom_api, mock_client):
        """Test creating ADOM with additional kwargs."""
        mock_data = {"name": "new_adom"}
        mock_client.get.return_value = mock_data

        await adom_api.create_adom(
            name="new_adom",
            workspace_mode=1,
            restricted_prds="fos",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["workspace_mode"] == 1
        assert data["restricted_prds"] == "fos"

    @pytest.mark.asyncio
    async def test_create_adom_different_version(self, adom_api, mock_client):
        """Test creating ADOM with different OS version."""
        mock_data = {"name": "new_adom"}
        mock_client.get.return_value = mock_data

        await adom_api.create_adom(
            name="new_adom",
            os_ver="7.2",
            mr=2,
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["os_ver"] == "7.2"
        assert data["mr"] == 2


class TestUpdateADOM:
    """Test updating ADOMs."""

    @pytest.mark.asyncio
    async def test_update_adom_success(self, adom_api, mock_client):
        """Test updating ADOM."""
        mock_data = {"name": "test", "desc": "Updated description"}
        mock_client.get.return_value = mock_data

        result = await adom_api.update_adom(
            name="test",
            desc="Updated description",
        )

        assert isinstance(result, ADOM)
        assert result.name == "test"
        mock_client.set.assert_called_once_with(
            "/dvmdb/adom/test",
            data={"desc": "Updated description"},
        )

    @pytest.mark.asyncio
    async def test_update_adom_multiple_fields(self, adom_api, mock_client):
        """Test updating multiple ADOM fields."""
        mock_data = {"name": "test"}
        mock_client.get.return_value = mock_data

        await adom_api.update_adom(
            name="test",
            desc="New description",
            workspace_mode=1,
        )

        call_args = mock_client.set.call_args
        data = call_args[1]["data"]
        assert data["desc"] == "New description"
        assert data["workspace_mode"] == 1


class TestDeleteADOM:
    """Test deleting ADOMs."""

    @pytest.mark.asyncio
    async def test_delete_adom_success(self, adom_api, mock_client):
        """Test deleting ADOM."""
        await adom_api.delete_adom("test")

        mock_client.delete.assert_called_once_with("/dvmdb/adom/test")

    @pytest.mark.asyncio
    async def test_delete_adom_different_name(self, adom_api, mock_client):
        """Test deleting ADOM with different name."""
        await adom_api.delete_adom("production")

        mock_client.delete.assert_called_once_with("/dvmdb/adom/production")


class TestWorkspaceOperations:
    """Test ADOM workspace operations."""

    @pytest.mark.asyncio
    async def test_lock_adom_basic(self, adom_api, mock_client):
        """Test locking ADOM workspace."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await adom_api.lock_adom("test")

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert call_args[0][0] == "/dvmdb/adom/test/workspace/lock"
        assert call_args[1]["data"] == {}

    @pytest.mark.asyncio
    async def test_unlock_adom_basic(self, adom_api, mock_client):
        """Test unlocking ADOM workspace."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await adom_api.unlock_adom("test")

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert call_args[0][0] == "/dvmdb/adom/test/workspace/unlock"
        assert call_args[1]["data"] == {}

    @pytest.mark.asyncio
    async def test_commit_adom(self, adom_api, mock_client):
        """Test committing ADOM changes."""
        await adom_api.commit_adom("test")

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvmdb/adom/workspace/commit"
        data = call_args[1]["data"]
        assert data["adom"] == "test"

    @pytest.mark.asyncio
    async def test_lock_adom_exec(self, adom_api, mock_client):
        """Test locking ADOM workspace using exec method."""
        mock_result = {"status": "success"}
        mock_client.exec.return_value = mock_result

        result = await adom_api.lock_adom("test")

        assert result == mock_result
        call_args = mock_client.exec.call_args
        assert "/workspace/lock" in call_args[0][0]


class TestCloneADOM:
    """Test cloning ADOMs."""

    @pytest.mark.asyncio
    async def test_clone_adom_basic(self, adom_api, mock_client):
        """Test cloning ADOM."""
        mock_data = {"name": "new_adom", "os_ver": "7.0"}
        mock_client.get.return_value = mock_data

        result = await adom_api.clone_adom(
            source_adom="source",
            target_adom="new_adom",
        )

        assert isinstance(result, ADOM)
        assert result.name == "new_adom"

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvmdb/adom/clone"
        data = call_args[1]["data"]
        assert data["src-name"] == "source"
        assert data["dst-name"] == "new_adom"

    @pytest.mark.asyncio
    async def test_clone_adom_with_description(self, adom_api, mock_client):
        """Test cloning ADOM with description."""
        mock_data = {"name": "new_adom"}
        mock_client.get.return_value = mock_data

        await adom_api.clone_adom(
            source_adom="source",
            target_adom="new_adom",
            description="Cloned ADOM",
        )

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["desc"] == "Cloned ADOM"


class TestMoveDeviceOperations:
    """Test moving devices and VDOMs between ADOMs."""

    @pytest.mark.asyncio
    async def test_move_device_to_adom(self, adom_api, mock_client):
        """Test moving device to different ADOM."""
        await adom_api.move_device_to_adom(
            device_name="device1",
            target_adom="target",
            source_adom="source",
        )

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvm/cmd/move/device"
        data = call_args[1]["data"]
        assert data["device"] == "device1"
        assert data["src-adom"] == "source"
        assert data["dst-adom"] == "target"

    @pytest.mark.asyncio
    async def test_move_device_to_adom_from_root(self, adom_api, mock_client):
        """Test moving device from root ADOM."""
        await adom_api.move_device_to_adom(
            device_name="device1",
            target_adom="target",
        )

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["src-adom"] == "root"

    @pytest.mark.asyncio
    async def test_move_vdom_to_adom(self, adom_api, mock_client):
        """Test moving VDOM to different ADOM."""
        await adom_api.move_vdom_to_adom(
            device_name="device1",
            vdom_name="vdom1",
            target_adom="target",
            source_adom="source",
        )

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvm/cmd/move/vdom"
        data = call_args[1]["data"]
        assert data["device"] == "device1"
        assert data["vdom"] == "vdom1"
        assert data["src-adom"] == "source"
        assert data["dst-adom"] == "target"


class TestADOMRevisions:
    """Test ADOM revision operations."""

    @pytest.mark.asyncio
    async def test_get_adom_revision_list(self, adom_api, mock_client):
        """Test getting ADOM revision list."""
        mock_data = [
            {"version": 1, "name": "rev1"},
            {"version": 2, "name": "rev2"},
        ]
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_revision_list("test")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/revision")

    @pytest.mark.asyncio
    async def test_get_adom_revision_list_single(self, adom_api, mock_client):
        """Test getting ADOM revision list with single result."""
        mock_data = {"version": 1, "name": "rev1"}
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_revision_list("test")

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_adom_revision_list_empty(self, adom_api, mock_client):
        """Test getting ADOM revision list when empty."""
        mock_client.get.return_value = None

        result = await adom_api.get_adom_revision_list("test")

        assert result == []

    @pytest.mark.asyncio
    async def test_revert_adom_revision(self, adom_api, mock_client):
        """Test reverting ADOM to specific revision."""
        await adom_api.revert_adom_revision(
            adom="test",
            revision_id=5,
        )

        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvmdb/adom/revision/revert"
        data = call_args[1]["data"]
        assert data["adom"] == "test"
        assert data["version"] == 5

    @pytest.mark.asyncio
    async def test_create_adom_revision_basic(self, adom_api, mock_client):
        """Test creating ADOM revision."""
        result = await adom_api.create_adom_revision(
            adom="test",
            name="checkpoint1",
        )

        assert result == {"name": "checkpoint1", "adom": "test"}
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/dvmdb/adom/test/revision"
        data = call_args[1]["data"]
        assert data["name"] == "checkpoint1"
        assert data["locked"] == 0

    @pytest.mark.asyncio
    async def test_create_adom_revision_with_description(self, adom_api, mock_client):
        """Test creating ADOM revision with description."""
        await adom_api.create_adom_revision(
            adom="test",
            name="checkpoint1",
            description="Before upgrade",
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["desc"] == "Before upgrade"

    @pytest.mark.asyncio
    async def test_create_adom_revision_locked(self, adom_api, mock_client):
        """Test creating locked ADOM revision."""
        await adom_api.create_adom_revision(
            adom="test",
            name="checkpoint1",
            locked=True,
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["locked"] == 1

    @pytest.mark.asyncio
    async def test_delete_adom_revision(self, adom_api, mock_client):
        """Test deleting ADOM revision."""
        await adom_api.delete_adom_revision(
            adom="test",
            revision_id=3,
        )

        mock_client.delete.assert_called_once_with("/dvmdb/adom/test/revision/3")


class TestADOMIntegrityAndChecksum:
    """Test ADOM integrity and checksum operations."""

    @pytest.mark.asyncio
    async def test_get_adom_checksum(self, adom_api, mock_client):
        """Test getting ADOM checksum."""
        mock_result = {"checksum": "abc123", "timestamp": 1234567890}
        mock_client.execute.return_value = mock_result

        result = await adom_api.get_adom_checksum("test")

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvmdb/adom/checksum"
        data = call_args[1]["data"]
        assert data["adom"] == "test"

    @pytest.mark.asyncio
    async def test_check_adom_integrity(self, adom_api, mock_client):
        """Test checking ADOM integrity."""
        mock_result = {"status": "ok", "issues": []}
        mock_client.execute.return_value = mock_result

        result = await adom_api.check_adom_integrity("test")

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvm/cmd/check-integrity"
        data = call_args[1]["data"]
        assert data["adom"] == "test"


class TestUpgradeADOM:
    """Test ADOM upgrade operations."""

    @pytest.mark.asyncio
    async def test_upgrade_adom_basic(self, adom_api, mock_client):
        """Test upgrading ADOM to new version."""
        mock_result = {"taskid": 123, "status": "started"}
        mock_client.execute.return_value = mock_result

        result = await adom_api.upgrade_adom(
            adom="test",
            target_version="7.2",
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/dvmdb/adom/upgrade"
        data = call_args[1]["data"]
        assert data["adom"] == "test"
        assert data["target-ver"] == "7.2"
        assert data["target-mr"] == 0

    @pytest.mark.asyncio
    async def test_upgrade_adom_with_mr(self, adom_api, mock_client):
        """Test upgrading ADOM with maintenance release."""
        mock_client.execute.return_value = {"taskid": 123}

        await adom_api.upgrade_adom(
            adom="test",
            target_version="7.2",
            target_mr=4,
        )

        call_args = mock_client.execute.call_args
        data = call_args[1]["data"]
        assert data["target-mr"] == 4


class TestWhereUsedOperations:
    """Test where-used operations."""

    @pytest.mark.asyncio
    async def test_get_adom_where_used(self, adom_api, mock_client):
        """Test getting where object is used in ADOM."""
        mock_result = [
            {"type": "policy", "name": "policy1"},
            {"type": "group", "name": "group1"},
        ]
        mock_client.execute.return_value = mock_result

        result = await adom_api.get_adom_where_used(
            adom="test",
            object_type="firewall address",
            object_name="addr1",
        )

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert "firewall/address/where-used" in call_args[0][0]
        data = call_args[1]["data"]
        assert data["adom"] == "test"
        assert data["mkey"] == "addr1"

    @pytest.mark.asyncio
    async def test_get_adom_where_used_single(self, adom_api, mock_client):
        """Test getting where-used with single result."""
        mock_result = {"type": "policy", "name": "policy1"}
        mock_client.execute.return_value = mock_result

        result = await adom_api.get_adom_where_used(
            adom="test",
            object_type="firewall service",
            object_name="svc1",
        )

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_adom_where_used_empty(self, adom_api, mock_client):
        """Test getting where-used with empty result."""
        mock_client.execute.return_value = None

        result = await adom_api.get_adom_where_used(
            adom="test",
            object_type="firewall address",
            object_name="addr1",
        )

        assert result == []


class TestADOMObjectUsage:
    """Test ADOM object usage operations."""

    @pytest.mark.asyncio
    async def test_get_adom_object_usage(self, adom_api, mock_client):
        """Test getting ADOM object usage statistics."""
        mock_result = {
            "addresses": 100,
            "address_groups": 20,
            "services": 50,
        }
        mock_client.get.return_value = mock_result

        result = await adom_api.get_adom_object_usage("test")

        assert result == mock_result
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/object-usage")


class TestAssignDeviceToADOM:
    """Test assigning devices to ADOMs."""

    @pytest.mark.asyncio
    async def test_assign_device_to_adom_basic(self, adom_api, mock_client):
        """Test assigning device to ADOM."""
        await adom_api.assign_device_to_adom(
            device_name="device1",
            adom="target",
        )

        call_args = mock_client.set.call_args
        assert call_args[0][0] == "/dvmdb/device/device1/vdom/root"
        data = call_args[1]["data"]
        assert data["adm-usr"] == "target"

    @pytest.mark.asyncio
    async def test_assign_device_to_adom_with_vdom(self, adom_api, mock_client):
        """Test assigning device VDOM to ADOM."""
        await adom_api.assign_device_to_adom(
            device_name="device1",
            adom="target",
            vdom="vdom1",
        )

        call_args = mock_client.set.call_args
        assert "vdom/vdom1" in call_args[0][0]


class TestADOMPolicySyncStatus:
    """Test ADOM policy sync status."""

    @pytest.mark.asyncio
    async def test_get_adom_policy_sync_status(self, adom_api, mock_client):
        """Test getting ADOM policy sync status."""
        mock_result = {"status": "in_sync", "devices": []}
        mock_client.get.return_value = mock_result

        result = await adom_api.get_adom_policy_sync_status("test")

        assert result == mock_result
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/sync/status")


class TestADOMMetaFields:
    """Test ADOM meta fields."""

    @pytest.mark.asyncio
    async def test_get_adom_meta_fields(self, adom_api, mock_client):
        """Test getting ADOM meta fields."""
        mock_data = [
            {"name": "priority", "value": "high"},
            {"name": "owner", "value": "admin"},
        ]
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_meta_fields("test")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/meta-fields")

    @pytest.mark.asyncio
    async def test_get_adom_meta_fields_single(self, adom_api, mock_client):
        """Test getting ADOM meta fields with single result."""
        mock_data = {"name": "priority", "value": "high"}
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_meta_fields("test")

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_adom_meta_fields_empty(self, adom_api, mock_client):
        """Test getting ADOM meta fields when empty."""
        mock_client.get.return_value = None

        result = await adom_api.get_adom_meta_fields("test")

        assert result == []


class TestADOMStatistics:
    """Test ADOM statistics operations."""

    @pytest.mark.asyncio
    async def test_get_adom_statistics_success(self, adom_api, mock_client):
        """Test getting ADOM statistics successfully."""
        mock_data = {
            "devices": 10,
            "policies": 100,
            "objects": 500,
        }
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_statistics("test")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/statistics")

    @pytest.mark.asyncio
    async def test_get_adom_statistics_not_found(self, adom_api, mock_client):
        """Test getting ADOM statistics when endpoint not supported."""
        mock_client.get.side_effect = ResourceNotFoundError("Endpoint not found")

        result = await adom_api.get_adom_statistics("test")

        assert "error" in result
        assert result["error"] == "ADOM statistics endpoint not supported"
        assert result["adom"] == "test"

    @pytest.mark.asyncio
    async def test_get_adom_statistics_other_error(self, adom_api, mock_client):
        """Test getting ADOM statistics with other errors."""
        mock_client.get.side_effect = APIError("API Error")

        with pytest.raises(APIError):
            await adom_api.get_adom_statistics("test")

    @pytest.mark.asyncio
    async def test_get_adom_statistics_non_dict(self, adom_api, mock_client):
        """Test getting ADOM statistics returns empty dict for non-dict."""
        mock_client.get.return_value = ["not", "a", "dict"]

        result = await adom_api.get_adom_statistics("test")

        assert result == {}


class TestExportADOMConfiguration:
    """Test exporting ADOM configuration."""

    @pytest.mark.asyncio
    async def test_export_adom_configuration(self, adom_api, mock_client):
        """Test exporting ADOM configuration."""
        mock_result = {"config": "exported_data"}
        mock_client.execute.return_value = mock_result

        result = await adom_api.export_adom_configuration("test")

        assert result == mock_result
        call_args = mock_client.execute.call_args
        assert call_args[0][0] == "/pm/config/adom/test/export"


class TestADOMHealthStatus:
    """Test ADOM health status operations."""

    @pytest.mark.asyncio
    async def test_get_adom_health_status_success(self, adom_api, mock_client):
        """Test getting ADOM health status successfully."""
        mock_data = {
            "status": "healthy",
            "devices": [{"name": "dev1", "status": "up"}],
        }
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_health_status("test")

        assert result == mock_data
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/health")

    @pytest.mark.asyncio
    async def test_get_adom_health_status_not_found(self, adom_api, mock_client):
        """Test getting ADOM health when endpoint not supported."""
        mock_client.get.side_effect = ResourceNotFoundError("Endpoint not found")

        result = await adom_api.get_adom_health_status("test")

        assert "error" in result
        assert result["error"] == "ADOM health endpoint not supported"
        assert result["adom"] == "test"

    @pytest.mark.asyncio
    async def test_get_adom_health_status_other_error(self, adom_api, mock_client):
        """Test getting ADOM health with other errors."""
        mock_client.get.side_effect = APIError("API Error")

        with pytest.raises(APIError):
            await adom_api.get_adom_health_status("test")

    @pytest.mark.asyncio
    async def test_get_adom_health_status_non_dict(self, adom_api, mock_client):
        """Test getting ADOM health returns empty dict for non-dict."""
        mock_client.get.return_value = "not a dict"

        result = await adom_api.get_adom_health_status("test")

        assert result == {}


class TestADOMDiskUsage:
    """Test ADOM disk usage operations."""

    @pytest.mark.asyncio
    async def test_get_adom_disk_usage_success(self, adom_api, mock_client):
        """Test getting ADOM disk usage successfully."""
        mock_data = {
            "total": 1000000,
            "used": 500000,
            "available": 500000,
        }
        mock_client.get.return_value = mock_data

        result = await adom_api.get_adom_disk_usage("test")

        assert result == mock_data
        # Note: Based on the pattern, this would call an endpoint


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_api_error_propagation(self, adom_api, mock_client):
        """Test that API errors are propagated."""
        mock_client.get.side_effect = APIError("API call failed")

        with pytest.raises(APIError):
            await adom_api.list_adoms()

    @pytest.mark.asyncio
    async def test_resource_not_found_propagation(self, adom_api, mock_client):
        """Test that ResourceNotFoundError is propagated."""
        mock_client.get.side_effect = ResourceNotFoundError("ADOM not found")

        with pytest.raises(ResourceNotFoundError):
            await adom_api.get_adom("nonexistent")

    @pytest.mark.asyncio
    async def test_create_adom_without_description(self, adom_api, mock_client):
        """Test creating ADOM without description."""
        mock_data = {"name": "test"}
        mock_client.get.return_value = mock_data

        await adom_api.create_adom(name="test")

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert "desc" not in data

    @pytest.mark.asyncio
    async def test_create_adom_revision_not_locked(self, adom_api, mock_client):
        """Test creating ADOM revision not locked by default."""
        await adom_api.create_adom_revision(
            adom="test",
            name="rev1",
            locked=False,
        )

        call_args = mock_client.add.call_args
        data = call_args[1]["data"]
        assert data["locked"] == 0

    @pytest.mark.asyncio
    async def test_workspace_operations_different_adoms(self, adom_api, mock_client):
        """Test workspace operations on different ADOMs."""
        test_adoms = ["root", "test", "production", "staging"]

        for adom in test_adoms:
            mock_client.exec.reset_mock()
            mock_client.exec.return_value = {"status": "success"}

            await adom_api.lock_adom(adom)

            call_args = mock_client.exec.call_args
            assert f"/dvmdb/adom/{adom}/workspace/lock" in call_args[0][0]
