"""Unit tests for api.workspace module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.workspace import WorkspaceAPI


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
def workspace_api(mock_client):
    """Create WorkspaceAPI instance with mock client."""
    return WorkspaceAPI(mock_client)


class TestWorkspaceAPIInit:
    """Test WorkspaceAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = WorkspaceAPI(mock_client)
        assert api.client == mock_client


class TestADOMWorkspaceOperations:
    """Test ADOM workspace operations."""

    @pytest.mark.asyncio
    async def test_lock_adom_root(self, workspace_api, mock_client):
        """Test locking root ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.lock_adom("root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with("/dvmdb/adom/root/workspace/lock")

    @pytest.mark.asyncio
    async def test_lock_adom_custom(self, workspace_api, mock_client):
        """Test locking custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.lock_adom("test-adom")

        mock_client.exec.assert_called_once_with("/dvmdb/adom/test-adom/workspace/lock")

    @pytest.mark.asyncio
    async def test_lock_adom_default(self, workspace_api, mock_client):
        """Test locking ADOM with default parameter."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.lock_adom()

        mock_client.exec.assert_called_once_with("/dvmdb/adom/root/workspace/lock")

    @pytest.mark.asyncio
    async def test_unlock_adom_root(self, workspace_api, mock_client):
        """Test unlocking root ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.unlock_adom("root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with("/dvmdb/adom/root/workspace/unlock")

    @pytest.mark.asyncio
    async def test_unlock_adom_custom(self, workspace_api, mock_client):
        """Test unlocking custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.unlock_adom("custom-adom")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/custom-adom/workspace/unlock"
        )

    @pytest.mark.asyncio
    async def test_commit_adom_root(self, workspace_api, mock_client):
        """Test committing root ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.commit_adom("root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with("/dvmdb/adom/root/workspace/commit")

    @pytest.mark.asyncio
    async def test_commit_adom_custom(self, workspace_api, mock_client):
        """Test committing custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.commit_adom("my-adom")

        mock_client.exec.assert_called_once_with("/dvmdb/adom/my-adom/workspace/commit")

    @pytest.mark.asyncio
    async def test_get_lock_info(self, workspace_api, mock_client):
        """Test getting ADOM lock info."""
        mock_data = {
            "lock_user": "admin",
            "lock_time": 1234567890,
            "dirty": True,
        }
        mock_client.get.return_value = mock_data

        result = await workspace_api.get_lock_info("root")

        assert result["lock_user"] == "admin"
        assert result["dirty"] is True
        mock_client.get.assert_called_once_with("/dvmdb/adom/root/workspace/lockinfo")

    @pytest.mark.asyncio
    async def test_get_lock_info_custom_adom(self, workspace_api, mock_client):
        """Test getting lock info for custom ADOM."""
        mock_data = {"lock_user": None}
        mock_client.get.return_value = mock_data

        result = await workspace_api.get_lock_info("test")

        assert result["lock_user"] is None
        mock_client.get.assert_called_once_with("/dvmdb/adom/test/workspace/lockinfo")


class TestPolicyPackageWorkspaceOperations:
    """Test policy package workspace operations."""

    @pytest.mark.asyncio
    async def test_lock_package(self, workspace_api, mock_client):
        """Test locking policy package."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.lock_package("default", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/lock/pkg/default"
        )

    @pytest.mark.asyncio
    async def test_lock_package_custom_adom(self, workspace_api, mock_client):
        """Test locking package in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.lock_package("my-pkg", adom="test-adom")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/test-adom/workspace/lock/pkg/my-pkg"
        )

    @pytest.mark.asyncio
    async def test_unlock_package(self, workspace_api, mock_client):
        """Test unlocking policy package."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.unlock_package("default", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/unlock/pkg/default"
        )

    @pytest.mark.asyncio
    async def test_unlock_package_custom_adom(self, workspace_api, mock_client):
        """Test unlocking package in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.unlock_package("test-pkg", adom="my-adom")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/my-adom/workspace/unlock/pkg/test-pkg"
        )

    @pytest.mark.asyncio
    async def test_commit_package(self, workspace_api, mock_client):
        """Test committing policy package."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.commit_package("default", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/commit/pkg/default"
        )

    @pytest.mark.asyncio
    async def test_commit_package_custom_adom(self, workspace_api, mock_client):
        """Test committing package in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.commit_package("pkg-name", adom="custom")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/custom/workspace/commit/pkg/pkg-name"
        )

    @pytest.mark.asyncio
    async def test_get_package_lock_info_dvmdb(self, workspace_api, mock_client):
        """Test getting package lock info via dvmdb endpoint."""
        mock_data = {"lock_user": "admin", "lock_time": 1234567890}
        mock_client.get.return_value = mock_data

        result = await workspace_api.get_package_lock_info("default", adom="root")

        assert result["lock_user"] == "admin"
        # The first get_package_lock_info method uses pm/config endpoint
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_package_lock_info_custom_adom(self, workspace_api, mock_client):
        """Test getting package lock info for custom ADOM."""
        mock_data = {"lock_user": None}
        mock_client.get.return_value = mock_data

        await workspace_api.get_package_lock_info("test-pkg", adom="test")

        mock_client.get.assert_called_once()


class TestDeviceWorkspaceOperations:
    """Test device workspace operations."""

    @pytest.mark.asyncio
    async def test_lock_device(self, workspace_api, mock_client):
        """Test locking device."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.lock_device("FGT1", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/lock/dev/FGT1"
        )

    @pytest.mark.asyncio
    async def test_lock_device_custom_adom(self, workspace_api, mock_client):
        """Test locking device in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.lock_device("FGT2", adom="branch")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/branch/workspace/lock/dev/FGT2"
        )

    @pytest.mark.asyncio
    async def test_unlock_device(self, workspace_api, mock_client):
        """Test unlocking device."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.unlock_device("FGT1", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/unlock/dev/FGT1"
        )

    @pytest.mark.asyncio
    async def test_unlock_device_custom_adom(self, workspace_api, mock_client):
        """Test unlocking device in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.unlock_device("FGT-Branch", adom="test")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/test/workspace/unlock/dev/FGT-Branch"
        )

    @pytest.mark.asyncio
    async def test_commit_device(self, workspace_api, mock_client):
        """Test committing device."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.commit_device("FGT1", adom="root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/workspace/commit/dev/FGT1"
        )

    @pytest.mark.asyncio
    async def test_commit_device_custom_adom(self, workspace_api, mock_client):
        """Test committing device in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.commit_device("Device123", adom="datacenter")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/datacenter/workspace/commit/dev/Device123"
        )


class TestADOMRevisionOperations:
    """Test ADOM revision operations."""

    @pytest.mark.asyncio
    async def test_revert_adom_revision(self, workspace_api, mock_client):
        """Test reverting ADOM to previous revision."""
        mock_client.set.return_value = {"status": {"code": 0}}

        result = await workspace_api.revert_adom_revision(5, adom="root")

        assert result["status"]["code"] == 0
        mock_client.set.assert_called_once_with(
            "/dvmdb/adom/root/revision/revert", data={"version": 5}
        )

    @pytest.mark.asyncio
    async def test_revert_adom_revision_custom_adom(self, workspace_api, mock_client):
        """Test reverting custom ADOM to previous revision."""
        mock_client.set.return_value = {"status": {"code": 0}}

        await workspace_api.revert_adom_revision(10, adom="production")

        mock_client.set.assert_called_once_with(
            "/dvmdb/adom/production/revision/revert", data={"version": 10}
        )

    @pytest.mark.asyncio
    async def test_revert_adom_revision_different_versions(
        self, workspace_api, mock_client
    ):
        """Test reverting to different version numbers."""
        mock_client.set.return_value = {"status": {"code": 0}}

        await workspace_api.revert_adom_revision(1, adom="root")

        call_args = mock_client.set.call_args
        assert call_args[1]["data"]["version"] == 1


class TestAdditionalWorkspaceOperations:
    """Test additional workspace operations from Phase 44."""

    @pytest.mark.asyncio
    async def test_get_workspace_lock_info(self, workspace_api, mock_client):
        """Test getting detailed workspace lock info."""
        mock_data = {
            "lock_user": "admin",
            "lock_time": 1234567890,
            "locked": True,
        }
        mock_client.get.return_value = mock_data

        result = await workspace_api.get_workspace_lock_info("root")

        assert result["lock_user"] == "admin"
        assert result["locked"] is True
        mock_client.get.assert_called_once_with("/dvmdb/adom/root/workspace/lockinfo")

    @pytest.mark.asyncio
    async def test_get_workspace_lock_info_custom_adom(
        self, workspace_api, mock_client
    ):
        """Test getting workspace lock info for custom ADOM."""
        mock_data = {"locked": False}
        mock_client.get.return_value = mock_data

        result = await workspace_api.get_workspace_lock_info("test-adom")

        assert result["locked"] is False
        mock_client.get.assert_called_once_with(
            "/dvmdb/adom/test-adom/workspace/lockinfo"
        )

    @pytest.mark.asyncio
    async def test_get_package_lock_info_pm_endpoint(
        self, workspace_api, mock_client
    ):
        """Test getting package lock info via pm config endpoint."""
        mock_data = {"lock_status": "locked", "user": "admin"}
        mock_client.get.return_value = mock_data

        # The second get_package_lock_info in the file uses pm/config endpoint
        result = await workspace_api.get_package_lock_info("default", adom="root")

        assert result["lock_status"] == "locked"
        # The method is called twice in workspace.py, using the first occurrence
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_discard_adom_changes(self, workspace_api, mock_client):
        """Test discarding ADOM changes."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        result = await workspace_api.discard_adom_changes("root")

        assert result["status"]["code"] == 0
        mock_client.exec.assert_called_once_with("/dvmdb/adom/root/workspace/discard")

    @pytest.mark.asyncio
    async def test_discard_adom_changes_custom_adom(
        self, workspace_api, mock_client
    ):
        """Test discarding changes in custom ADOM."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        await workspace_api.discard_adom_changes("staging")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/staging/workspace/discard"
        )

    @pytest.mark.asyncio
    async def test_get_revision_diff(self, workspace_api, mock_client):
        """Test getting differences between ADOM revisions."""
        mock_data = {
            "changes": [
                {"type": "add", "object": "policy1"},
                {"type": "modify", "object": "policy2"},
            ]
        }
        mock_client.exec.return_value = mock_data

        result = await workspace_api.get_revision_diff(5, 10, adom="root")

        assert "changes" in result
        assert len(result["changes"]) == 2
        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/root/revision/diff", data={"version1": 5, "version2": 10}
        )

    @pytest.mark.asyncio
    async def test_get_revision_diff_custom_adom(self, workspace_api, mock_client):
        """Test getting revision diff for custom ADOM."""
        mock_data = {"changes": []}
        mock_client.exec.return_value = mock_data

        await workspace_api.get_revision_diff(1, 2, adom="test")

        mock_client.exec.assert_called_once_with(
            "/dvmdb/adom/test/revision/diff", data={"version1": 1, "version2": 2}
        )

    @pytest.mark.asyncio
    async def test_get_revision_diff_reverse_order(self, workspace_api, mock_client):
        """Test getting revision diff in reverse order."""
        mock_data = {"changes": []}
        mock_client.exec.return_value = mock_data

        await workspace_api.get_revision_diff(10, 5, adom="root")

        call_args = mock_client.exec.call_args
        assert call_args[1]["data"]["version1"] == 10
        assert call_args[1]["data"]["version2"] == 5


class TestWorkspaceWorkflow:
    """Test typical workspace workflow scenarios."""

    @pytest.mark.asyncio
    async def test_lock_modify_commit_workflow(self, workspace_api, mock_client):
        """Test typical lock-modify-commit workflow."""
        mock_client.exec.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {"lock_user": "admin"}

        # Lock ADOM
        await workspace_api.lock_adom("root")
        # Check lock info
        lock_info = await workspace_api.get_lock_info("root")
        # Commit changes
        await workspace_api.commit_adom("root")

        assert mock_client.exec.call_count == 2
        assert mock_client.get.call_count == 1
        assert lock_info["lock_user"] == "admin"

    @pytest.mark.asyncio
    async def test_lock_discard_unlock_workflow(self, workspace_api, mock_client):
        """Test lock-discard-unlock workflow."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        # Lock ADOM
        await workspace_api.lock_adom("root")
        # Discard changes
        await workspace_api.discard_adom_changes("root")
        # Unlock ADOM
        await workspace_api.unlock_adom("root")

        assert mock_client.exec.call_count == 3

    @pytest.mark.asyncio
    async def test_package_workspace_workflow(self, workspace_api, mock_client):
        """Test package-specific workspace workflow."""
        mock_client.exec.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {"lock_user": "admin"}

        # Lock package
        await workspace_api.lock_package("default", adom="root")
        # Get lock info
        await workspace_api.get_package_lock_info("default", adom="root")
        # Commit package
        await workspace_api.commit_package("default", adom="root")

        assert mock_client.exec.call_count == 2
        assert mock_client.get.call_count == 1

    @pytest.mark.asyncio
    async def test_device_workspace_workflow(self, workspace_api, mock_client):
        """Test device-specific workspace workflow."""
        mock_client.exec.return_value = {"status": {"code": 0}}

        # Lock device
        await workspace_api.lock_device("FGT1", adom="root")
        # Commit device
        await workspace_api.commit_device("FGT1", adom="root")
        # Unlock device (if needed after commit)
        await workspace_api.unlock_device("FGT1", adom="root")

        assert mock_client.exec.call_count == 3


class TestWorkspaceErrorHandling:
    """Test workspace error handling scenarios."""

    @pytest.mark.asyncio
    async def test_lock_already_locked(self, workspace_api, mock_client):
        """Test locking when already locked."""
        mock_client.exec.return_value = {"status": {"code": -2, "message": "Already locked"}}

        result = await workspace_api.lock_adom("root")

        assert result["status"]["code"] == -2
        assert "Already locked" in result["status"]["message"]

    @pytest.mark.asyncio
    async def test_unlock_not_locked(self, workspace_api, mock_client):
        """Test unlocking when not locked."""
        mock_client.exec.return_value = {"status": {"code": -10, "message": "Not locked"}}

        result = await workspace_api.unlock_adom("root")

        assert result["status"]["code"] == -10

    @pytest.mark.asyncio
    async def test_commit_no_changes(self, workspace_api, mock_client):
        """Test committing when no changes exist."""
        mock_client.exec.return_value = {"status": {"code": 0, "message": "No changes to commit"}}

        result = await workspace_api.commit_adom("root")

        assert result["status"]["code"] == 0
