"""Unit tests for tools.provisioning_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.tools import provisioning_tools


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    client.clone = AsyncMock()
    return client


@pytest.fixture
def mock_provisioning_api(mock_client):
    """Create mock ProvisioningAPI instance."""
    with patch('fortimanager_mcp.tools.provisioning_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.list_cli_templates = AsyncMock()
        api.get_cli_template = AsyncMock()
        api.create_cli_template = AsyncMock()
        api.delete_cli_template = AsyncMock()
        api.update_cli_template = AsyncMock()
        api.assign_cli_template = AsyncMock()
        api.assign_prerun_cli_template = AsyncMock()
        api.unassign_cli_template = AsyncMock()
        api.get_cli_template_assigned_devices = AsyncMock()
        api.validate_cli_template = AsyncMock()
        api.list_cli_template_groups = AsyncMock()
        api.get_cli_template_group = AsyncMock()
        api.create_cli_template_group = AsyncMock()
        api.delete_cli_template_group = AsyncMock()
        api.add_template_to_group = AsyncMock()
        api.remove_template_from_group = AsyncMock()
        api.assign_cli_template_group = AsyncMock()
        api.unassign_cli_template_group = AsyncMock()
        api.get_cli_template_group_assigned_devices = AsyncMock()
        api.list_system_templates = AsyncMock()
        api.get_system_template = AsyncMock()
        api.create_system_template = AsyncMock()
        api.update_system_template = AsyncMock()
        api.delete_system_template = AsyncMock()
        api.clone_system_template = AsyncMock()
        api.assign_system_template = AsyncMock()
        api.unassign_system_template = AsyncMock()
        api.get_system_template_assigned_devices = AsyncMock()
        api.get_template_interface_actions = AsyncMock()
        
        with patch('fortimanager_mcp.tools.provisioning_tools.ProvisioningAPI', return_value=api):
            yield api


class TestListCliTemplates:
    """Test list_cli_templates tool."""

    @pytest.mark.asyncio
    async def test_list_cli_templates_success(self, mock_provisioning_api):
        """Test listing CLI templates successfully."""
        mock_provisioning_api.list_cli_templates.return_value = [
            {"name": "template1", "description": "First template"},
            {"name": "template2", "description": "Second template"}
        ]

        result = await provisioning_tools.list_cli_templates(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["templates"]) == 2
        mock_provisioning_api.list_cli_templates.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_cli_templates_empty(self, mock_provisioning_api):
        """Test listing CLI templates with empty result."""
        mock_provisioning_api.list_cli_templates.return_value = []

        result = await provisioning_tools.list_cli_templates()

        assert result["status"] == "success"
        assert result["count"] == 0
        assert len(result["templates"]) == 0


class TestGetCliTemplate:
    """Test get_cli_template tool."""

    @pytest.mark.asyncio
    async def test_get_cli_template_success(self, mock_provisioning_api):
        """Test getting CLI template successfully."""
        mock_provisioning_api.get_cli_template.return_value = {
            "name": "test_template",
            "script": "config system interface\nend",
            "description": "Test template"
        }

        result = await provisioning_tools.get_cli_template(
            name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["template"]["name"] == "test_template"
        mock_provisioning_api.get_cli_template.assert_called_once_with(
            name="test_template",
            adom="root"
        )


class TestCreateCliTemplate:
    """Test create_cli_template tool."""

    @pytest.mark.asyncio
    async def test_create_cli_template_success(self, mock_provisioning_api):
        """Test creating CLI template successfully."""
        mock_provisioning_api.create_cli_template.return_value = {"name": "new_template"}

        result = await provisioning_tools.create_cli_template(
            name="new_template",
            script="config system interface\nend",
            adom="root",
            description="New template"
        )

        assert result["status"] == "success"
        assert "template" in result
        mock_provisioning_api.create_cli_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_cli_template_minimal(self, mock_provisioning_api):
        """Test creating CLI template with minimal parameters."""
        mock_provisioning_api.create_cli_template.return_value = {"name": "minimal"}

        result = await provisioning_tools.create_cli_template(
            name="minimal",
            script="config system settings\nend"
        )

        assert result["status"] == "success"


class TestDeleteCliTemplate:
    """Test delete_cli_template tool."""

    @pytest.mark.asyncio
    async def test_delete_cli_template_success(self, mock_provisioning_api):
        """Test deleting CLI template successfully."""
        mock_provisioning_api.delete_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.delete_cli_template(
            name="old_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.delete_cli_template.assert_called_once_with(
            name="old_template",
            adom="root"
        )


class TestUpdateCliTemplate:
    """Test update_cli_template tool."""

    @pytest.mark.asyncio
    async def test_update_cli_template_success(self, mock_provisioning_api):
        """Test updating CLI template successfully."""
        mock_provisioning_api.update_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.update_cli_template(
            name="existing_template",
            script="config system interface\nend",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.update_cli_template.assert_called_once()


class TestAssignCliTemplate:
    """Test assign_cli_template tool."""

    @pytest.mark.asyncio
    async def test_assign_cli_template_success(self, mock_provisioning_api):
        """Test assigning CLI template successfully."""
        mock_provisioning_api.assign_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.assign_cli_template(
            template_name="test_template",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.assign_cli_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_cli_template_with_vdom(self, mock_provisioning_api):
        """Test assigning CLI template with VDOM."""
        mock_provisioning_api.assign_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.assign_cli_template(
            template_name="test_template",
            device_name="FGT-01",
            adom="root",
            vdom="vdom1"
        )

        assert result["status"] == "success"


class TestAssignPrerunCliTemplate:
    """Test assign_prerun_cli_template tool."""

    @pytest.mark.asyncio
    async def test_assign_prerun_cli_template_success(self, mock_provisioning_api):
        """Test assigning prerun CLI template successfully."""
        mock_provisioning_api.assign_prerun_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.assign_prerun_cli_template(
            template_name="prerun_template",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.assign_prerun_cli_template.assert_called_once()


class TestUnassignCliTemplate:
    """Test unassign_cli_template tool."""

    @pytest.mark.asyncio
    async def test_unassign_cli_template_success(self, mock_provisioning_api):
        """Test unassigning CLI template successfully."""
        mock_provisioning_api.unassign_cli_template.return_value = {"status": "success"}

        result = await provisioning_tools.unassign_cli_template(
            template_name="test_template",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.unassign_cli_template.assert_called_once()


class TestGetCliTemplateAssignedDevices:
    """Test get_cli_template_assigned_devices tool."""

    @pytest.mark.asyncio
    async def test_get_cli_template_assigned_devices_success(self, mock_provisioning_api):
        """Test getting CLI template assigned devices successfully."""
        mock_provisioning_api.get_cli_template_assigned_devices.return_value = [
            {"name": "FGT-01"},
            {"name": "FGT-02"}
        ]

        result = await provisioning_tools.get_cli_template_assigned_devices(
            template_name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_provisioning_api.get_cli_template_assigned_devices.assert_called_once()


class TestValidateCliTemplate:
    """Test validate_cli_template tool."""

    @pytest.mark.asyncio
    async def test_validate_cli_template_success(self, mock_provisioning_api):
        """Test validating CLI template successfully."""
        mock_provisioning_api.validate_cli_template.return_value = {
            "valid": True,
            "errors": []
        }

        result = await provisioning_tools.validate_cli_template(
            name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert "validation" in result
        mock_provisioning_api.validate_cli_template.assert_called_once()


class TestCliTemplateGroups:
    """Test CLI template group tools."""

    @pytest.mark.asyncio
    async def test_list_cli_template_groups_success(self, mock_provisioning_api):
        """Test listing CLI template groups successfully."""
        mock_provisioning_api.list_cli_template_groups.return_value = [
            {"name": "group1"},
            {"name": "group2"}
        ]

        result = await provisioning_tools.list_cli_template_groups(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_provisioning_api.list_cli_template_groups.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_cli_template_group_success(self, mock_provisioning_api):
        """Test getting CLI template group successfully."""
        mock_provisioning_api.get_cli_template_group.return_value = {
            "name": "test_group",
            "members": ["template1", "template2"]
        }

        result = await provisioning_tools.get_cli_template_group(
            name="test_group",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["group"]["name"] == "test_group"
        mock_provisioning_api.get_cli_template_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_cli_template_group_success(self, mock_provisioning_api):
        """Test creating CLI template group successfully."""
        mock_provisioning_api.create_cli_template_group.return_value = {"name": "new_group"}

        result = await provisioning_tools.create_cli_template_group(
            name="new_group",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.create_cli_template_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_cli_template_group_success(self, mock_provisioning_api):
        """Test deleting CLI template group successfully."""
        mock_provisioning_api.delete_cli_template_group.return_value = {"status": "success"}

        result = await provisioning_tools.delete_cli_template_group(
            name="old_group",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.delete_cli_template_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_template_to_group_success(self, mock_provisioning_api):
        """Test adding template to group successfully."""
        mock_provisioning_api.add_template_to_group.return_value = {"status": "success"}

        result = await provisioning_tools.add_template_to_group(
            group_name="test_group",
            template_name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.add_template_to_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_template_from_group_success(self, mock_provisioning_api):
        """Test removing template from group successfully."""
        mock_provisioning_api.remove_template_from_group.return_value = {"status": "success"}

        result = await provisioning_tools.remove_template_from_group(
            group_name="test_group",
            template_name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.remove_template_from_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_cli_template_group_success(self, mock_provisioning_api):
        """Test assigning CLI template group successfully."""
        mock_provisioning_api.assign_cli_template_group.return_value = {"status": "success"}

        result = await provisioning_tools.assign_cli_template_group(
            group_name="test_group",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.assign_cli_template_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_unassign_cli_template_group_success(self, mock_provisioning_api):
        """Test unassigning CLI template group successfully."""
        mock_provisioning_api.unassign_cli_template_group.return_value = {"status": "success"}

        result = await provisioning_tools.unassign_cli_template_group(
            group_name="test_group",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.unassign_cli_template_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cli_template_group_assigned_devices_success(self, mock_provisioning_api):
        """Test getting CLI template group assigned devices successfully."""
        mock_provisioning_api.get_cli_template_group_assigned_devices.return_value = [
            {"name": "FGT-01"}
        ]

        result = await provisioning_tools.get_cli_template_group_assigned_devices(
            group_name="test_group",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_provisioning_api.get_cli_template_group_assigned_devices.assert_called_once()


class TestSystemTemplates:
    """Test system template tools."""

    @pytest.mark.asyncio
    async def test_list_system_templates_success(self, mock_provisioning_api):
        """Test listing system templates successfully."""
        mock_provisioning_api.list_system_templates.return_value = [
            {"name": "template1"},
            {"name": "template2"}
        ]

        result = await provisioning_tools.list_system_templates(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_provisioning_api.list_system_templates.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_get_system_template_success(self, mock_provisioning_api):
        """Test getting system template successfully."""
        mock_provisioning_api.get_system_template.return_value = {
            "name": "test_template",
            "description": "Test system template"
        }

        result = await provisioning_tools.get_system_template(
            name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["template"]["name"] == "test_template"
        mock_provisioning_api.get_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_system_template_success(self, mock_provisioning_api):
        """Test creating system template successfully."""
        mock_provisioning_api.create_system_template.return_value = {"name": "new_sys_template"}

        result = await provisioning_tools.create_system_template(
            name="new_sys_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.create_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_system_template_success(self, mock_provisioning_api):
        """Test updating system template successfully."""
        mock_provisioning_api.update_system_template.return_value = {"status": "success"}

        result = await provisioning_tools.update_system_template(
            name="existing_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.update_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_system_template_success(self, mock_provisioning_api):
        """Test deleting system template successfully."""
        mock_provisioning_api.delete_system_template.return_value = {"status": "success"}

        result = await provisioning_tools.delete_system_template(
            name="old_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.delete_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_clone_system_template_success(self, mock_provisioning_api):
        """Test cloning system template successfully."""
        mock_provisioning_api.clone_system_template.return_value = {"name": "cloned_template"}

        result = await provisioning_tools.clone_system_template(
            source_name="source_template",
            new_name="cloned_template",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.clone_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_system_template_success(self, mock_provisioning_api):
        """Test assigning system template successfully."""
        mock_provisioning_api.assign_system_template.return_value = {"status": "success"}

        result = await provisioning_tools.assign_system_template(
            template_name="test_template",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.assign_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_unassign_system_template_success(self, mock_provisioning_api):
        """Test unassigning system template successfully."""
        mock_provisioning_api.unassign_system_template.return_value = {"status": "success"}

        result = await provisioning_tools.unassign_system_template(
            template_name="test_template",
            device_name="FGT-01",
            adom="root"
        )

        assert result["status"] == "success"
        mock_provisioning_api.unassign_system_template.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_system_template_assigned_devices_success(self, mock_provisioning_api):
        """Test getting system template assigned devices successfully."""
        mock_provisioning_api.get_system_template_assigned_devices.return_value = [
            {"name": "FGT-01"}
        ]

        result = await provisioning_tools.get_system_template_assigned_devices(
            template_name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_provisioning_api.get_system_template_assigned_devices.assert_called_once()


class TestGetTemplateInterfaceActions:
    """Test get_template_interface_actions tool."""

    @pytest.mark.asyncio
    async def test_get_template_interface_actions_success(self, mock_provisioning_api):
        """Test getting template interface actions successfully."""
        mock_provisioning_api.get_template_interface_actions.return_value = {
            "actions": ["add", "modify", "delete"]
        }

        result = await provisioning_tools.get_template_interface_actions(
            template_name="test_template",
            adom="root"
        )

        assert result["status"] == "success"
        assert "actions" in result
        mock_provisioning_api.get_template_interface_actions.assert_called_once()


class TestGetProvisioningApiError:
    """Test _get_provisioning_api error handling."""

    @pytest.mark.asyncio
    async def test_get_provisioning_api_no_client(self):
        """Test _get_provisioning_api with no client."""
        with patch('fortimanager_mcp.tools.provisioning_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                provisioning_tools._get_provisioning_api()
