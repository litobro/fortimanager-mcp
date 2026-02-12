"""Unit tests for tools.policy_tools module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fortimanager_mcp.api.models import FirewallPolicy, PolicyPackage
from fortimanager_mcp.tools import policy_tools


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    client.move = AsyncMock()
    client.clone = AsyncMock()
    return client


@pytest.fixture
def mock_policy_api(mock_client):
    """Create mock PolicyAPI instance."""
    with patch('fortimanager_mcp.tools.policy_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.list_packages = AsyncMock()
        api.list_policies = AsyncMock()
        api.get_policy = AsyncMock()
        api.create_policy = AsyncMock()
        api.delete_policy = AsyncMock()
        api.move_policy = AsyncMock()
        api.clone_policy = AsyncMock()
        api.list_central_snat_policies = AsyncMock()
        api.get_central_snat_policy = AsyncMock()
        api.create_central_snat_policy = AsyncMock()
        api.delete_central_snat_policy = AsyncMock()
        api.list_central_dnat_policies = AsyncMock()
        api.get_central_dnat_policy = AsyncMock()
        api.create_central_dnat_policy = AsyncMock()
        api.delete_central_dnat_policy = AsyncMock()
        api.create_policy_folder = AsyncMock()
        api.move_package_to_folder = AsyncMock()
        
        with patch('fortimanager_mcp.tools.policy_tools.PolicyAPI', return_value=api):
            yield api


@pytest.fixture
def mock_installation_api(mock_client):
    """Create mock InstallationAPI instance."""
    with patch('fortimanager_mcp.tools.policy_tools.get_fmg_client') as mock_get_client:
        mock_get_client.return_value = mock_client
        api = MagicMock()
        api.install_policy_package = AsyncMock()
        
        with patch('fortimanager_mcp.tools.policy_tools.InstallationAPI', return_value=api):
            yield api


class TestListPolicyPackages:
    """Test list_policy_packages tool."""

    @pytest.mark.asyncio
    async def test_list_policy_packages_success(self, mock_policy_api):
        """Test listing policy packages successfully."""
        pkg1 = PolicyPackage(name="default", type="pkg", scope_member=["FGT-01"])
        pkg2 = PolicyPackage(name="branch", type="pkg", scope_member=["FGT-02"])
        mock_policy_api.list_packages.return_value = [pkg1, pkg2]

        result = await policy_tools.list_policy_packages(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["packages"]) == 2
        assert result["packages"][0]["name"] == "default"
        assert result["packages"][1]["name"] == "branch"
        mock_policy_api.list_packages.assert_called_once_with(adom="root")

    @pytest.mark.asyncio
    async def test_list_policy_packages_error(self, mock_policy_api):
        """Test listing policy packages with error."""
        mock_policy_api.list_packages.side_effect = Exception("API Error")

        result = await policy_tools.list_policy_packages(adom="root")

        assert result["status"] == "error"
        assert "API Error" in result["message"]


class TestListFirewallPolicies:
    """Test list_firewall_policies tool."""

    @pytest.mark.asyncio
    async def test_list_firewall_policies_success(self, mock_policy_api):
        """Test listing firewall policies successfully."""
        policy1 = FirewallPolicy(
            policyid=1,
            name="Allow-Web",
            srcintf=["port1"],
            dstintf=["port2"],
            srcaddr=["all"],
            dstaddr=["webserver"],
            service=["HTTP"],
            action="accept",
            status="enable",
        )
        policy2 = FirewallPolicy(
            policyid=2,
            name="Block-All",
            srcintf=["any"],
            dstintf=["any"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["ALL"],
            action="deny",
            status="enable",
        )
        mock_policy_api.list_policies.return_value = [policy1, policy2]

        result = await policy_tools.list_firewall_policies(
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        assert len(result["policies"]) == 2
        assert result["policies"][0]["policy_id"] == 1
        assert result["policies"][0]["name"] == "Allow-Web"
        assert result["policies"][1]["policy_id"] == 2
        mock_policy_api.list_policies.assert_called_once_with(
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_list_firewall_policies_error(self, mock_policy_api):
        """Test listing firewall policies with error."""
        mock_policy_api.list_policies.side_effect = Exception("Package not found")

        result = await policy_tools.list_firewall_policies(
            package="invalid",
            adom="root"
        )

        assert result["status"] == "error"
        assert "Package not found" in result["message"]


class TestGetFirewallPolicy:
    """Test get_firewall_policy tool."""

    @pytest.mark.asyncio
    async def test_get_firewall_policy_success(self, mock_policy_api):
        """Test getting firewall policy successfully."""
        policy = FirewallPolicy(
            policyid=1,
            name="Allow-Web",
            srcintf=["port1"],
            dstintf=["port2"],
            srcaddr=["internal-net"],
            dstaddr=["webserver"],
            service=["HTTP", "HTTPS"],
            action="accept",
            status="enable",
            comments="Allow web traffic",
        )
        mock_policy_api.get_policy.return_value = policy

        result = await policy_tools.get_firewall_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["policy"]["policy_id"] == 1
        assert result["policy"]["name"] == "Allow-Web"
        assert result["policy"]["action"] == "accept"
        mock_policy_api.get_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_get_firewall_policy_error(self, mock_policy_api):
        """Test getting firewall policy with error."""
        mock_policy_api.get_policy.side_effect = Exception("Policy not found")

        result = await policy_tools.get_firewall_policy(
            policy_id=999,
            package="default",
            adom="root"
        )

        assert result["status"] == "error"
        assert "Policy not found" in result["message"]


class TestCreateFirewallPolicy:
    """Test create_firewall_policy tool."""

    @pytest.mark.asyncio
    async def test_create_firewall_policy_success(self, mock_policy_api):
        """Test creating firewall policy successfully."""
        mock_policy_api.create_policy.return_value = {"policyid": 10}

        result = await policy_tools.create_firewall_policy(
            name="New-Policy",
            source_interface=["port1"],
            destination_interface=["port2"],
            source_address=["internal-net"],
            destination_address=["internet"],
            service=["HTTP"],
            action="accept",
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert "policy_id" in result
        mock_policy_api.create_policy.assert_called_once()
        call_kwargs = mock_policy_api.create_policy.call_args.kwargs
        assert call_kwargs["name"] == "New-Policy"
        assert call_kwargs["package"] == "default"
        assert call_kwargs["adom"] == "root"

    @pytest.mark.asyncio
    async def test_create_firewall_policy_error(self, mock_policy_api):
        """Test creating firewall policy with error."""
        mock_policy_api.create_policy.side_effect = Exception("Create failed")

        result = await policy_tools.create_firewall_policy(
            name="New-Policy",
            source_interface=["port1"],
            destination_interface=["port2"],
            source_address=["all"],
            destination_address=["all"],
            service=["ALL"],
            action="accept",
            package="default"
        )

        assert result["status"] == "error"
        assert "Create failed" in result["message"]


class TestDeleteFirewallPolicy:
    """Test delete_firewall_policy tool."""

    @pytest.mark.asyncio
    async def test_delete_firewall_policy_success(self, mock_policy_api):
        """Test deleting firewall policy successfully."""
        mock_policy_api.delete_policy.return_value = {"status": "success"}

        result = await policy_tools.delete_firewall_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.delete_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_delete_firewall_policy_error(self, mock_policy_api):
        """Test deleting firewall policy with error."""
        mock_policy_api.delete_policy.side_effect = Exception("Delete failed")

        result = await policy_tools.delete_firewall_policy(
            policy_id=1,
            package="default"
        )

        assert result["status"] == "error"
        assert "Delete failed" in result["message"]


class TestInstallPolicyPackage:
    """Test install_policy_package tool."""

    @pytest.mark.asyncio
    async def test_install_policy_package_success(self, mock_installation_api):
        """Test installing policy package successfully."""
        mock_installation_api.install_policy_package.return_value = {"task_id": 123}

        result = await policy_tools.install_policy_package(
            package="default",
            scope=["FGT-01"],
            adom="root"
        )

        assert result["status"] == "success"
        assert "task_id" in result
        mock_installation_api.install_policy_package.assert_called_once()

    @pytest.mark.asyncio
    async def test_install_policy_package_error(self, mock_installation_api):
        """Test installing policy package with error."""
        mock_installation_api.install_policy_package.side_effect = Exception("Install failed")

        result = await policy_tools.install_policy_package(
            package="default",
            scope=["FGT-01"]
        )

        assert result["status"] == "error"
        assert "Install failed" in result["message"]


class TestMoveFirewallPolicy:
    """Test move_firewall_policy tool."""

    @pytest.mark.asyncio
    async def test_move_firewall_policy_success(self, mock_policy_api):
        """Test moving firewall policy successfully."""
        mock_policy_api.move_policy.return_value = {"status": "success"}

        result = await policy_tools.move_firewall_policy(
            policy_id=1,
            package="default",
            position="after",
            reference_id=5,
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.move_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            position="after",
            reference_id=5,
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_move_firewall_policy_error(self, mock_policy_api):
        """Test moving firewall policy with error."""
        mock_policy_api.move_policy.side_effect = Exception("Move failed")

        result = await policy_tools.move_firewall_policy(
            policy_id=1,
            package="default",
            position="before",
            reference_id=3
        )

        assert result["status"] == "error"
        assert "Move failed" in result["message"]


class TestCloneFirewallPolicy:
    """Test clone_firewall_policy tool."""

    @pytest.mark.asyncio
    async def test_clone_firewall_policy_success(self, mock_policy_api):
        """Test cloning firewall policy successfully."""
        mock_policy_api.clone_policy.return_value = {"policyid": 20}

        result = await policy_tools.clone_firewall_policy(
            policy_id=1,
            new_name="Cloned-Policy",
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert "new_policy_id" in result
        mock_policy_api.clone_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_clone_firewall_policy_error(self, mock_policy_api):
        """Test cloning firewall policy with error."""
        mock_policy_api.clone_policy.side_effect = Exception("Clone failed")

        result = await policy_tools.clone_firewall_policy(
            policy_id=1,
            new_name="Cloned-Policy",
            package="default"
        )

        assert result["status"] == "error"
        assert "Clone failed" in result["message"]


class TestCentralSnatPolicies:
    """Test central SNAT policy tools."""

    @pytest.mark.asyncio
    async def test_list_central_snat_policies_success(self, mock_policy_api):
        """Test listing central SNAT policies successfully."""
        mock_policy_api.list_central_snat_policies.return_value = [
            {"policyid": 1, "name": "SNAT-1"},
            {"policyid": 2, "name": "SNAT-2"}
        ]

        result = await policy_tools.list_central_snat_policies(
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_policy_api.list_central_snat_policies.assert_called_once_with(
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_get_central_snat_policy_success(self, mock_policy_api):
        """Test getting central SNAT policy successfully."""
        mock_policy_api.get_central_snat_policy.return_value = {
            "policyid": 1,
            "name": "SNAT-1"
        }

        result = await policy_tools.get_central_snat_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["policy"]["policyid"] == 1
        mock_policy_api.get_central_snat_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_create_central_snat_policy_success(self, mock_policy_api):
        """Test creating central SNAT policy successfully."""
        mock_policy_api.create_central_snat_policy.return_value = {"policyid": 10}

        result = await policy_tools.create_central_snat_policy(
            name="New-SNAT",
            source_interface=["port1"],
            destination_interface=["port2"],
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.create_central_snat_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_central_snat_policy_success(self, mock_policy_api):
        """Test deleting central SNAT policy successfully."""
        mock_policy_api.delete_central_snat_policy.return_value = {"status": "success"}

        result = await policy_tools.delete_central_snat_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.delete_central_snat_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )


class TestCentralDnatPolicies:
    """Test central DNAT policy tools."""

    @pytest.mark.asyncio
    async def test_list_central_dnat_policies_success(self, mock_policy_api):
        """Test listing central DNAT policies successfully."""
        mock_policy_api.list_central_dnat_policies.return_value = [
            {"policyid": 1, "name": "DNAT-1"},
            {"policyid": 2, "name": "DNAT-2"}
        ]

        result = await policy_tools.list_central_dnat_policies(
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["count"] == 2
        mock_policy_api.list_central_dnat_policies.assert_called_once_with(
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_get_central_dnat_policy_success(self, mock_policy_api):
        """Test getting central DNAT policy successfully."""
        mock_policy_api.get_central_dnat_policy.return_value = {
            "policyid": 1,
            "name": "DNAT-1"
        }

        result = await policy_tools.get_central_dnat_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        assert result["policy"]["policyid"] == 1
        mock_policy_api.get_central_dnat_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )

    @pytest.mark.asyncio
    async def test_create_central_dnat_policy_success(self, mock_policy_api):
        """Test creating central DNAT policy successfully."""
        mock_policy_api.create_central_dnat_policy.return_value = {"policyid": 10}

        result = await policy_tools.create_central_dnat_policy(
            name="New-DNAT",
            source_interface=["port1"],
            destination_interface=["port2"],
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.create_central_dnat_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_central_dnat_policy_success(self, mock_policy_api):
        """Test deleting central DNAT policy successfully."""
        mock_policy_api.delete_central_dnat_policy.return_value = {"status": "success"}

        result = await policy_tools.delete_central_dnat_policy(
            policy_id=1,
            package="default",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.delete_central_dnat_policy.assert_called_once_with(
            policy_id=1,
            package="default",
            adom="root"
        )


class TestPolicyFolder:
    """Test policy folder tools."""

    @pytest.mark.asyncio
    async def test_create_policy_folder_success(self, mock_policy_api):
        """Test creating policy folder successfully."""
        mock_policy_api.create_policy_folder.return_value = {"status": "success"}

        result = await policy_tools.create_policy_folder(
            name="Branch-Policies",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.create_policy_folder.assert_called_once()

    @pytest.mark.asyncio
    async def test_move_policy_package_to_folder_success(self, mock_policy_api):
        """Test moving policy package to folder successfully."""
        mock_policy_api.move_package_to_folder.return_value = {"status": "success"}

        result = await policy_tools.move_policy_package_to_folder(
            package="branch-pkg",
            folder="Branch-Policies",
            adom="root"
        )

        assert result["status"] == "success"
        mock_policy_api.move_package_to_folder.assert_called_once()


class TestGetPolicyApiError:
    """Test _get_policy_api error handling."""

    @pytest.mark.asyncio
    async def test_get_policy_api_no_client(self):
        """Test _get_policy_api with no client."""
        with patch('fortimanager_mcp.tools.policy_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                policy_tools._get_policy_api()

    @pytest.mark.asyncio
    async def test_get_installation_api_no_client(self):
        """Test _get_installation_api with no client."""
        with patch('fortimanager_mcp.tools.policy_tools.get_fmg_client', return_value=None):
            with pytest.raises(RuntimeError, match="FortiManager client not initialized"):
                policy_tools._get_installation_api()
