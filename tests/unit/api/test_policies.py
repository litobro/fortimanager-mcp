"""Unit tests for api.policies module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.policies import PolicyAPI
from fortimanager_mcp.api.models import FirewallPolicy, PolicyPackage


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
    client.move = AsyncMock()
    client.clone = AsyncMock()
    return client


@pytest.fixture
def policy_api(mock_client):
    """Create PolicyAPI instance with mock client."""
    return PolicyAPI(mock_client)


class TestPolicyAPIInit:
    """Test PolicyAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = PolicyAPI(mock_client)
        assert api.client == mock_client


class TestListPackages:
    """Test listing policy packages."""

    @pytest.mark.asyncio
    async def test_list_packages_success(self, policy_api, mock_client):
        """Test listing packages successfully."""
        mock_data = [
            {
                "name": "default",
                "type": "pkg",
                "oid": 1234,
            },
            {
                "name": "test-pkg",
                "type": "pkg",
                "oid": 5678,
            },
        ]
        mock_client.get.return_value = mock_data

        result = await policy_api.list_packages(adom="root")

        assert len(result) == 2
        assert all(isinstance(pkg, PolicyPackage) for pkg in result)
        assert result[0].name == "default"
        assert result[1].name == "test-pkg"
        mock_client.get.assert_called_once_with(
            "/pm/pkg/adom/root",
            fields=None,
        )

    @pytest.mark.asyncio
    async def test_list_packages_with_fields(self, policy_api, mock_client):
        """Test listing packages with specific fields."""
        mock_data = [{"name": "default"}]
        mock_client.get.return_value = mock_data

        await policy_api.list_packages(adom="test-adom", fields=["name", "type"])

        mock_client.get.assert_called_once_with(
            "/pm/pkg/adom/test-adom",
            fields=["name", "type"],
        )

    @pytest.mark.asyncio
    async def test_list_packages_single_result(self, policy_api, mock_client):
        """Test listing packages with single result."""
        mock_data = {"name": "default", "type": "pkg"}
        mock_client.get.return_value = mock_data

        result = await policy_api.list_packages()

        assert len(result) == 1
        assert result[0].name == "default"

    @pytest.mark.asyncio
    async def test_list_packages_empty(self, policy_api, mock_client):
        """Test listing packages with empty result."""
        mock_client.get.return_value = None

        result = await policy_api.list_packages()

        assert len(result) == 0


class TestGetPackage:
    """Test getting a specific policy package."""

    @pytest.mark.asyncio
    async def test_get_package_success(self, policy_api, mock_client):
        """Test getting package successfully."""
        mock_data = {
            "name": "test-pkg",
            "type": "pkg",
            "oid": 1234,
        }
        mock_client.get.return_value = mock_data

        result = await policy_api.get_package("test-pkg", adom="root")

        assert isinstance(result, PolicyPackage)
        assert result.name == "test-pkg"
        mock_client.get.assert_called_once_with("/pm/pkg/adom/root/test-pkg")

    @pytest.mark.asyncio
    async def test_get_package_different_adom(self, policy_api, mock_client):
        """Test getting package from different ADOM."""
        mock_data = {"name": "pkg", "type": "pkg"}
        mock_client.get.return_value = mock_data

        await policy_api.get_package("pkg", adom="custom")

        mock_client.get.assert_called_once_with("/pm/pkg/adom/custom/pkg")


class TestCreatePackage:
    """Test creating policy packages."""

    @pytest.mark.asyncio
    async def test_create_package_success(self, policy_api, mock_client):
        """Test creating package successfully."""
        mock_client.add.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {
            "name": "new-pkg",
            "type": "pkg",
        }

        result = await policy_api.create_package("new-pkg", adom="root")

        assert isinstance(result, PolicyPackage)
        assert result.name == "new-pkg"
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/pkg/adom/root"
        assert call_args[1]["data"]["name"] == "new-pkg"
        assert call_args[1]["data"]["type"] == "pkg"

    @pytest.mark.asyncio
    async def test_create_package_with_kwargs(self, policy_api, mock_client):
        """Test creating package with additional parameters."""
        mock_client.add.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {"name": "pkg", "type": "pkg"}

        await policy_api.create_package(
            "pkg", adom="root", scope_member=[{"name": "FGT1"}]
        )

        call_args = mock_client.add.call_args
        assert "scope_member" in call_args[1]["data"]


class TestDeletePackage:
    """Test deleting policy packages."""

    @pytest.mark.asyncio
    async def test_delete_package_success(self, policy_api, mock_client):
        """Test deleting package successfully."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_package("test-pkg", adom="root")

        mock_client.delete.assert_called_once_with("/pm/pkg/adom/root/test-pkg")

    @pytest.mark.asyncio
    async def test_delete_package_different_adom(self, policy_api, mock_client):
        """Test deleting package from different ADOM."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_package("pkg", adom="test")

        mock_client.delete.assert_called_once_with("/pm/pkg/adom/test/pkg")


class TestListPolicies:
    """Test listing firewall policies."""

    @pytest.mark.asyncio
    async def test_list_policies_success(self, policy_api, mock_client):
        """Test listing policies successfully."""
        mock_data = [
            {
                "policyid": 1,
                "name": "Allow-Web",
                "action": "accept",
                "srcintf": ["port1"],
                "dstintf": ["port2"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["HTTP"],
            },
            {
                "policyid": 2,
                "name": "Deny-All",
                "action": "deny",
                "srcintf": ["any"],
                "dstintf": ["any"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
            },
        ]
        mock_client.get.return_value = mock_data

        result = await policy_api.list_policies("default", adom="root")

        assert len(result) == 2
        assert all(isinstance(policy, FirewallPolicy) for policy in result)
        assert result[0].policyid == 1
        assert result[1].policyid == 2
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/policy",
            fields=None,
            filter=None,
        )

    @pytest.mark.asyncio
    async def test_list_policies_with_filter(self, policy_api, mock_client):
        """Test listing policies with filter."""
        mock_data = [{"policyid": 1, "action": "accept"}]
        mock_client.get.return_value = mock_data

        filter_criteria = ["action", "==", "accept"]
        await policy_api.list_policies("pkg", filter=filter_criteria)

        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        assert call_args[1]["filter"] == filter_criteria

    @pytest.mark.asyncio
    async def test_list_policies_single_result(self, policy_api, mock_client):
        """Test listing policies with single result."""
        mock_data = {"policyid": 1, "action": "accept"}
        mock_client.get.return_value = mock_data

        result = await policy_api.list_policies("pkg")

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_policies_empty(self, policy_api, mock_client):
        """Test listing policies with empty result."""
        mock_client.get.return_value = None

        result = await policy_api.list_policies("pkg")

        assert len(result) == 0


class TestGetPolicy:
    """Test getting a specific firewall policy."""

    @pytest.mark.asyncio
    async def test_get_policy_success(self, policy_api, mock_client):
        """Test getting policy successfully."""
        mock_data = {
            "policyid": 1,
            "name": "Test-Policy",
            "action": "accept",
        }
        mock_client.get.return_value = mock_data

        result = await policy_api.get_policy(1, "default", adom="root")

        assert isinstance(result, FirewallPolicy)
        assert result.policyid == 1
        assert result.name == "Test-Policy"
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/policy/1"
        )

    @pytest.mark.asyncio
    async def test_get_policy_different_adom(self, policy_api, mock_client):
        """Test getting policy from different ADOM."""
        mock_data = {"policyid": 5, "action": "deny"}
        mock_client.get.return_value = mock_data

        await policy_api.get_policy(5, "pkg", adom="test")

        mock_client.get.assert_called_once_with(
            "/pm/config/adom/test/pkg/pkg/firewall/policy/5"
        )


class TestCreatePolicy:
    """Test creating firewall policies."""

    @pytest.mark.asyncio
    async def test_create_policy_success_with_policyid(self, policy_api, mock_client):
        """Test creating policy successfully with policyid in result."""
        mock_client.add.return_value = {"policyid": 10}
        mock_client.get.return_value = {
            "policyid": 10,
            "action": "accept",
            "srcintf": ["port1"],
            "dstintf": ["port2"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["HTTP"],
        }

        result = await policy_api.create_policy(
            package="default",
            srcintf=["port1"],
            dstintf=["port2"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["HTTP"],
            adom="root",
        )

        assert isinstance(result, FirewallPolicy)
        assert result.policyid == 10
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/pkg/default/firewall/policy"
        assert call_args[1]["data"]["action"] == "accept"
        assert call_args[1]["data"]["schedule"] == "always"
        assert call_args[1]["data"]["status"] == "enable"

    @pytest.mark.asyncio
    async def test_create_policy_without_policyid(self, policy_api, mock_client):
        """Test creating policy when policyid not in result."""
        mock_client.add.return_value = {"status": {"code": 0}}
        mock_client.get.side_effect = [
            # First call - list_policies
            [
                {"policyid": 1, "action": "accept"},
                {"policyid": 2, "action": "deny"},
            ]
        ]

        result = await policy_api.create_policy(
            package="pkg",
            srcintf=["any"],
            dstintf=["any"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["ALL"],
        )

        assert isinstance(result, FirewallPolicy)
        assert result.policyid == 2

    @pytest.mark.asyncio
    async def test_create_policy_with_name(self, policy_api, mock_client):
        """Test creating policy with name."""
        mock_client.add.return_value = {"policyid": 5}
        mock_client.get.return_value = {
            "policyid": 5,
            "name": "Custom-Policy",
            "action": "accept",
        }

        await policy_api.create_policy(
            package="pkg",
            srcintf=["port1"],
            dstintf=["port2"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["HTTPS"],
            name="Custom-Policy",
        )

        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["name"] == "Custom-Policy"

    @pytest.mark.asyncio
    async def test_create_policy_with_kwargs(self, policy_api, mock_client):
        """Test creating policy with additional parameters."""
        mock_client.add.return_value = {"policyid": 1}
        mock_client.get.return_value = {"policyid": 1, "action": "accept"}

        await policy_api.create_policy(
            package="pkg",
            srcintf=["port1"],
            dstintf=["port2"],
            srcaddr=["all"],
            dstaddr=["all"],
            service=["HTTP"],
            logtraffic="all",
            nat="enable",
        )

        call_args = mock_client.add.call_args
        assert call_args[1]["data"]["logtraffic"] == "all"
        assert call_args[1]["data"]["nat"] == "enable"

    @pytest.mark.asyncio
    async def test_create_policy_failure(self, policy_api, mock_client):
        """Test creating policy failure."""
        mock_client.add.return_value = {"status": {"code": 0}}
        mock_client.get.side_effect = [
            []  # Empty list - no policies
        ]

        with pytest.raises(ValueError, match="Failed to get created policy"):
            await policy_api.create_policy(
                package="pkg",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["HTTP"],
            )


class TestUpdatePolicy:
    """Test updating firewall policies."""

    @pytest.mark.asyncio
    async def test_update_policy_success(self, policy_api, mock_client):
        """Test updating policy successfully."""
        mock_client.set.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {
            "policyid": 1,
            "action": "deny",
            "name": "Updated-Policy",
        }

        result = await policy_api.update_policy(
            1, "default", adom="root", action="deny", name="Updated-Policy"
        )

        assert isinstance(result, FirewallPolicy)
        assert result.policyid == 1
        mock_client.set.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/policy/1",
            data={"action": "deny", "name": "Updated-Policy"},
        )

    @pytest.mark.asyncio
    async def test_update_policy_different_adom(self, policy_api, mock_client):
        """Test updating policy in different ADOM."""
        mock_client.set.return_value = {"status": {"code": 0}}
        mock_client.get.return_value = {"policyid": 2, "action": "accept"}

        await policy_api.update_policy(2, "pkg", adom="test", logtraffic="all")

        mock_client.set.assert_called_once()
        call_args = mock_client.set.call_args
        assert "/adom/test/" in call_args[0][0]


class TestDeletePolicy:
    """Test deleting firewall policies."""

    @pytest.mark.asyncio
    async def test_delete_policy_success(self, policy_api, mock_client):
        """Test deleting policy successfully."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_policy(1, "default", adom="root")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/policy/1"
        )

    @pytest.mark.asyncio
    async def test_delete_policy_different_adom(self, policy_api, mock_client):
        """Test deleting policy from different ADOM."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_policy(5, "pkg", adom="test")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/test/pkg/pkg/firewall/policy/5"
        )


class TestMovePolicy:
    """Test moving/reordering firewall policies."""

    @pytest.mark.asyncio
    async def test_move_policy_after(self, policy_api, mock_client):
        """Test moving policy after another."""
        mock_client.move.return_value = {"status": {"code": 0}}

        await policy_api.move_policy(1, "default", target=5, option="after", adom="root")

        mock_client.move.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/policy/1",
            data={"option": "after", "target": 5},
        )

    @pytest.mark.asyncio
    async def test_move_policy_before(self, policy_api, mock_client):
        """Test moving policy before another."""
        mock_client.move.return_value = {"status": {"code": 0}}

        await policy_api.move_policy(2, "pkg", target=1, option="before")

        mock_client.move.assert_called_once()
        call_args = mock_client.move.call_args
        assert call_args[1]["data"]["option"] == "before"
        assert call_args[1]["data"]["target"] == 1


class TestClonePolicy:
    """Test cloning firewall policies."""

    @pytest.mark.asyncio
    async def test_clone_policy_success(self, policy_api, mock_client):
        """Test cloning policy successfully."""
        # Mock the get call for original policy
        mock_client.get.side_effect = [
            {
                "policyid": 1,
                "name": "Original-Policy",
                "action": "accept",
                "srcintf": ["port1"],
                "dstintf": ["port2"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["HTTP"],
            },
            # Mock the get call for cloned policy
            {
                "policyid": 10,
                "name": "Cloned-Policy",
                "action": "accept",
            },
        ]
        mock_client.add.return_value = {"policyid": 10}

        result = await policy_api.clone_policy(
            1, "default", new_name="Cloned-Policy", adom="root"
        )

        assert isinstance(result, FirewallPolicy)
        assert result.policyid == 10
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_clone_policy_without_policyid(self, policy_api, mock_client):
        """Test cloning policy when policyid not in result."""
        mock_client.get.side_effect = [
            # First call - get original policy
            {
                "policyid": 1,
                "name": "Original",
                "action": "accept",
                "srcintf": ["port1"],
                "dstintf": ["port2"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["HTTP"],
            },
            # Second call - list policies
            [{"policyid": 1, "action": "accept"}, {"policyid": 2, "action": "accept"}],
        ]
        mock_client.add.return_value = {"status": {"code": 0}}

        result = await policy_api.clone_policy(1, "pkg", new_name="Clone")

        assert result.policyid == 2


class TestCentralSNATPolicies:
    """Test central SNAT policy operations."""

    @pytest.mark.asyncio
    async def test_list_central_snat_policies(self, policy_api, mock_client):
        """Test listing central SNAT policies."""
        mock_data = [
            {"policyid": 1, "type": "snat"},
            {"policyid": 2, "type": "snat"},
        ]
        mock_client.get.return_value = mock_data

        result = await policy_api.list_central_snat_policies("default", adom="root")

        assert len(result) == 2
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/central-snat-map"
        )

    @pytest.mark.asyncio
    async def test_get_central_snat_policy(self, policy_api, mock_client):
        """Test getting central SNAT policy."""
        mock_data = {"policyid": 1, "type": "snat"}
        mock_client.get.return_value = mock_data

        result = await policy_api.get_central_snat_policy(1, "default", adom="root")

        assert result["policyid"] == 1
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/central-snat-map/1"
        )

    @pytest.mark.asyncio
    async def test_create_central_snat_policy(self, policy_api, mock_client):
        """Test creating central SNAT policy."""
        mock_client.add.return_value = {"status": {"code": 0}}

        await policy_api.create_central_snat_policy(
            package="default",
            srcintf=["port1"],
            dstintf=["port2"],
            orig_addr=["10.0.0.0/8"],
            nat_ippool=["POOL1"],
            adom="root",
        )

        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/pkg/default/firewall/central-snat-map"
        assert call_args[1]["data"]["orig-addr"] == ["10.0.0.0/8"]

    @pytest.mark.asyncio
    async def test_delete_central_snat_policy(self, policy_api, mock_client):
        """Test deleting central SNAT policy."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_central_snat_policy(1, "default", adom="root")

        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/pkg/default/firewall/central-snat-map/1"
        )


class TestCentralDNATPolicies:
    """Test central DNAT policy operations."""

    @pytest.mark.asyncio
    async def test_list_central_dnat_policies(self, policy_api, mock_client):
        """Test listing central DNAT policies."""
        mock_data = [{"policyid": 1}, {"policyid": 2}]
        mock_client.get.return_value = mock_data

        result = await policy_api.list_central_dnat_policies("default")

        assert len(result) == 2
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_central_dnat_policy(self, policy_api, mock_client):
        """Test getting central DNAT policy."""
        mock_data = {"policyid": 1}
        mock_client.get.return_value = mock_data

        result = await policy_api.get_central_dnat_policy(1, "default")

        assert result["policyid"] == 1

    @pytest.mark.asyncio
    async def test_create_central_dnat_policy(self, policy_api, mock_client):
        """Test creating central DNAT policy."""
        mock_client.add.return_value = {"status": {"code": 0}}

        await policy_api.create_central_dnat_policy(
            package="default",
            srcintf=["port1"],
            dstintf=["port2"],
            orig_addr=["0.0.0.0/0"],
            dst_addr=["VIP1"],
        )

        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_central_dnat_policy(self, policy_api, mock_client):
        """Test deleting central DNAT policy."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_central_dnat_policy(1, "default")

        mock_client.delete.assert_called_once()


class TestPolicyFolders:
    """Test policy folder operations."""

    @pytest.mark.asyncio
    async def test_create_policy_folder(self, policy_api, mock_client):
        """Test creating policy folder."""
        mock_client.add.return_value = {"status": {"code": 0}}

        result = await policy_api.create_policy_folder("test-folder", parent="", adom="root")

        assert result["name"] == "test-folder"
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert "pm/pkg/adom" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_move_package_to_folder(self, policy_api, mock_client):
        """Test moving package to folder."""
        mock_client.set.return_value = {"status": {"code": 0}}

        await policy_api.move_package_to_folder("pkg", "folder", adom="root")

        mock_client.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_policy_folder(self, policy_api, mock_client):
        """Test deleting policy folder."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_policy_folder("folder", adom="root")

        mock_client.delete.assert_called_once()


class TestPolicyBlocks:
    """Test policy block operations."""

    @pytest.mark.asyncio
    async def test_list_policy_blocks(self, policy_api, mock_client):
        """Test listing policy blocks."""
        mock_data = [{"name": "block1"}, {"name": "block2"}]
        mock_client.get.return_value = mock_data

        result = await policy_api.list_policy_blocks("default")

        assert len(result) == 2
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_policy_block(self, policy_api, mock_client):
        """Test getting policy block."""
        mock_data = {"name": "block1"}
        mock_client.get.return_value = mock_data

        result = await policy_api.get_policy_block("block1", "default")

        assert result["name"] == "block1"

    @pytest.mark.asyncio
    async def test_create_policy_block(self, policy_api, mock_client):
        """Test creating policy block."""
        mock_client.add.return_value = {"status": {"code": 0}}

        await policy_api.create_policy_block("new-block", "default")

        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_policy_block(self, policy_api, mock_client):
        """Test deleting policy block."""
        mock_client.delete.return_value = {"status": {"code": 0}}

        await policy_api.delete_policy_block("block1", "default")

        mock_client.delete.assert_called_once()


class TestPackageStatus:
    """Test package status operations."""

    @pytest.mark.asyncio
    async def test_get_package_status(self, policy_api, mock_client):
        """Test getting package status."""
        mock_data = {"status": "modified"}
        mock_client.get.return_value = mock_data

        result = await policy_api.get_package_status("default")

        assert result["status"] == "modified"
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_package_checksum(self, policy_api, mock_client):
        """Test getting package checksum."""
        mock_data = {"checksum": "abc123"}
        mock_client.execute.return_value = mock_data

        result = await policy_api.get_package_checksum("default")

        assert result["checksum"] == "abc123"
        mock_client.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_package_changes(self, policy_api, mock_client):
        """Test getting package changes."""
        mock_data = [{"type": "add"}]
        mock_client.get.return_value = mock_data

        result = await policy_api.get_package_changes("default")

        assert len(result) == 1
        assert result[0]["type"] == "add"


class TestPolicyHitcount:
    """Test policy hitcount operations."""

    @pytest.mark.asyncio
    async def test_get_policy_hitcount(self, policy_api, mock_client):
        """Test getting policy hitcount."""
        mock_data = {"hitcount": 1234}
        mock_client.execute.return_value = mock_data

        result = await policy_api.get_policy_hitcount("default", "FGT1")

        assert result["hitcount"] == 1234
        mock_client.execute.assert_called_once()


class TestRevertPackage:
    """Test reverting package operations."""

    @pytest.mark.asyncio
    async def test_revert_package(self, policy_api, mock_client):
        """Test reverting package."""
        mock_client.execute.return_value = {"status": {"code": 0}}

        await policy_api.revert_package("default", revision=1, adom="root")

        mock_client.execute.assert_called_once()


class TestAdvancedPolicyOperations:
    """Test advanced policy operations."""

    @pytest.mark.asyncio
    async def test_insert_policy_at_position(self, policy_api, mock_client):
        """Test inserting policy at position."""
        mock_client.add.return_value = {"policyid": 5}

        policy_data = {
            "srcintf": ["port1"],
            "dstintf": ["port2"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["HTTP"],
        }
        result = await policy_api.insert_policy_at_position(
            package="default",
            position=3,
            policy_data=policy_data,
        )

        assert result["policyid"] == 5
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_nth_policy(self, policy_api, mock_client):
        """Test getting Nth policy."""
        mock_data = [
            {"policyid": 1, "action": "accept"},
            {"policyid": 2, "action": "deny"},
            {"policyid": 3, "action": "accept"},
        ]
        mock_client.get.return_value = mock_data

        result = await policy_api.get_nth_policy("default", 1)

        assert isinstance(result, dict)
        assert result["policyid"] == 2


class TestPolicySections:
    """Test policy section operations."""

    @pytest.mark.asyncio
    async def test_create_policy_section(self, policy_api, mock_client):
        """Test creating policy section."""
        mock_client.add.return_value = {"status": {"code": 0}}

        await policy_api.create_policy_section("Section1", "default")

        mock_client.add.assert_called_once()


class TestImportExport:
    """Test import/export operations."""

    @pytest.mark.asyncio
    async def test_import_policy_configuration(self, policy_api, mock_client):
        """Test importing policy configuration."""
        mock_client.execute.return_value = {"status": {"code": 0}}

        config_data = "config firewall policy\n..."
        await policy_api.import_policy_configuration("default", config_data)

        mock_client.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_policy_configuration(self, policy_api, mock_client):
        """Test exporting policy configuration."""
        mock_data = {"config": "config firewall policy\n..."}
        mock_client.execute.return_value = mock_data

        result = await policy_api.export_policy_configuration("default")

        assert "config" in result or isinstance(result, str)
        mock_client.execute.assert_called_once()
