"""Unit tests for api.models module."""

import pytest

from fortimanager_mcp.api.models import (
    ADOM,
    APIResponse,
    Device,
    FirewallAddress,
    FirewallAddressGroup,
    JSONRPCRequest,
)


class TestAPIResponse:
    """Test APIResponse model."""

    def test_init_basic(self):
        """Test basic initialization."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0, "message": "OK"}, "data": {"test": "data"}}],
        )
        assert response.id == 1
        assert len(response.result) == 1
        assert response.session is None

    def test_init_with_session_string(self):
        """Test initialization with string session."""
        response = APIResponse(
            id=1,
            result=[],
            session="abc123",
        )
        assert response.session == "abc123"

    def test_init_with_session_int(self):
        """Test initialization with integer session."""
        response = APIResponse(
            id=1,
            result=[],
            session=123,
        )
        assert response.session == 123

    def test_is_success_true(self):
        """Test is_success property when successful."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0, "message": "OK"}}],
        )
        assert response.is_success is True

    def test_is_success_false_error_code(self):
        """Test is_success property when error code present."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": -1, "message": "Error"}}],
        )
        assert response.is_success is False

    def test_is_success_false_empty_result(self):
        """Test is_success property with empty result."""
        response = APIResponse(id=1, result=[])
        assert response.is_success is False

    def test_error_code_success(self):
        """Test error_code property on success."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0, "message": "OK"}}],
        )
        assert response.error_code == 0

    def test_error_code_error(self):
        """Test error_code property on error."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": -3, "message": "Not found"}}],
        )
        assert response.error_code == -3

    def test_error_code_empty_result(self):
        """Test error_code property with empty result."""
        response = APIResponse(id=1, result=[])
        assert response.error_code is None

    def test_error_message_success(self):
        """Test error_message property on success."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0, "message": "OK"}}],
        )
        assert response.error_message == "OK"

    def test_error_message_error(self):
        """Test error_message property on error."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": -1, "message": "Internal error"}}],
        )
        assert response.error_message == "Internal error"

    def test_error_message_empty_result(self):
        """Test error_message property with empty result."""
        response = APIResponse(id=1, result=[])
        assert response.error_message is None

    def test_data_present(self):
        """Test data property when data present."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0}, "data": {"key": "value"}}],
        )
        assert response.data == {"key": "value"}

    def test_data_absent(self):
        """Test data property when data absent."""
        response = APIResponse(
            id=1,
            result=[{"status": {"code": 0}}],
        )
        assert response.data is None

    def test_data_empty_result(self):
        """Test data property with empty result."""
        response = APIResponse(id=1, result=[])
        assert response.data is None


class TestJSONRPCRequest:
    """Test JSONRPCRequest model."""

    def test_init_basic(self):
        """Test basic initialization."""
        request = JSONRPCRequest(
            id=1,
            method="get",
            params=[{"url": "/api/test"}],
        )
        assert request.id == 1
        assert request.method == "get"
        assert request.params == [{"url": "/api/test"}]
        assert request.session is None

    def test_init_with_session(self):
        """Test initialization with session."""
        request = JSONRPCRequest(
            id=1,
            method="get",
            params=[{"url": "/api/test"}],
            session="abc123",
        )
        assert request.session == "abc123"


class TestDevice:
    """Test Device model."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        device = Device(name="FGT-01")
        assert device.name == "FGT-01"
        assert device.os_type is None
        assert device.sn is None

    def test_init_full(self):
        """Test full initialization."""
        device = Device(
            name="FGT-01",
            os_type="FortiGate",
            os_ver="7.4.0",
            mr=2,
            build=1234,
            platform_str="FortiGate-100F",
            sn="FGT60F1234567890",
            ip="192.168.1.99",
            conn_status=1,
            ha_mode="standalone",
            oid=123,
        )
        assert device.name == "FGT-01"
        assert device.os_type == "FortiGate"
        assert device.sn == "FGT60F1234567890"

    def test_is_connected_true_int(self):
        """Test is_connected property with integer 1."""
        device = Device(name="FGT-01", conn_status=1)
        assert device.is_connected is True

    def test_is_connected_true_string(self):
        """Test is_connected property with string 'up'."""
        device = Device(name="FGT-01", conn_status="up")
        assert device.is_connected is True

    def test_is_connected_false_int(self):
        """Test is_connected property with integer 0."""
        device = Device(name="FGT-01", conn_status=0)
        assert device.is_connected is False

    def test_is_connected_false_string(self):
        """Test is_connected property with string 'down'."""
        device = Device(name="FGT-01", conn_status="down")
        assert device.is_connected is False

    def test_is_connected_false_none(self):
        """Test is_connected property with None."""
        device = Device(name="FGT-01", conn_status=None)
        assert device.is_connected is False

    def test_vdom_list(self):
        """Test device with VDOMs."""
        device = Device(
            name="FGT-01",
            vdom=[{"name": "root", "opmode": "nat"}, {"name": "vdom1", "opmode": "nat"}],
        )
        assert device.vdom is not None
        assert len(device.vdom) == 2


class TestADOM:
    """Test ADOM model."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        adom = ADOM(name="root")
        assert adom.name == "root"
        assert adom.desc is None
        assert adom.mr is None

    def test_init_full(self):
        """Test full initialization."""
        adom = ADOM(
            name="test-adom",
            desc="Test ADOM",
            mr=4,
            os_ver="7.4",
            restricted_prds="fos",
            state=1,
            oid=123,
            create_time=1234567890,
            workspace_mode=1,
        )
        assert adom.name == "test-adom"
        assert adom.desc == "Test ADOM"
        assert adom.mr == 4
        assert adom.os_ver == "7.4"


class TestFirewallAddress:
    """Test FirewallAddress model."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        addr = FirewallAddress(name="addr1")
        assert addr.name == "addr1"
        assert addr.type == 0
        assert addr.subnet is None

    def test_init_ipmask(self):
        """Test initialization for ipmask type."""
        addr = FirewallAddress(
            name="addr1",
            type=0,
            subnet=["192.168.1.0", "255.255.255.0"],
        )
        assert addr.name == "addr1"
        assert addr.type == 0
        assert addr.subnet == ["192.168.1.0", "255.255.255.0"]

    def test_init_iprange(self):
        """Test initialization for iprange type."""
        addr = FirewallAddress(
            name="addr1",
            type=1,
            start_ip="192.168.1.1",
            end_ip="192.168.1.254",
        )
        assert addr.type == 1
        assert addr.start_ip == "192.168.1.1"
        assert addr.end_ip == "192.168.1.254"

    def test_init_fqdn(self):
        """Test initialization for FQDN type."""
        addr = FirewallAddress(
            name="google",
            type=2,
            fqdn="www.google.com",
        )
        assert addr.type == 2
        assert addr.fqdn == "www.google.com"

    def test_init_geography(self):
        """Test initialization for geography type."""
        addr = FirewallAddress(
            name="usa",
            type=6,
            country="US",
        )
        assert addr.type == 6
        assert addr.country == "US"

    def test_init_with_comment(self):
        """Test initialization with comment."""
        addr = FirewallAddress(
            name="addr1",
            comment="Test address",
        )
        assert addr.comment == "Test address"

    def test_init_with_color(self):
        """Test initialization with color."""
        addr = FirewallAddress(
            name="addr1",
            color=5,
        )
        assert addr.color == 5

    def test_init_with_uuid(self):
        """Test initialization with UUID."""
        addr = FirewallAddress(
            name="addr1",
            uuid="12345678-1234-1234-1234-123456789012",
        )
        assert addr.uuid == "12345678-1234-1234-1234-123456789012"


class TestFirewallAddressGroup:
    """Test FirewallAddressGroup model."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        group = FirewallAddressGroup(name="group1")
        assert group.name == "group1"
        assert group.member == []

    def test_init_with_members(self):
        """Test initialization with members."""
        group = FirewallAddressGroup(
            name="group1",
            member=["addr1", "addr2"],
        )
        assert group.name == "group1"
        assert group.member == ["addr1", "addr2"]

    def test_init_with_comment(self):
        """Test initialization with comment."""
        group = FirewallAddressGroup(
            name="group1",
            comment="Test group",
        )
        assert group.comment == "Test group"
