"""Unit tests for api.vpn module."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fortimanager_mcp.api.vpn import VPNAPI


@pytest.fixture
def mock_client():
    """Create mock FortiManager client."""
    client = MagicMock()
    client.get = AsyncMock()
    client.add = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.execute = AsyncMock()
    client.update = AsyncMock()
    return client


@pytest.fixture
def vpn_api(mock_client):
    """Create VPNAPI instance with mock client."""
    return VPNAPI(mock_client)


class TestVPNAPIInit:
    """Test VPNAPI initialization."""

    def test_init(self, mock_client):
        """Test initialization with client."""
        api = VPNAPI(mock_client)
        assert api.client == mock_client


class TestIPsecPhase1:
    """Test IPsec Phase1 operations."""

    @pytest.mark.asyncio
    async def test_list_ipsec_phase1(self, vpn_api, mock_client):
        """Test listing IPsec Phase1 interfaces."""
        mock_data = [
            {"name": "vpn1", "interface": "wan1", "remote-gw": "203.0.113.10"},
            {"name": "vpn2", "interface": "wan2", "remote-gw": "203.0.113.20"},
        ]
        mock_client.get.return_value = mock_data

        result = await vpn_api.list_ipsec_phase1(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/vpn/ipsec/phase1-interface"
        )

    @pytest.mark.asyncio
    async def test_list_ipsec_phase1_empty(self, vpn_api, mock_client):
        """Test listing IPsec Phase1 interfaces with empty result."""
        mock_client.get.return_value = []

        result = await vpn_api.list_ipsec_phase1(adom="custom")

        assert result == []
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ipsec_phase1(self, vpn_api, mock_client):
        """Test getting IPsec Phase1 interface details."""
        mock_data = {
            "name": "vpn1",
            "interface": "wan1",
            "remote-gw": "203.0.113.10",
            "authmethod": "psk",
        }
        mock_client.get.return_value = mock_data

        result = await vpn_api.get_ipsec_phase1("vpn1", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once_with(
            "/pm/config/adom/root/obj/vpn/ipsec/phase1-interface/vpn1"
        )

    @pytest.mark.asyncio
    async def test_create_ipsec_phase1_with_psk(self, vpn_api, mock_client):
        """Test creating IPsec Phase1 interface with PSK."""
        mock_result = {"name": "vpn1"}
        mock_client.add.return_value = mock_result

        result = await vpn_api.create_ipsec_phase1(
            name="vpn1",
            interface="wan1",
            remote_gw="203.0.113.10",
            adom="root",
            psk="mysecretkey",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()
        call_args = mock_client.add.call_args
        assert call_args[0][0] == "/pm/config/adom/root/obj/vpn/ipsec/phase1-interface"
        assert call_args[0][1]["name"] == "vpn1"
        assert call_args[0][1]["authmethod"] == "psk"
        assert call_args[0][1]["psksecret"] == "mysecretkey"

    @pytest.mark.asyncio
    async def test_create_ipsec_phase1_with_certificate(self, vpn_api, mock_client):
        """Test creating IPsec Phase1 interface with certificate."""
        mock_result = {"name": "vpn1"}
        mock_client.add.return_value = mock_result

        result = await vpn_api.create_ipsec_phase1(
            name="vpn1",
            interface="wan1",
            remote_gw="203.0.113.10",
            adom="root",
            certificate="Fortinet_CA_SSL",
        )

        assert result == mock_result
        call_args = mock_client.add.call_args
        assert call_args[0][1]["authmethod"] == "signature"
        assert call_args[0][1]["certificate"] == "Fortinet_CA_SSL"

    @pytest.mark.asyncio
    async def test_update_ipsec_phase1(self, vpn_api, mock_client):
        """Test updating IPsec Phase1 interface."""
        mock_result = {"status": "success"}
        mock_client.update.return_value = mock_result

        result = await vpn_api.update_ipsec_phase1(
            name="vpn1",
            adom="root",
            remote_gw="203.0.113.30",
        )

        assert result == mock_result
        mock_client.update.assert_called_once()
        call_args = mock_client.update.call_args
        assert "vpn1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_delete_ipsec_phase1(self, vpn_api, mock_client):
        """Test deleting IPsec Phase1 interface."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await vpn_api.delete_ipsec_phase1("vpn1", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once_with(
            "/pm/config/adom/root/obj/vpn/ipsec/phase1-interface/vpn1"
        )


class TestIPsecPhase2:
    """Test IPsec Phase2 operations."""

    @pytest.mark.asyncio
    async def test_list_ipsec_phase2(self, vpn_api, mock_client):
        """Test listing IPsec Phase2 selectors."""
        mock_data = [
            {"name": "vpn1-p2", "phase1name": "vpn1"},
            {"name": "vpn2-p2", "phase1name": "vpn2"},
        ]
        mock_client.get.return_value = mock_data

        result = await vpn_api.list_ipsec_phase2(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ipsec_phase2(self, vpn_api, mock_client):
        """Test getting IPsec Phase2 selector details."""
        mock_data = {"name": "vpn1-p2", "phase1name": "vpn1"}
        mock_client.get.return_value = mock_data

        result = await vpn_api.get_ipsec_phase2("vpn1-p2", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_ipsec_phase2(self, vpn_api, mock_client):
        """Test creating IPsec Phase2 selector."""
        mock_result = {"name": "vpn1-p2"}
        mock_client.add.return_value = mock_result

        result = await vpn_api.create_ipsec_phase2(
            name="vpn1-p2",
            phase1name="vpn1",
            src_subnet="10.0.0.0/24",
            dst_subnet="192.168.0.0/24",
            adom="root",
        )

        assert result == mock_result
        mock_client.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_ipsec_phase2(self, vpn_api, mock_client):
        """Test deleting IPsec Phase2 selector."""
        mock_result = {"status": "success"}
        mock_client.delete.return_value = mock_result

        result = await vpn_api.delete_ipsec_phase2("vpn1-p2", adom="root")

        assert result == mock_result
        mock_client.delete.assert_called_once()


class TestSSLVPN:
    """Test SSL-VPN operations."""

    @pytest.mark.asyncio
    async def test_list_sslvpn_portals(self, vpn_api, mock_client):
        """Test listing SSL-VPN portals."""
        mock_data = [
            {"name": "full-access", "tunnel-mode": "enable"},
            {"name": "web-access", "tunnel-mode": "disable"},
        ]
        mock_client.get.return_value = mock_data

        result = await vpn_api.list_sslvpn_portals(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_sslvpn_portal(self, vpn_api, mock_client):
        """Test getting SSL-VPN portal details."""
        mock_data = {"name": "full-access", "tunnel-mode": "enable"}
        mock_client.get.return_value = mock_data

        result = await vpn_api.get_sslvpn_portal("full-access", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()


class TestCertificates:
    """Test certificate operations."""

    @pytest.mark.asyncio
    async def test_list_vpn_certificates_ca(self, vpn_api, mock_client):
        """Test listing CA certificates."""
        mock_data = [
            {"name": "Fortinet_CA_SSL", "range": "global"},
            {"name": "Fortinet_CA_Untrusted", "range": "global"},
        ]
        mock_client.get.return_value = mock_data

        result = await vpn_api.list_vpn_certificates_ca(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_vpn_certificate_ca(self, vpn_api, mock_client):
        """Test getting CA certificate details."""
        mock_data = {
            "name": "Fortinet_CA_SSL",
            "range": "global",
        }
        mock_client.get.return_value = mock_data

        result = await vpn_api.get_vpn_certificate_ca("Fortinet_CA_SSL", adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_vpn_certificates_remote(self, vpn_api, mock_client):
        """Test listing remote certificates."""
        mock_data = [
            {"name": "remote-cert1"},
            {"name": "remote-cert2"},
        ]
        mock_client.get.return_value = mock_data

        result = await vpn_api.list_vpn_certificates_remote(adom="root")

        assert result == mock_data
        mock_client.get.assert_called_once()
