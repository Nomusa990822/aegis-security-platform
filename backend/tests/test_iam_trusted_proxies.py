import pytest

from app.iam.trusted_proxies import resolve_client_ip


def test_ignores_forwarded_header_when_peer_is_not_trusted():
    assert resolve_client_ip("198.51.100.20", "203.0.113.99", "10.0.0.0/8") == "198.51.100.20"


def test_uses_client_address_from_single_trusted_proxy():
    assert resolve_client_ip("10.0.0.5", "198.51.100.20", "10.0.0.0/8") == "198.51.100.20"


def test_walks_multiple_trusted_proxy_hops_from_right_to_left():
    assert resolve_client_ip("10.0.0.3", "198.51.100.20, 10.0.0.2", "10.0.0.0/8") == "198.51.100.20"


def test_stops_at_first_untrusted_hop_and_ignores_spoofed_prefix():
    assert resolve_client_ip("10.0.0.3", "203.0.113.77, 198.51.100.20, 10.0.0.2", "10.0.0.0/8") == "198.51.100.20"


def test_supports_ipv6_peers_clients_and_networks():
    assert resolve_client_ip("2001:db8:ffff::2", "2001:db8:abcd::9", "2001:db8:ffff::/48") == "2001:db8:abcd::9"


@pytest.mark.parametrize("header", [
    "", ",", "198.51.100.1,", "not-an-ip", "198.51.100.1, invalid",
    ",".join(f"192.0.2.{i % 250 + 1}" for i in range(21)), "x" * 1025,
])
def test_malformed_or_excessive_forwarding_data_falls_back_to_peer(header):
    assert resolve_client_ip("10.0.0.5", header, "10.0.0.0/8") == "10.0.0.5"


def test_missing_forwarded_header_uses_peer():
    assert resolve_client_ip("10.0.0.5", None, "10.0.0.0/8") == "10.0.0.5"


def test_empty_trust_configuration_never_uses_forwarded_header():
    assert resolve_client_ip("10.0.0.5", "198.51.100.20", "") == "10.0.0.5"


def test_invalid_trusted_proxy_configuration_is_rejected():
    with pytest.raises(ValueError, match="invalid network"):
        resolve_client_ip("10.0.0.5", "198.51.100.20", "not-a-cidr")


def test_non_ip_transport_peer_never_trusts_forwarded_header():
    assert resolve_client_ip("testclient", "198.51.100.20", "10.0.0.0/8") == "testclient"
