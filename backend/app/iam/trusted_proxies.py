"""Resolve client IP addresses without trusting spoofable forwarding headers.

Forwarded addresses are considered only when the immediate ASGI peer belongs
to an explicitly configured trusted-proxy network. The ingress must strip
client-supplied X-Forwarded-For and write its own canonical chain.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

_MAX_FORWARDED_HOPS = 20
_MAX_FORWARDED_HEADER_LENGTH = 1024


def _trusted_networks(raw: str | None):
    if raw is None or not raw.strip():
        return ()
    networks = []
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError("AEGIS_TRUSTED_PROXY_CIDRS contains an invalid network") from exc
    return tuple(networks)


def _is_trusted(address, networks: Iterable) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def resolve_client_ip(
    peer_host: str,
    forwarded_for: str | None,
    trusted_proxy_cidrs: str | None = None,
) -> str:
    """Walk X-Forwarded-For right-to-left only across trusted proxy hops."""
    if not isinstance(peer_host, str) or not peer_host.strip():
        raise ValueError("peer_host must be a non-empty address")
    networks = _trusted_networks(trusted_proxy_cidrs)
    try:
        peer = ipaddress.ip_address(peer_host.strip())
    except ValueError:
        # Non-IP ASGI transports cannot match a trusted network.
        return peer_host.strip()

    if not _is_trusted(peer, networks) or not forwarded_for:
        return str(peer)
    if len(forwarded_for) > _MAX_FORWARDED_HEADER_LENGTH:
        return str(peer)

    parts = [part.strip() for part in forwarded_for.split(",")]
    if not parts or len(parts) > _MAX_FORWARDED_HOPS or any(not part for part in parts):
        return str(peer)
    try:
        chain = [ipaddress.ip_address(part) for part in parts]
    except ValueError:
        return str(peer)

    current = peer
    for candidate in reversed(chain):
        if not _is_trusted(current, networks):
            break
        current = candidate
        if not _is_trusted(current, networks):
            break
    return str(current)
