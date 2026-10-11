"""
Scan targets: one host, resolved once, connected to by a pinned address.

Standard library only - the on-site runner imports this without the rest of
Glitched. Resolving once and connecting to the pinned address (rather than
looking the name up again for every connection) means an allowlist check on
the resolved addresses can't be sidestepped by a DNS answer that changes
between the check and the probe.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    """A host name and the addresses it resolved to. Probes connect to `address`."""

    host: str
    addresses: tuple[str, ...] = ()

    @property
    def public(self) -> bool:
        return any(is_public(address) for address in self.addresses)

    @property
    def address(self) -> str:
        """The pinned address to connect to: the first IPv4 one, else the first."""
        for address in self.addresses:
            if ":" not in address:
                return address
        return self.addresses[0] if self.addresses else self.host


def is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])  # drop an IPv6 zone id
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def resolve(host: str) -> Target:
    """Look the host up once. Raises ValueError if it doesn't resolve."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Can't resolve {host!r}: {exc.strerror}") from None
    return Target(host, tuple(sorted({info[4][0] for info in infos})))


def validate_single_host(host: str) -> str:
    """Exactly one declared host: refuse CIDR ranges, lists, wildcards and IP ranges (ValueError)."""
    host = host.strip()
    if not host or re.search(r"[/,*\s]", host) or re.fullmatch(r"[\d.]+-[\d.]+", host):
        raise ValueError(f"{host!r} is not a single host - register each device separately")
    return host


def endpoint(target: str | Target) -> tuple[str, str]:
    """
    (address to connect to, name for TLS SNI and the HTTP Host header). A bare
    string is used for both, as before; a Target connects to its pinned address.
    """
    if isinstance(target, Target):
        return target.address, target.host
    return target, target
