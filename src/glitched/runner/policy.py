"""
The runner's local policy: what it may probe. Deny by default.

It lives in a file on the company's own machine (mounted read-only in the
container); the console never sees or changes it, only a summary. Even a
compromised console can't send the runner anywhere this file doesn't allow.

    [targets]
    allow = ["10.20.0.0/24", "arm02.lab"]   # networks (CIDR), addresses or host names
    deny = ["10.20.0.1"]                    # always wins over allow
    allow_public = false                    # public internet addresses (needs written authorization)

    [limits]
    max_jobs_per_hour = 60

    [evidence]
    mode = "full"                            # or "minimal": no banners or response text leave the site

A target passes only if every address its name resolves to is allowed (by
network, or because the name itself is listed) and none is denied. Names
listed in `allow` still have to resolve to private addresses unless
allow_public is true, so a DNS answer can't turn an allowed name into a
pivot to the internet.
"""

from __future__ import annotations

import hashlib
import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

from glitched.targets import Target, is_public

TEMPLATE = """\
# Glitched runner policy - what this runner may probe. Nothing is allowed
# unless it's listed here. The console can't change this file.

[targets]
# Networks (CIDR), single addresses or host names of robots you own or are
# authorized to test.
allow = [
  # "10.20.0.0/24",
  # "arm02.lab",
]
# Never probed, even if inside an allowed network (routers, PLCs, safety controllers ...).
deny = [
  # "10.20.0.1",
]
# Public internet addresses need explicit written authorization.
allow_public = false

[limits]
max_jobs_per_hour = 60

[evidence]
# "full" sends what the robot answered (banners, page titles) to the console;
# "minimal" sends only the verdicts.
mode = "full"
"""

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class PolicyError(Exception):
    """The policy file is missing or wrong. The runner refuses every job until it's fixed."""


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class Policy:
    allow_networks: tuple[Network, ...] = ()
    allow_hosts: frozenset[str] = frozenset()
    deny_networks: tuple[Network, ...] = ()
    deny_hosts: frozenset[str] = frozenset()
    allow_public: bool = False
    max_jobs_per_hour: int = 60
    evidence: str = "full"
    digest: str = ""

    def check(self, target: Target) -> Verdict:
        """May this resolved target be probed? Every address must pass."""
        host = target.host.strip().lower().rstrip(".")
        if not target.addresses:
            return Verdict(False, f"{target.host} didn't resolve to any address.")
        if host in self.deny_hosts:
            return Verdict(False, f"{target.host} is on the policy's deny list.")
        for text in target.addresses:
            address = ipaddress.ip_address(text.split("%")[0])
            if any(address in net for net in self.deny_networks):
                return Verdict(False, f"{target.host} resolves to {text}, which the policy denies.")
            if is_public(text) and not self.allow_public:
                return Verdict(False, f"{target.host} resolves to {text}, a public address "
                                      "(the policy has allow_public = false).")
            by_network = any(address in net for net in self.allow_networks)
            if not (by_network or host in self.allow_hosts):
                return Verdict(False, f"{target.host} resolves to {text}, which isn't in the policy's allow list.")
        return Verdict(True, f"Allowed by the local policy ({', '.join(target.addresses)}).")

    def summary(self) -> dict:
        """What the console may know: counts and settings, not the network layout."""
        return {"allow_entries": len(self.allow_networks) + len(self.allow_hosts),
                "deny_entries": len(self.deny_networks) + len(self.deny_hosts),
                "allow_public": self.allow_public, "max_jobs_per_hour": self.max_jobs_per_hour,
                "evidence": self.evidence, "digest": self.digest[:16]}


def _entries(values: object, key: str) -> tuple[list[Network], set[str]]:
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise PolicyError(f"targets.{key} must be a list of strings")
    networks, hosts = [], set()
    for value in values:
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
            continue
        except ValueError:
            pass
        if "*" in value or "/" in value or " " in value:
            raise PolicyError(f"targets.{key}: {value!r} isn't a network, address or host name (no wildcards)")
        hosts.add(value.lower().rstrip("."))
    return networks, hosts


def parse(text: str) -> Policy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"the policy isn't valid TOML: {exc}") from None
    unknown = set(data) - {"targets", "limits", "evidence"}
    if unknown:
        raise PolicyError(f"unknown section(s) {sorted(unknown)} - expected [targets], [limits], [evidence]")
    targets = data.get("targets", {})
    unknown = set(targets) - {"allow", "deny", "allow_public"}
    if unknown:
        raise PolicyError(f"unknown key(s) in [targets]: {sorted(unknown)}")
    allow_networks, allow_hosts = _entries(targets.get("allow", []), "allow")
    deny_networks, deny_hosts = _entries(targets.get("deny", []), "deny")
    allow_public = targets.get("allow_public", False)
    if not isinstance(allow_public, bool):
        raise PolicyError("targets.allow_public must be true or false")
    if any(net.prefixlen == 0 for net in allow_networks):
        raise PolicyError("targets.allow can't contain a whole address space (0.0.0.0/0 or ::/0)")
    limit = data.get("limits", {}).get("max_jobs_per_hour", 60)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
        raise PolicyError("limits.max_jobs_per_hour must be a whole number from 1 to 10000")
    evidence = data.get("evidence", {}).get("mode", "full")
    if evidence not in ("full", "minimal"):
        raise PolicyError('evidence.mode must be "full" or "minimal"')
    return Policy(tuple(allow_networks), frozenset(allow_hosts), tuple(deny_networks), frozenset(deny_hosts),
                  allow_public, limit, evidence, hashlib.sha256(text.encode()).hexdigest())


def load(path: Path) -> Policy:
    try:
        return parse(path.read_text())
    except FileNotFoundError:
        raise PolicyError(f"no policy at {path} - write one (glitched-runner policy template) "
                          "to allow your robots") from None
