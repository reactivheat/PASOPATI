"""Offline scope decisions, separate from network authorization and DNS."""

import ipaddress
from dataclasses import dataclass

from pasopati.config import Config
from pasopati.targets import Address, Target, matches, parse_target


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class Scope:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.rules = config.scope
        self.allowed_networks = tuple(ipaddress.ip_network(n) for n in self.rules.allow_cidrs)
        self.excluded_networks = tuple(ipaddress.ip_network(n) for n in self.rules.exclude_cidrs)

    def address(self, address: Address) -> Decision:
        if any(address in n for n in self.excluded_networks):
            return Decision(False, "excluded")
        # Stable conservative special-use policy even on older Python registry snapshots.
        special = any(
            address in ipaddress.ip_network(n)
            for n in (
                "0.0.0.0/8",
                "100.64.0.0/10",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "2001:db8::/32",
                "3fff::/20",
                "100::/64",
            )
        )
        # Transition mechanisms and mapped addresses are rejected rather than reinterpreted.
        transition = isinstance(address, ipaddress.IPv6Address) and (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
            or address in ipaddress.ip_network("64:ff9b::/96")
            or address in ipaddress.ip_network("64:ff9b:1::/48")
        )
        if (
            address.is_unspecified
            or address.is_multicast
            or (address.is_reserved and not address.is_loopback)
            or address.is_link_local
            or transition
            or special
            or address == ipaddress.ip_address("255.255.255.255")
        ):
            return Decision(False, "address_forbidden")
        if not address.is_global:
            # Only private/loopback lab space, never documentation or shared-address space.
            lab = address.is_loopback or any(
                address in n
                for n in (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("fc00::/7"),
                )
            )
            if not (
                lab
                and self.config.authorized
                and self.rules.allow_private
                and any(address in n for n in self.allowed_networks)
            ):
                return Decision(False, "address_forbidden")
        return Decision(True, "allowed")

    def target(self, target: Target) -> Decision:
        if target.port is not None and target.port not in self.rules.ports:
            return Decision(False, "port_denied")
        try:
            address = ipaddress.ip_address(target.host)
        except ValueError:
            if any(matches(target.host, rule) for rule in self.rules.exclude_domains):
                return Decision(False, "excluded")
            allowed = any(matches(target.host, rule) for rule in self.rules.allow_domains)
            return Decision(allowed, "allowed" if allowed else "not_allowlisted")
        decision = self.address(address)
        if not decision.allowed:
            return decision
        allowed = any(address in n for n in self.allowed_networks)
        return Decision(allowed, "allowed" if allowed else "not_allowlisted")

    def check(self, value: str) -> Decision:
        return self.target(parse_target(value))
