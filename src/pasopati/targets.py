"""Strict parsing shared by configuration, offline scope and the HTTP backend."""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from pasopati.core.errors import PolicyError

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def hostname(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or any(ord(c) <= 32 or unicodedata.category(c).startswith("C") for c in value)
    ):
        raise PolicyError("invalid_target", 2)
    if any(c in value for c in "%/@\\?#"):
        raise PolicyError("invalid_target", 2)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.removesuffix(".")
    try:
        result = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("invalid_target", 2) from exc
    labels = result.split(".")
    if (
        len(result) > 253
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels)
        or labels[-1].isdigit()
        or any(p.startswith("0x") for p in labels)
    ):
        raise PolicyError("invalid_target", 2)
    return result


def domain_rule(value: str) -> str:
    wildcard = value.startswith("*.")
    normalized = hostname(value[2:] if wildcard else value)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return ("*." if wildcard else "") + normalized
    raise PolicyError("invalid_config", 2)


def matches(host: str, rule: str) -> bool:
    return host.endswith("." + rule[2:]) if rule.startswith("*.") else host == rule


@dataclass(frozen=True)
class Target:
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str = "/"

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return f"{host}:{self.port}" if self.port != default else host

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"


def parse_target(value: str, *, require_url: bool = False) -> Target:
    if (
        not value
        or any(ord(c) <= 32 or unicodedata.category(c).startswith("C") for c in value)
        or "\\" in value
    ):
        raise PolicyError("invalid_target", 2)
    if "://" not in value:
        if require_url:
            raise PolicyError("invalid_target", 2)
        return Target(hostname(value))
    try:
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or parts.username is not None
            or parts.password is not None
            or not parts.hostname
            or parts.fragment
            or parts.netloc.endswith(":")
        ):
            raise ValueError
        host = hostname(parts.hostname)
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parts.query:
            path += "?" + quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
        return Target(host, parts.scheme, port, path)
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("invalid_target", 2) from exc
