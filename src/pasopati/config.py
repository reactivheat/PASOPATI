"""Strict, bounded, offline TOML configuration; no automatic discovery/fallback."""

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pasopati.core.errors import PolicyError
from pasopati.profiles import get_profile
from pasopati.targets import domain_rule

TEMPLATE = """schema_version = 1
profile = "passive"
authorized = false

[scope]
allow_domains = ["example.invalid"]
allow_cidrs = []
exclude_domains = []
exclude_cidrs = []
ports = [80, 443]
allow_private = false
"""


@dataclass(frozen=True)
class ScopeConfig:
    allow_domains: tuple[str, ...] = ()
    allow_cidrs: tuple[str, ...] = ()
    exclude_domains: tuple[str, ...] = ()
    exclude_cidrs: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)
    allow_private: bool = False

    def __post_init__(self) -> None:
        try:
            if type(self.allow_private) is not bool:
                raise ValueError
            for key in ("allow_domains", "exclude_domains", "allow_cidrs", "exclude_cidrs"):
                values = getattr(self, key)
                if not isinstance(values, tuple) or len(values) > 1024:
                    raise ValueError
                if any(not isinstance(v, str) for v in values):
                    raise ValueError
                normalized = tuple(
                    domain_rule(v)
                    if key.endswith("domains")
                    else str(ipaddress.ip_network(v, strict=True))
                    for v in values
                )
                object.__setattr__(self, key, normalized)
            if (
                not isinstance(self.ports, tuple)
                or len(self.ports) > 1024
                or any(type(p) is not int or not 1 <= p <= 65535 for p in self.ports)
            ):
                raise ValueError
        except (ValueError, TypeError, PolicyError) as exc:
            raise PolicyError("invalid_config", 2) from exc


@dataclass(frozen=True)
class Config:
    schema_version: int = 1
    profile: str = "passive"
    authorized: bool = False
    scope: ScopeConfig = ScopeConfig()

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.authorized) is not bool
            or not isinstance(self.profile, str)
            or not isinstance(self.scope, ScopeConfig)
        ):
            raise PolicyError("invalid_config", 2)
        get_profile(self.profile)


def parse_config(data: bytes) -> Config:
    try:
        if len(data) > 65536:
            raise ValueError
        raw = tomllib.loads(data.decode("utf-8"))
        if set(raw) != {"schema_version", "profile", "authorized", "scope"}:
            raise ValueError
        scope = raw.get("scope", {})
        if not isinstance(scope, dict) or set(scope) - set(ScopeConfig.__dataclass_fields__):
            raise ValueError
        for key in ("allow_domains", "exclude_domains", "allow_cidrs", "exclude_cidrs", "ports"):
            if key in scope:
                if not isinstance(scope[key], list):
                    raise ValueError
                scope[key] = tuple(scope[key])
        return Config(
            raw.get("schema_version", 1),
            raw.get("profile", "passive"),
            raw.get("authorized", False),
            ScopeConfig(**scope),
        )
    except (ValueError, UnicodeError, TypeError) as exc:
        raise PolicyError("invalid_config", 2) from exc


def load_config(path: Path) -> Config:
    try:
        with path.open("rb") as stream:
            data = stream.read(65537)
    except OSError as exc:
        raise PolicyError("config_io") from exc
    return parse_config(data)


def init_config(path: Path) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(TEMPLATE)
    except OSError as exc:
        raise PolicyError("config_io") from exc
