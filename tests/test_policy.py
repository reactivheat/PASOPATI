import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pasopati.cli import app
from pasopati.config import TEMPLATE, Config, ScopeConfig, init_config, parse_config
from pasopati.core.errors import PolicyError
from pasopati.profiles import get_profile
from pasopati.scope import Scope
from pasopati.targets import parse_target


def test_safe_template_and_immutability() -> None:
    config = parse_config(TEMPLATE.encode())
    assert config.profile == "passive" and not config.authorized
    assert get_profile(config.profile).request_budget == 0
    with pytest.raises(FrozenInstanceError):
        config.__setattr__("authorized", True)
    with pytest.raises(FrozenInstanceError):
        get_profile("safe").__setattr__("max_redirects", 100)


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"broken[",
        b"\xff",
        b"x" * 65537,
        TEMPLATE.replace("schema_version = 1", "schema_version = true").encode(),
        TEMPLATE.replace("schema_version = 1", "schema_version = 2").encode(),
        TEMPLATE.replace('profile = "passive"', 'profile = "fast"').encode(),
        TEMPLATE.replace("authorized = false", 'authorized = "false"').encode(),
        TEMPLATE.replace("ports = [80, 443]", "ports = [true]").encode(),
        TEMPLATE.replace("ports = [80, 443]", "ports = [65536]").encode(),
        TEMPLATE.replace("allow_cidrs = []", 'allow_cidrs = ["10.1.1.1/8"]').encode(),
        TEMPLATE.replace('allow_domains = ["example.invalid"]', "allow_domains = false").encode(),
        TEMPLATE.replace("[scope]", "extra = 1\n[scope]").encode(),
        (TEMPLATE + "secret = 'hidden'\n").encode(),
    ],
    ids=lambda value: f"invalid-{len(value)}-bytes",
)
def test_strict_config(bad: bytes) -> None:
    with pytest.raises(PolicyError) as error:
        parse_config(bad)
    assert error.value.exit_code == 2


@pytest.mark.parametrize(
    "value,allowed",
    [
        ("example.invalid", True),
        ("EXAMPLE.INVALID.", True),
        ("a.example.invalid", True),
        ("deep.a.example.invalid", True),
        ("evil-example.invalid", False),
        ("example.invalid.attacker.invalid", False),
        ("blocked.example.invalid", False),
        ("other.invalid", False),
        ("https://example.invalid:443/a?b=c", True),
        ("https://example.invalid:444/", False),
    ],
)
def test_domain_scope(value: str, allowed: bool) -> None:
    policy = Scope(
        Config(
            scope=ScopeConfig(
                allow_domains=("example.invalid", "*.example.invalid"),
                exclude_domains=("blocked.example.invalid",),
            )
        )
    )
    assert policy.check(value).allowed is allowed


def test_wildcard_not_apex_and_idna() -> None:
    policy = Scope(Config(scope=ScopeConfig(allow_domains=("*.example.invalid", "bücher.invalid"))))
    assert not policy.check("example.invalid").allowed
    assert policy.check("XN--BCHER-KVA.INVALID.").allowed


@pytest.mark.parametrize(
    "target",
    [
        "",
        "127.1",
        "0177.0.0.1",
        "2130706433",
        "0x7f000001",
        "::1%lo",
        "https://exam\u200bple.invalid",
        "https://example.invalid/\u0080",
        "http://user:password@example.invalid",
        "http://example.invalid:",
        "http://example.invalid:0",
        "http://example.invalid:65536",
        "https:///path",
        "ftp://example.invalid",
        "https://example.invalid/#fragment",
        "https://example.invalid/\r\nInjected:yes",
        "http://example.invalid\\@evil.invalid",
    ],
)
def test_invalid_targets(target: str) -> None:
    with pytest.raises(PolicyError) as error:
        parse_target(target)
    assert str(error.value) == "invalid_target"


@pytest.mark.parametrize(
    "target,allowed",
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("10.0.0.1", True),
        ("10.0.0.2", False),
        ("169.254.169.254", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("192.0.2.1", False),
        ("100.64.0.1", False),
        ("::ffff:127.0.0.1", False),
        ("64:ff9b::7f00:1", False),
        ("3fff::1", False),
        ("192.0.0.8", False),
    ],
)
def test_lab_addresses(target: str, allowed: bool) -> None:
    policy = Scope(
        Config(
            authorized=True,
            scope=ScopeConfig(
                allow_cidrs=("127.0.0.1/32", "::1/128", "10.0.0.0/8", "0.0.0.0/0", "::/0"),
                exclude_cidrs=("10.0.0.2/32",),
                allow_private=True,
            ),
        )
    )
    assert policy.check(target).allowed is allowed


@pytest.mark.parametrize("authorized,private", [(False, True), (True, False), (False, False)])
def test_private_requires_all_permissions(authorized: bool, private: bool) -> None:
    policy = Scope(
        Config(
            authorized=authorized,
            scope=ScopeConfig(allow_cidrs=("127.0.0.1/32",), allow_private=private),
        )
    )
    assert not policy.check("127.0.0.1").allowed


def test_init_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "pasopati.toml"
    init_config(path)
    before = path.read_bytes()
    with pytest.raises(PolicyError):
        init_config(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("language", ["en", "id"])
def test_cli_policy_and_json_errors(tmp_path: Path, language: str) -> None:
    path = tmp_path / "pasopati.toml"
    runner = CliRunner()
    init_config(path)
    prefix = ["--lang", language]
    for args, code in [
        (["config", "validate", "--config", str(path)], 0),
        (["scope", "check", "example.invalid", "--config", str(path)], 0),
        (["scope", "check", "other.invalid", "--config", str(path)], 1),
        (["scope", "check", "https://user:secret@example.invalid", "--config", str(path)], 2),
        (["profiles", "list"], 0),
        (["profiles", "show", "safe"], 0),
        (["profiles", "show", "unknown"], 2),
        (["config", "validate", "--config", str(tmp_path / "missing")], 1),
        (["init", "--path", str(path)], 1),
    ]:
        result = runner.invoke(app, prefix + args + ["--json"], env={"FORCE_COLOR": "1"})
        assert result.exit_code == code, result.output
        payload = json.loads(result.stdout)
        assert payload["language"] == language
        assert payload["ok"] is (code == 0)
        assert "\x1b" not in result.stdout and "secret" not in result.stdout
        if args[:2] == ["scope", "check"] and code != 2:
            assert payload["dns_checked"] is False
            assert payload["connectivity_checked"] is False
    result = runner.invoke(
        app, prefix + ["--no-banner", "scope", "check", "example.invalid", "--config", str(path)]
    )
    assert result.exit_code == 0
    assert "BELUM" in result.output if language == "id" else "NOT" in result.output
