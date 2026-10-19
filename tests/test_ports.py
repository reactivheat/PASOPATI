import errno
import ipaddress
import json
import socket
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_discovery import FakeQuery, new_budget

from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.dns_client import DNSAnswer
from pasopati.i18n import Language
from pasopati.limits import Deadline
from pasopati.port_inventory import (
    normalize_hosts,
    parse_ports,
    run_port_inventory,
    validate_inventory,
)
from pasopati.reports import render_json, render_text
from pasopati.targets import Address
from pasopati.tcp import NumericTCPConnector, connect_outcome


def configuration(*ports: int) -> Config:
    return Config(
        profile="safe",
        authorized=True,
        scope=ScopeConfig(
            allow_domains=("example.invalid", "*.example.invalid"),
            exclude_domains=("excluded.example.invalid",),
            ports=ports or (80, 443),
        ),
    )


class FakeTCP:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, float]] = []
        self.errors: dict[tuple[str, int], BaseException] = {}

    def connect(self, address: Address, port: int, deadline: Deadline, timeout: float) -> None:
        assert isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        assert 0 < deadline.remaining() <= timeout <= 3
        self.calls.append((str(address), port, deadline.clock.monotonic()))
        if (str(address), port) in self.errors:
            raise self.errors[(str(address), port)]


@pytest.mark.parametrize(
    "value",
    ["", "0", "65536", "01", "+80", "-1", "1-5", "80,", " 80", "80, 443", "http", "١٢", "80" * 300],
)
def test_invalid_port_lists(value: str) -> None:
    with pytest.raises(PolicyError, match="invalid_ports"):
        parse_ports(value)


def test_input_bounds_and_normalization() -> None:
    assert parse_ports("443,80,443,65535") == (443, 80, 65535)
    assert normalize_hosts(["API.Example.invalid.", "api.example.invalid", "::1"]) == (
        "api.example.invalid",
        "::1",
    )
    for values in ([], ["example.invalid"] * 65, ["x" * 254]):
        with pytest.raises(PolicyError, match="invalid_hosts"):
            normalize_hosts(values)
    with pytest.raises(PolicyError, match="invalid_ports"):
        parse_ports(",".join(str(n) for n in range(1, 66)))
    with pytest.raises(PolicyError):
        validate_inventory(
            configuration(), tuple(f"h{n}.example.invalid" for n in range(5)), tuple(range(1, 65))
        )
    for bad_ports in ((True,), (0,), (65536,), (80, 80), ()):
        with pytest.raises(PolicyError):
            validate_inventory(configuration(), ("example.invalid",), bad_ports)


@pytest.mark.parametrize(
    "host",
    [
        "https://example.invalid",
        "example.invalid:80",
        "*.example.invalid",
        "127.0.0.1/32",
        "user:SECRET@example.invalid",
        "localhost",
        " 8.8.8.8",
        "127.01.0.1",
    ],
)
def test_reject_implicit_or_unsafe_targets(host: str) -> None:
    with pytest.raises(PolicyError, match="invalid_hosts"):
        normalize_hosts([host])


@pytest.mark.parametrize(
    "error,state",
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "SECRET"), "refused"),
        (OSError(10061, "SECRET"), "refused"),
        (TimeoutError("SECRET"), "timeout"),
        (OSError(errno.ETIMEDOUT, "SECRET"), "timeout"),
        (OSError(10060, "SECRET"), "timeout"),
        (OSError(errno.EHOSTUNREACH, "SECRET"), "unreachable"),
        (OSError(errno.ENETUNREACH, "SECRET"), "unreachable"),
        (OSError(10065, "SECRET"), "unreachable"),
        (OSError(errno.ECONNRESET, "SECRET"), "reset"),
        (OSError(10054, "SECRET"), "reset"),
        (PermissionError(errno.EACCES, "SECRET"), "local_error"),
        (OSError(errno.EMFILE, "SECRET"), "local_error"),
        (OSError(10047, "SECRET"), "local_error"),
        (OSError(65536, "SECRET"), "error"),
    ],
)
def test_os_errors_are_observations_not_guessed_closed_ports(error: OSError, state: str) -> None:
    config = configuration()
    resolver, connector = FakeQuery(), FakeTCP()
    resolver.add("example.invalid", "8.8.8.8")
    connector.errors[("8.8.8.8", 80)] = error
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (80,),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert report.assets[0].status == ("completed" if state == "refused" else "partial")
    assert [o.value for o in report.assets[0].observations if o.kind == "tcp.state"] == [state]
    assert not report.assets[0].evidence[-1].connected_address
    text = render_json(report)
    assert "SECRET" not in text and '"closed"' not in text and '"filtered"' not in text
    assert connect_outcome(error)[0] == state


def test_all_addresses_and_ports_share_one_snapshot_and_budget() -> None:
    config = configuration()
    resolver, connector = FakeQuery(), FakeTCP()
    resolver.add("example.invalid", "8.8.8.8", "2606:4700:4700::1111")
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (80, 443),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert report.ok and report.requests_used == 6 and len(resolver.calls) == 2
    assert (
        report.tcp is not None and report.tcp.tcp_attempts == 4 and report.tcp.dns_queries_used == 2
    )
    assert [c[1] for c in connector.calls] == [80, 80, 443, 443]
    assert [c[2] for c in connector.calls] == [2, 3, 4, 5]
    ids = [e.id for a in report.assets for e in a.evidence]
    assert len(set(ids)) == len(ids)
    payload = json.loads(render_json(report, Language.ID))
    assert payload["schema_version"] == "3" and "discovery" not in payload
    assert payload["tcp"]["payloads_sent"] is False
    assert payload["tcp"]["service_identification"] == "not_performed"
    assert payload["findings"] == [] and payload["vulnerability_assessment"] == "not_performed"
    assert all(e["url"] is None for a in payload["assets"] for e in a["evidence"])
    assert "tcp.state" in render_text(report, Language.ID)


@pytest.mark.parametrize(
    "addresses", [("8.8.8.8", "127.0.0.1"), ("8.8.8.8", "169.254.169.254"), ("8.8.8.8", "::1")]
)
def test_mixed_dns_address_sets_fail_closed(addresses: tuple[str, ...]) -> None:
    config, resolver, connector = configuration(), FakeQuery(), FakeTCP()
    resolver.add("example.invalid", *addresses)
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (80,),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert not connector.calls and report.assets[0].status == "denied"
    assert report.assets[0].reason == "address_forbidden"


def test_scope_port_and_auth_checks_precede_dns() -> None:
    config, resolver, connector = configuration(), FakeQuery(), FakeTCP()
    report = run_port_inventory(
        config,
        ("outside.invalid", "excluded.example.invalid", "127.0.0.1"),
        (80, 81),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert not resolver.calls and not connector.calls and report.requests_used == 0
    assert all(a.status == "denied" for a in report.assets)
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (81,),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert not resolver.calls and report.assets[0].reason == "port_denied"
    for bad in (replace(config, authorized=False), replace(config, profile="passive")):
        with pytest.raises(PolicyError):
            run_port_inventory(bad, ("example.invalid",), (80,), connector=connector)


def test_no_connections_on_dns_failure_negative_or_excess_addresses() -> None:
    for answer in (DNSAnswer("nxdomain"), DNSAnswer("no_address"), PolicyError("timeout")):
        config, resolver, connector = configuration(), FakeQuery(), FakeTCP()
        resolver.answers[("example.invalid", "A")] = answer
        resolver.answers[("example.invalid", "AAAA")] = DNSAnswer("no_address")
        report = run_port_inventory(
            config,
            ("example.invalid",),
            (80,),
            budget=new_budget(config),
            resolver=resolver,
            connector=connector,
        )
        assert not report.ok and not connector.calls
        assert all(o.kind != "tcp.state" for a in report.assets for o in a.observations)
    resolver.add("example.invalid", *(f"8.8.8.{n}" for n in range(1, 18)))
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (80,),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert report.assets[0].reason == "tcp_address_limit" and not connector.calls


def test_shared_budget_exhaustion_never_invents_tcp_attempts() -> None:
    config = configuration(*range(1, 65))
    resolver, connector = FakeQuery(), FakeTCP()
    resolver.add("example.invalid", "8.8.8.8")
    report = run_port_inventory(
        config,
        ("example.invalid",),
        tuple(range(1, 65)),
        budget=new_budget(config),
        resolver=resolver,
        connector=connector,
    )
    assert report.requests_used == 50 and len(connector.calls) == 48 and not report.ok
    assert report.tcp is not None and report.tcp.tcp_attempts == 48
    assert all(a.status == "skipped" and a.reason == "budget_exhausted" for a in report.assets[48:])
    assert all(e.source != "tcp_connect" for a in report.assets[48:] for e in a.evidence)


def test_partial_address_coverage_retains_actual_results_only() -> None:
    config = configuration(80, 81)
    resolver, connector, budget = FakeQuery(), FakeTCP(), new_budget(config)
    resolver.add("example.invalid", "8.8.8.8", "8.8.4.4")
    # Leave DNS plus a single endpoint attempt: second address and later ports stay unprobed.
    for _ in range(47):
        budget.reserve(Deadline(budget.clock.monotonic() + 10, budget.clock))
    report = run_port_inventory(
        config,
        ("example.invalid",),
        (80, 81),
        budget=budget,
        resolver=resolver,
        connector=connector,
    )
    assert report.requests_used == 50 and len(connector.calls) == 1
    assert report.assets[0].status == "partial" and report.assets[1].status == "skipped"
    assert report.assets[0].reason == "budget_exhausted"
    assert sum(e.source == "tcp_connect" for a in report.assets for e in a.evidence) == 1


def test_existing_report_schemas_do_not_gain_tcp_fields(tmp_path: Path) -> None:
    # Both older commands use the same augmented dataclasses; their wire shape is unchanged.
    from pasopati.discovery import run_discovery
    from pasopati.discovery_options import Source
    from pasopati.discovery_sources import prepare_discovery
    from pasopati.recon import Asset, Evidence, RunReport

    evidence = Evidence(
        "e1", "ip_literal", "8.8.8.8", "http://8.8.8.8/", "time", "literal", "PASOPATI", "test"
    )
    old = RunReport(
        "r",
        "test",
        "time",
        "time",
        "safe",
        1,
        False,
        (Asset("a", "http://8.8.8.8/", "completed", "allowed", (evidence,), ()),),
    )
    payload = old.to_dict()
    assert payload["schema_version"] == "1" and "tcp" not in payload
    assert '"port":' not in json.dumps(payload) and '"subject_name":' not in json.dumps(payload)
    path = tmp_path / "candidates.txt"
    path.write_text("api.example.invalid\n", encoding="utf-8")
    discovery = run_discovery(
        Config(), prepare_discovery("example.invalid", (Source.FILE,), candidates_file=path)
    )
    payload = discovery.to_dict()
    assert payload["schema_version"] == "2" and "tcp" not in payload
    assert '"port":' not in json.dumps(payload) and '"transport":' not in json.dumps(payload)


def test_mismatched_budget_is_rejected_before_dns() -> None:
    with pytest.raises(PolicyError, match="invalid_config"):
        run_port_inventory(
            configuration(), ("example.invalid",), (80,), budget=new_budget(Config())
        )


@pytest.mark.parametrize("refusal", [False, True])
def test_late_results_are_not_accepted_as_open_or_refused(refusal: bool) -> None:
    config, connector = configuration(), FakeTCP()
    budget = new_budget(config)

    class Late(FakeTCP):
        def connect(self, address: Address, port: int, deadline: Deadline, timeout: float) -> None:
            budget.clock.sleep(4)
            if refusal:
                raise ConnectionRefusedError(errno.ECONNREFUSED, "SECRET")

    report = run_port_inventory(config, ("8.8.8.8",), (80,), budget=budget, connector=connector)
    # Public literal IPs still need an explicit CIDR, independently of domain scope.
    assert not report.ok and not connector.calls
    config = replace(config, scope=ScopeConfig(allow_cidrs=("8.8.8.8/32",)))
    report = run_port_inventory(config, ("8.8.8.8",), (80,), budget=budget, connector=Late())
    assert report.assets[0].reason == "tcp_deadline_exceeded" and not report.ok


@pytest.mark.parametrize(
    "address,endpoint",
    [("8.8.8.8", ("8.8.8.8", 443)), ("2606:4700:4700::1111", ("2606:4700:4700::1111", 443, 0, 0))],
)
@pytest.mark.parametrize("error", [None, TimeoutError(), KeyboardInterrupt()])
def test_numeric_socket_cleanup_without_payloads(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
    endpoint: tuple[object, ...],
    error: BaseException | None,
) -> None:
    connection = Mock(spec=["settimeout", "connect", "close"])
    connection.connect.side_effect = error
    factory = Mock(return_value=connection)
    monkeypatch.setattr(socket, "socket", factory)
    budget = new_budget(configuration())
    deadline = Deadline(3, budget.clock)
    if error is None:
        NumericTCPConnector().connect(ipaddress.ip_address(address), 443, deadline, 3)
    else:
        with pytest.raises(type(error)):
            NumericTCPConnector().connect(ipaddress.ip_address(address), 443, deadline, 3)
    connection.connect.assert_called_once_with(endpoint)
    connection.close.assert_called_once_with()
    connection.settimeout.assert_called_once_with(3)
