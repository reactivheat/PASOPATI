import ipaddress
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_transport import FakeClock, FakeConnector, FakeExchange, FakeResolver

from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.discovery import provider_config, run_discovery
from pasopati.discovery_options import Source
from pasopati.discovery_sources import base_domain, parse_crtsh, prepare_discovery
from pasopati.dns_client import DNSAnswer, RecordType
from pasopati.i18n import Language
from pasopati.limits import Deadline, RequestBudget
from pasopati.profiles import get_profile
from pasopati.reports import render_json, render_text
from pasopati.transport import Session


def configuration(network: bool = False) -> Config:
    return Config(
        profile="safe" if network else "passive",
        authorized=network,
        scope=ScopeConfig(
            allow_domains=("example.invalid", "*.example.invalid"),
            exclude_domains=("excluded.example.invalid",),
        ),
    )


def candidates_file(tmp_path: Path, content: str = "api.example.invalid\n") -> Path:
    path = tmp_path / "private-candidates.txt"
    path.write_text(content, encoding="utf-8")
    return path


class FakeQuery:
    def __init__(self, *, wildcard: bool = False) -> None:
        self.calls: list[tuple[str, RecordType, float]] = []
        self.answers: dict[tuple[str, RecordType], DNSAnswer | PolicyError] = {}
        self.wildcard = wildcard

    def query(self, host: str, kind: RecordType, timeout: float) -> DNSAnswer:
        self.calls.append((host, kind, timeout))
        value = self.answers.get((host, kind))
        if value is None and host.startswith("pasopati-") and self.wildcard:
            value = (
                DNSAnswer("answer", (ipaddress.ip_address("8.8.4.4"),), 60)
                if kind == "A"
                else DNSAnswer("no_address")
            )
        value = value or DNSAnswer("nxdomain")
        if isinstance(value, PolicyError):
            raise value
        return value

    def add(self, name: str, *addresses: str) -> None:
        for kind in ("A", "AAAA"):
            values = tuple(
                ipaddress.ip_address(a)
                for a in addresses
                if ipaddress.ip_address(a).version == (4 if kind == "A" else 6)
            )
            self.answers[(name, kind)] = DNSAnswer("answer" if values else "no_address", values, 60)


def new_budget(config: Config) -> RequestBudget:
    return RequestBudget(get_profile(config.profile), FakeClock())


def test_offline_sources_deduplicate_without_network_and_keep_patterns(tmp_path: Path) -> None:
    path = candidates_file(
        tmp_path, "API.Example.invalid.\napi.example.invalid\n*.example.invalid\n"
    )
    words = tmp_path / "words.txt"
    words.write_text("api\nwww\n", encoding="utf-8")
    plan = prepare_discovery(
        "EXAMPLE.invalid.", (Source.FILE, Source.WORDLIST), candidates_file=path, wordlist=words
    )
    report = run_discovery(configuration(), plan)
    assert report.ok and report.requests_used == 0 and report.discovery is not None
    assert len(report.assets) == 3 and len(report.assets[0].evidence) == 2
    assert report.assets[1].target == "*.example.invalid"
    assert report.assets[1].reason == "wildcard_pattern"
    assert all(e.confidence == "tentative" for a in report.assets for e in a.evidence)
    payload = json.loads(render_json(report))
    assert payload["schema_version"] == "2" and payload["discovery"]["dns_queries_used"] == 0
    assert payload["findings"] == [] and payload["vulnerability_assessment"] == "not_performed"
    assert str(tmp_path) not in render_json(report) and "private-candidates.txt" not in render_json(
        report
    )
    assert len(report.discovery.sources[0].input_digest or "") == 64


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.invalid",
        "*.example.invalid",
        "127.0.0.1",
        "bad",
        "user:SECRET@example.invalid",
        "example.invalid/SECRET",
    ],
)
def test_invalid_base_domain(domain: str) -> None:
    with pytest.raises(PolicyError, match="invalid_domain"):
        base_domain(domain)


@pytest.mark.parametrize(
    "content",
    [
        "badexample.invalid\n",
        "api.example.invalid.evil.invalid\n",
        "https://api.example.invalid\n",
        "user:SECRET@example.invalid\n",
        "# nothing\n\n",
        "a..example.invalid\n",
    ],
)
def test_bad_local_input_rejected_entirely(tmp_path: Path, content: str) -> None:
    with pytest.raises(PolicyError, match="invalid_candidates"):
        prepare_discovery(
            "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path, content)
        )


def test_bounded_files_and_wordlist(tmp_path: Path) -> None:
    path = candidates_file(tmp_path, "x" * (1024 * 1024 + 1))
    with pytest.raises(PolicyError, match="invalid_candidates"):
        prepare_discovery("example.invalid", (Source.FILE,), candidates_file=path)
    path.write_bytes(b"\xff")
    with pytest.raises(PolicyError, match="candidates_io"):
        prepare_discovery("example.invalid", (Source.FILE,), candidates_file=path)
    path.write_text("\n".join(f"host{n}.example.invalid" for n in range(257)), encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid_candidates"):
        prepare_discovery("example.invalid", (Source.FILE,), candidates_file=path)
    path.write_text("*.invalid\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid_candidates"):
        prepare_discovery("example.invalid", (Source.WORDLIST,), wordlist=path)


def test_source_selection_and_provider_consent_are_explicit(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="invalid_discovery"):
        prepare_discovery("example.invalid", ())
    with pytest.raises(PolicyError, match="invalid_discovery"):
        prepare_discovery("example.invalid", (Source.FILE,))
    with pytest.raises(PolicyError, match="invalid_discovery"):
        prepare_discovery(
            "example.invalid", (Source.CRTSH,), candidates_file=candidates_file(tmp_path)
        )
    with pytest.raises(PolicyError, match="provider_consent_required"):
        prepare_discovery("example.invalid", (Source.CRTSH,))


@pytest.mark.parametrize(
    "data",
    [
        b"{}",
        b"not json SECRET",
        b"[NaN]",
        b'[{"name_value":1}]',
        b'[{"name_value":"api.example.invalid","name_value":"SECRET"}]',
    ],
)
def test_bad_provider_json(data: bytes) -> None:
    if data == b'[{"name_value":1}]':
        candidates, status = parse_crtsh(data, "example.invalid")
        assert not candidates and status.status == "partial"
    else:
        with pytest.raises(PolicyError, match="provider_invalid"):
            parse_crtsh(data, "example.invalid")


def test_provider_boundary_wildcard_idna_and_safe_references() -> None:
    payload = json.dumps(
        [
            {
                "id": 123,
                "name_value": "API.Example.invalid.\n*.example.invalid\napi.example.invalid\n"
                "example.invalid.evil.invalid\nbadexample.invalid\nuser@SECRET.invalid",
            }
        ]
    ).encode()
    candidates, status = parse_crtsh(payload, "example.invalid")
    assert [c.name for c in candidates] == ["api.example.invalid", "*.example.invalid"]
    assert all(c.reference == "certificate:123" for c in candidates)
    assert status.discarded == 3 and status.status == "completed"
    candidates, _ = parse_crtsh(
        b'[{"name_value":"API.xn--bcher-kva.invalid"}]', "xn--bcher-kva.invalid"
    )
    assert candidates[0].name == "api.xn--bcher-kva.invalid"


def test_provider_limit_is_partial_not_silent() -> None:
    data = json.dumps([{"name_value": f"h{n}.example.invalid"} for n in range(300)]).encode()
    names, status = parse_crtsh(data, "example.invalid")
    assert len(names) == 256 and status.reason == "candidate_limit" and status.status == "partial"


def test_provider_uses_pinned_session_and_shared_budget(tmp_path: Path) -> None:
    config = configuration(True)
    budget = new_budget(config)
    resolver = FakeQuery()
    resolver.add("api.example.invalid", "8.8.8.8")
    payload = b'[{"id":1,"name_value":"api.example.invalid\\n*.example.invalid"}]'
    connector = FakeConnector([FakeExchange(body=payload)])
    session = Session(
        provider_config(config), budget=budget, resolver=FakeResolver(), connector=connector
    )
    plan = prepare_discovery(
        "example.invalid",
        (Source.FILE, Source.CRTSH),
        candidates_file=candidates_file(tmp_path),
        allow_provider_queries=True,
        resolve=True,
    )
    report = run_discovery(config, plan, budget=budget, resolver=resolver, provider_session=session)
    assert report.discovery is not None and report.ok
    assert report.discovery.provider_http_attempts == 1 and report.discovery.dns_queries_used == 5
    assert report.requests_used == 6
    assert connector.calls[0][0].url == "https://crt.sh/?q=%25.example.invalid&output=json"
    assert connector.calls[0][1] == ipaddress.ip_address("8.8.8.8")
    assert len([e for e in report.assets[0].evidence if e.source in {"file", "crtsh"}]) == 2
    assert len(report.discovery.provider_evidence) == 2
    assert report.assets[1].reason == "wildcard_pattern"  # Never resolve '*.example.invalid'.
    assert not any("*" in name for name, _, _ in resolver.calls)


@pytest.mark.parametrize("location", ["https://outside.invalid/SECRET", "http://crt.sh/SECRET"])
def test_provider_redirect_cannot_widen_scope(location: str) -> None:
    config, plan = (
        configuration(True),
        prepare_discovery("example.invalid", (Source.CRTSH,), allow_provider_queries=True),
    )
    budget = new_budget(config)
    connector = FakeConnector([FakeExchange(302, headers={"Location": location})])
    report = run_discovery(
        config,
        plan,
        budget=budget,
        provider_session=Session(
            provider_config(config), budget=budget, resolver=FakeResolver(), connector=connector
        ),
    )
    assert not report.ok and len(connector.calls) == 1 and report.requests_used == 1
    assert report.discovery is not None and report.discovery.sources[0].status == "error"
    assert "SECRET" not in render_json(report)


@pytest.mark.parametrize(
    "status,body,reason",
    [
        (429, b"SECRET", "provider_unavailable"),
        (200, b"SECRET HTML", "provider_invalid"),
        (200, b"x" * 65537, "body_too_large"),
    ],
    ids=["rate-limit", "bad-json", "oversized"],
)
def test_provider_failure_is_not_reported_as_empty_success(
    status: int, body: bytes, reason: str
) -> None:
    config = configuration(True)
    budget = new_budget(config)
    plan = prepare_discovery("example.invalid", (Source.CRTSH,), allow_provider_queries=True)
    report = run_discovery(
        config,
        plan,
        budget=budget,
        provider_session=Session(
            provider_config(config),
            budget=budget,
            resolver=FakeResolver(),
            connector=FakeConnector([FakeExchange(status, body)]),
        ),
    )
    assert not report.ok and report.discovery is not None
    assert report.discovery.sources[0].reason == reason and not report.assets
    assert "SECRET" not in render_json(report)


def test_valid_empty_provider_response_is_distinct() -> None:
    config = configuration(True)
    budget = new_budget(config)
    plan = prepare_discovery("example.invalid", (Source.CRTSH,), allow_provider_queries=True)
    report = run_discovery(
        config,
        plan,
        budget=budget,
        provider_session=Session(
            provider_config(config),
            budget=budget,
            resolver=FakeResolver(),
            connector=FakeConnector([FakeExchange(body=b"[]")]),
        ),
    )
    assert report.ok and not report.assets and report.requests_used == 1


@pytest.mark.parametrize("wildcard", [False, True])
def test_dns_wildcard_changes_confidence_not_observation(tmp_path: Path, wildcard: bool) -> None:
    config = configuration(True)
    resolver = FakeQuery(wildcard=wildcard)
    resolver.add("api.example.invalid", "8.8.8.8", "2606:4700:4700::1111")
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path), resolve=True
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    asset = report.assets[0]
    assert report.ok and asset.reason == ("dns_wildcard_possible" if wildcard else "dns_resolved")
    assert report.discovery is not None and report.discovery.wildcard_checks[0].status == (
        "possible" if wildcard else "clear"
    )
    assert any(
        o.kind == "dns.addresses" and o.value == ("8.8.8.8", "2606:4700:4700::1111")
        for o in asset.observations
    )
    assert all(0 < timeout <= 3 for _, _, timeout in resolver.calls)
    text = render_text(report, Language.ID)
    assert "BUKAN berarti aman" in text and "\x1b" not in text


def test_scope_does_not_expand_for_random_wildcard_checks(tmp_path: Path) -> None:
    config = replace(
        configuration(True),
        scope=ScopeConfig(allow_domains=("example.invalid", "api.example.invalid")),
    )
    resolver = FakeQuery()
    resolver.add("api.example.invalid", "8.8.8.8")
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path), resolve=True
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert len(resolver.calls) == 2 and report.assets[0].reason == "dns_wildcard_unchecked"
    assert (
        report.discovery is not None
        and report.discovery.wildcard_checks[0].status == "not_checked_scope"
    )


def test_excluded_candidates_are_not_queried(tmp_path: Path) -> None:
    config = configuration(True)
    resolver = FakeQuery()
    plan = prepare_discovery(
        "example.invalid",
        (Source.FILE,),
        candidates_file=candidates_file(tmp_path, "excluded.example.invalid\n"),
        resolve=True,
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert not resolver.calls and report.assets[0].status == "denied" and not report.ok


@pytest.mark.parametrize(
    "answer,reason,state",
    [
        (DNSAnswer("nxdomain"), "dns_nxdomain", "completed"),
        (DNSAnswer("no_address"), "dns_no_address", "completed"),
        (PolicyError("timeout"), "timeout", "partial"),
        (PolicyError("SECRET"), "dns_failed", "partial"),
        (DNSAnswer("answer", (ipaddress.ip_address("127.0.0.1"),)), "address_forbidden", "denied"),
    ],
)
def test_dns_negatives_failures_and_address_policy_are_distinct(
    tmp_path: Path, answer: DNSAnswer | PolicyError, reason: str, state: str
) -> None:
    config = configuration(True)
    resolver = FakeQuery()
    for kind in ("A", "AAAA"):
        resolver.answers[("api.example.invalid", kind)] = answer
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path), resolve=True
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert report.assets[0].reason == reason and report.assets[0].status == state
    assert "SECRET" not in render_json(report)


def test_inconsistent_dns_answers_are_partial(tmp_path: Path) -> None:
    config, resolver = configuration(True), FakeQuery()
    resolver.add("api.example.invalid", "8.8.8.8")
    resolver.answers[("api.example.invalid", "AAAA")] = DNSAnswer("nxdomain")
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path), resolve=True
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert report.assets[0].reason == "dns_inconsistent" and not report.ok


def test_dns_budget_is_shared_across_candidates_and_wildcard_probes(tmp_path: Path) -> None:
    config, resolver = configuration(True), FakeQuery()
    names = [f"h{n}.example.invalid" for n in range(30)]
    for name in names:
        resolver.add(name, "8.8.8.8")
    plan = prepare_discovery(
        "example.invalid",
        (Source.FILE,),
        candidates_file=candidates_file(tmp_path, "\n".join(names)),
        resolve=True,
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert report.requests_used == len(resolver.calls) == 50 and not report.ok
    assert any(a.status == "skipped" and a.reason == "budget_exhausted" for a in report.assets)
    assert report.discovery is not None and len(report.discovery.wildcard_checks) == 1


def test_shared_budget_cannot_be_reset_by_a_second_session() -> None:
    config = configuration(True)
    budget = new_budget(config)
    first = Session(
        provider_config(config), budget=budget, resolver=FakeResolver(), connector=FakeConnector()
    )
    first.fetch("https://crt.sh/")
    for _ in range(49):
        budget.reserve(Deadline(budget.clock.monotonic() + 10, budget.clock))
    second = Session(
        provider_config(config), budget=budget, resolver=FakeResolver(), connector=FakeConnector()
    )
    with pytest.raises(PolicyError, match="budget_exhausted"):
        second.fetch("https://crt.sh/")


def test_active_discovery_requires_authorization_and_safe_profile(tmp_path: Path) -> None:
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path), resolve=True
    )
    with pytest.raises(PolicyError, match="not_authorized"):
        run_discovery(configuration(), plan)
    with pytest.raises(PolicyError, match="passive_profile"):
        run_discovery(replace(configuration(), authorized=True), plan)


def test_wildcard_work_is_bounded_per_parent(tmp_path: Path) -> None:
    config, resolver = configuration(True), FakeQuery()
    names = [f"api.p{n}.example.invalid" for n in range(6)]
    for name in names:
        resolver.add(name, "8.8.8.8")
    plan = prepare_discovery(
        "example.invalid",
        (Source.FILE,),
        resolve=True,
        candidates_file=candidates_file(tmp_path, "\n".join(names)),
    )
    report = run_discovery(config, plan, budget=new_budget(config), resolver=resolver)
    assert report.discovery is not None
    assert [c.status for c in report.discovery.wildcard_checks] == ["clear"] * 4 + [
        "not_checked_limit"
    ] * 2
    assert len([name for name, _, _ in resolver.calls if name.startswith("pasopati-")]) == 12
    assert [a.status for a in report.assets[-2:]] == ["partial", "partial"]
    assert not report.ok


def test_dns_deadline_rejects_late_answers_without_inventing_response(tmp_path: Path) -> None:
    config = configuration(True)
    budget = new_budget(config)

    class Slow(FakeQuery):
        def query(self, host: str, kind: RecordType, timeout: float) -> DNSAnswer:
            budget.clock.sleep(11)
            return DNSAnswer("answer", (ipaddress.ip_address("8.8.8.8"),))

    # Exact host authorization prevents wildcard probes; only the actual candidate is queried.
    config = replace(
        config, scope=ScopeConfig(allow_domains=("example.invalid", "api.example.invalid"))
    )
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), resolve=True, candidates_file=candidates_file(tmp_path)
    )
    report = run_discovery(config, plan, budget=budget, resolver=Slow())
    assert report.assets[0].reason == "timeout" and report.requests_used == 1
    assert report.assets[0].evidence[-1].source == "dns_query_attempt"
    assert not report.assets[0].evidence[-1].addresses


def test_invalid_prepared_plan_cannot_bypass_domain_boundary(tmp_path: Path) -> None:
    plan = prepare_discovery(
        "example.invalid", (Source.FILE,), candidates_file=candidates_file(tmp_path)
    )
    bad = replace(plan, candidates=(replace(plan.candidates[0], name="outside.invalid"),))
    with pytest.raises(PolicyError, match="invalid_candidates"):
        run_discovery(configuration(True), bad)


def test_provider_policy_never_grants_private_or_target_scope() -> None:
    policy = provider_config(configuration(True))
    assert policy.scope.allow_domains == ("crt.sh",) and policy.scope.ports == (443,)
    assert not policy.scope.allow_private and not policy.scope.allow_cidrs


def test_deep_or_oversized_provider_payload_fails_cleanly() -> None:
    with pytest.raises(PolicyError, match="provider_invalid"):
        parse_crtsh(b"[" * 2000 + b"0" + b"]" * 2000, "example.invalid")
    with pytest.raises(PolicyError, match="body_too_large"):
        parse_crtsh(b"x" * 65537, "example.invalid")
