import json
from pathlib import Path

import pytest
from test_transport import FakeClock, FakeConnector, FakeExchange, FakeResolver, config

from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.i18n import Language
from pasopati.recon import load_targets, normalize_targets, run_recon
from pasopati.redaction import header_summary, page_title, report_url
from pasopati.reports import prepare_output, render_json, render_text, write_reports
from pasopati.transport import Session


def client(exchanges: list[FakeExchange]) -> Session:
    return Session(
        config(), resolver=FakeResolver(), connector=FakeConnector(exchanges), clock=FakeClock()
    )


def test_normalization_and_deduplication() -> None:
    assert normalize_targets(["https://EXAMPLE.invalid:443", "https://example.invalid/"]) == (
        "https://example.invalid/",
    )


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["example.invalid"],
        ["https://u:secret@example.invalid"],
        ["https://example.invalid/"] * 257,
        ["https://example.invalid/" + "x" * 4096],
    ],
)
def test_invalid_batch_before_dns(values: list[str]) -> None:
    resolver = FakeResolver()
    session = Session(config(), resolver=resolver, connector=FakeConnector(), clock=FakeClock())
    with pytest.raises(PolicyError):
        run_recon(config(), values, session=session)
    assert not resolver.calls


def test_target_file_bounded_utf8_and_comments(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_bytes(b"\xef\xbb\xbf# comment\n https://example.invalid/ \n\n")
    assert load_targets(path) == ("https://example.invalid/",)
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(PolicyError, match="invalid_targets"):
        load_targets(path)
    path.write_bytes(b"\xff")
    with pytest.raises(PolicyError, match="targets_io"):
        load_targets(path)


def test_inventory_has_provenance_not_vulnerability_claims() -> None:
    session = client(
        [
            FakeExchange(
                404,
                b"<title>Public demo</title>",
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "nginx/1.2 arbitrary-secret",
                    "Set-Cookie": "secret=DO_NOT_PERSIST",
                    "Content-Security-Policy": "nonce-SECRET",
                },
            )
        ]
    )
    report = run_recon(
        config(),
        ["https://example.invalid/"],
        session=session,
        timestamp=lambda: "2026-10-20T01:02:03+00:00",
    )
    asset = report.assets[0]
    assert report.ok and asset.status == "completed"  # 404 is an observed response, not failure.
    assert [e.source for e in asset.evidence] == ["dns_resolution", "http_response"]
    response = asset.evidence[-1]
    assert response.connected_address == "8.8.8.8" and response.http_status == 404
    assert response.method == "GET" and response.tool_version == report.tool_version
    assert response.collected_at == report.started_at
    values = {o.kind: o.value for o in asset.observations}
    assert values["header.server"] == "nginx"
    assert values["header.content-security-policy"] == "present"
    assert values["header.x-frame-options"] is None
    assert "http.title" not in values  # Explicit opt-in, not an accidental sensitive-data sink.
    payload = json.loads(render_json(report))
    assert payload["findings"] == [] and payload["vulnerability_assessment"] == "not_performed"
    assert {o.evidence_id for o in asset.observations} <= {e.id for e in asset.evidence}
    serialized = render_json(report) + render_text(report)
    for forbidden in ("DO_NOT_PERSIST", "arbitrary-secret", "nonce-SECRET", "Public demo"):
        assert forbidden not in serialized


def test_redirect_evidence_and_partial_denial_are_preserved() -> None:
    session = client(
        [FakeExchange(302, headers={"Location": "http://outside.invalid/secret?q=TOKEN"})]
    )
    report = run_recon(config(), ["http://example.invalid/"], session=session)
    assert not report.ok and report.status == "partial" and report.requests_used == 1
    assert report.assets[0].reason == "not_allowlisted"
    assert report.assets[0].evidence[-1].redirect_destination == (
        "http://outside.invalid/[path-redacted]?[redacted]"
    )
    assert "TOKEN" not in render_json(report)


def test_malformed_redirect_is_an_explicit_partial_result() -> None:
    report = run_recon(
        config(),
        ["https://example.invalid/"],
        session=client([FakeExchange(302, headers={"Location": "https://[invalid/SECRET"})]),
    )
    assert report.assets[0].reason == "invalid_target"
    assert report.assets[0].status == "partial"
    assert "SECRET" not in render_json(report)


def test_dns_proof_survives_connect_failure() -> None:
    class Broken(FakeConnector):
        def open(self, *args: object, **kwargs: object) -> FakeExchange:
            raise OSError("SECRET error not for output")

    session = Session(config(), resolver=FakeResolver(), connector=Broken(), clock=FakeClock())
    report = run_recon(config(), ["https://example.invalid/"], session=session)
    assert report.assets[0].reason == "network_failed"
    assert report.assets[0].evidence[0].connected_address is None
    assert "SECRET" not in render_json(report)


def test_shared_budget_reports_unfinished_targets() -> None:
    session = client([FakeExchange() for _ in range(50)])
    report = run_recon(
        config(), [f"https://example.invalid/{n}" for n in range(52)], session=session
    )
    assert report.requests_used == 50
    assert sum(a.status == "completed" for a in report.assets) == 50
    assert [a.status for a in report.assets[-2:]] == ["skipped", "skipped"]
    assert report.assets[-1].reason == "budget_exhausted" and not report.ok


def test_sample_limit_is_partial_and_legacy_transport_still_strict() -> None:
    report = run_recon(
        config(), ["https://example.invalid/"], session=client([FakeExchange(body=b"x" * 65537)])
    )
    assert report.assets[0].status == "partial" and report.assets[0].reason == "body_sampled"
    session = client([FakeExchange(body=b"x" * 65537)])
    with pytest.raises(PolicyError, match="body_too_large"):
        session.fetch("https://example.invalid/")


@pytest.mark.parametrize(
    "configuration,reason",
    [(Config(), "not_authorized"), (Config(authorized=True), "passive_profile")],
)
def test_network_gates_for_recon(configuration: Config, reason: str) -> None:
    with pytest.raises(PolicyError, match=reason):
        run_recon(configuration, ["https://example.invalid/"])


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.invalid/", "https://example.invalid/"),
        (
            "https://example.invalid/reset/SECRET?token=SECRET",
            "https://example.invalid/[path-redacted]?[redacted]",
        ),
        ("https://user:SECRET@example.invalid", "[invalid-url]"),
        ("http://[::1]:8765/path", "http://[::1]:8765/[path-redacted]"),
    ],
)
def test_url_redaction(url: str, expected: str) -> None:
    assert report_url(url) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"<title>Hello &amp; world</title>", "Hello & world"),
        (b"<title>token=SECRET</title>", "[redacted]"),
        (b"<title>user@example.invalid</title>", "[redacted]"),
        (b"<title>SECRET</title>", "[redacted]"),
        (b"<title>incomplete", None),
        (b"<title>Public\x1b[31m page</title>", "Public[31m page"),
    ],
)
def test_opt_in_title_redaction(body: bytes, expected: str | None) -> None:
    assert page_title(body, "text/html", ("https://example.invalid/?key=SECRET",)) == expected


def test_title_is_opt_in_and_header_values_are_restricted() -> None:
    report = run_recon(
        config(),
        ["https://example.invalid/"],
        include_titles=True,
        session=client(
            [
                FakeExchange(
                    body=b"<title>Public demo</title>", headers={"Content-Type": "text/html"}
                )
            ]
        ),
    )
    assert any(
        o.kind == "http.title" and o.value == "Public demo" for o in report.assets[0].observations
    )
    assert header_summary("content-security-policy", "SECRET") == "present"
    assert header_summary("x-frame-options", "DENY") == "deny"


def test_report_output_never_overwrites_and_renderers_share_data(tmp_path: Path) -> None:
    report = run_recon(config(), ["https://example.invalid/"], session=client([FakeExchange()]))
    output = tmp_path / "reports" / "new-run"
    prepare_output(output)
    write_reports(report, output, Language.ID)
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    text = (output / "report.txt").read_text(encoding="utf-8")
    assert payload["run_id"] == report.run_id and report.assets[0].id in text
    assert "BUKAN berarti aman" in text and "\x1b" not in text
    original = (output / "report.json").read_bytes()
    with pytest.raises(PolicyError, match="report_io"):
        prepare_output(output)
    with pytest.raises(PolicyError, match="report_io"):
        write_reports(report, output)
    assert (output / "report.json").read_bytes() == original
