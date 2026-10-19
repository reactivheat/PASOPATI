import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import asdict
from typing import cast
from unittest.mock import Mock

import pytest
from test_transport import FakeClock, FakeConnector, FakeExchange, FakeResolver, config

from pasopati.core.errors import PolicyError
from pasopati.limits import Deadline
from pasopati.profiles import Profile, get_profile
from pasopati.recon import run_recon
from pasopati.reports import render_json, render_text
from pasopati.targets import Address, Target
from pasopati.tls_metadata import TLSInfo, verified_metadata
from pasopati.transport import Exchange, Session, SocketConnector
from pasopati.web_metadata import web_observations


def fake_tls() -> Mock:
    connection = Mock(spec=ssl.SSLSocket)
    connection.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    connection.version.return_value = "TLSv1.3"
    connection.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    connection.getpeercert.side_effect = lambda binary_form=False: (
        b"DER"
        if binary_form
        else {
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "subject": ((("commonName", "SECRET"),),),
            "issuer": ((("commonName", "SECRET"),),),
            "subjectAltName": (
                ("DNS", "SECRET.invalid"),
                ("IP Address", "127.0.0.1"),
                ("email", "SECRET@example.invalid"),
            ),
        }
    )
    return connection


def test_verified_leaf_summary_is_bounded_and_private() -> None:
    connection = fake_tls()
    info = verified_metadata(cast(ssl.SSLSocket, connection))
    assert info.leaf_sha256 == hashlib.sha256(b"DER").hexdigest()
    assert (info.san_dns_count, info.san_ip_count, info.san_other_count) == (1, 1, 1)
    assert info.not_before == "2026-01-01T00:00:00+00:00"
    assert info.not_after == "2027-01-01T00:00:00+00:00"
    assert info.cipher_bits == 256 and "SECRET" not in json.dumps(asdict(info))


@pytest.mark.parametrize(
    "problem",
    [
        "no-verification",
        "no-hostname",
        "no-cert",
        "huge-cert",
        "bad-date",
        "huge-sans",
        "bad-cipher",
        "no-cipher",
        "old-protocol",
    ],
)
def test_invalid_or_unverified_metadata_never_claims_verified(problem: str) -> None:
    connection = fake_tls()
    if problem == "no-verification":
        connection.context.check_hostname = False
        connection.context.verify_mode = ssl.CERT_NONE
    elif problem == "no-hostname":
        connection.context.check_hostname = False
    elif problem == "no-cert":
        connection.getpeercert.side_effect = lambda binary_form=False: b"" if binary_form else {}
    elif problem == "huge-cert":
        connection.getpeercert.side_effect = lambda binary_form=False: b"x" * 65537
    elif problem == "bad-date":
        connection.getpeercert.side_effect = lambda binary_form=False: (
            b"DER" if binary_form else {"notBefore": "SECRET"}
        )
    elif problem == "huge-sans":
        original = connection.getpeercert()
        original["subjectAltName"] = (("DNS", "SECRET.invalid"),) * 4097
        connection.getpeercert.side_effect = lambda binary_form=False: (
            b"DER" if binary_form else original
        )
    elif problem == "bad-cipher":
        connection.cipher.return_value = ("SECRET\n", "TLSv1.3", 256)
    elif problem == "no-cipher":
        connection.cipher.return_value = None
    else:
        connection.version.return_value = "TLSv1.1"
    with pytest.raises(PolicyError, match="tls_metadata_unavailable"):
        verified_metadata(cast(ssl.SSLSocket, connection))


@pytest.mark.parametrize(
    "hsts,valid,seconds",
    [
        ("max-age=31536000; includeSubDomains; preload", True, 31536000),
        ("max-age=0", True, 0),
        ("MAX-AGE=42; includeSubDomains", True, 42),
        ("max-age=1; max-age=2", False, None),
        ("max-age=SECRET", False, None),
        ("max-age=-1", False, None),
        ("max-age=99999999999", False, None),
        ("includeSubDomains", False, None),
        ("max-age=1; preload=1", False, None),
        ("SECRET" * 2000, False, None),
    ],
)
def test_hsts_is_an_observation_not_a_security_verdict(
    hsts: str, valid: bool, seconds: int | None
) -> None:
    values = {
        o.kind: o.value for o in web_observations({"strict-transport-security": hsts}, https=False)
    }
    assert values["hsts.received_over_https"] is False
    assert values["hsts.syntax_supported"] is valid
    assert values.get("hsts.max_age_seconds") == seconds
    assert "SECRET" not in json.dumps(values)


def test_fixed_rules_do_not_export_versions_sources_nonces_or_unknown_values() -> None:
    headers = {
        "server": "nginx/SECRET",
        "x-powered-by": "PHP/SECRET",
        "content-security-policy": "default-src 'self'; script-src 'nonce-SECRET'; report-uri https://SECRET.invalid/key",
        "allow": "GET, HEAD, TRACE",
    }
    observations = web_observations(headers, https=True)
    values = {o.kind: o.value for o in observations}
    assert values["fingerprint.server"] == "nginx"
    assert values["fingerprint.x-powered-by"] == "php"
    assert all(
        o.confidence == "tentative"
        for o in observations
        if o.kind in {"fingerprint.server", "fingerprint.x-powered-by"}
    )
    assert values["fingerprint.server.rule"] == "header-prefix/1:server:nginx"
    assert values["csp.recognized_directives"] == ("default-src", "script-src", "report-uri")
    assert values["http.advertised_methods"] == ("GET", "HEAD", "TRACE")
    assert "SECRET" not in json.dumps(values)


@pytest.mark.parametrize(
    "headers",
    [
        {"server": "not-nginx SECRET", "x-powered-by": "phpish SECRET"},
        {"allow": "GET, SECRET"},
        {"allow": "GET,"},
        {"allow": "GET" * 3000},
        {"content-security-policy": "default-src SECRET,"},
        {"content-security-policy": "default-src SECRET;" * 65},
        {"content-security-policy": "SECRET" * 2000},
    ],
)
def test_unsupported_headers_are_qualified_not_dumped(headers: dict[str, str]) -> None:
    values = web_observations(headers, https=True)
    assert "SECRET" not in json.dumps([asdict(o) for o in values])
    assert not any(o.kind.startswith("fingerprint.") for o in values)


def test_endpoint_ids_hide_paths_and_are_run_local_without_extra_requests() -> None:
    urls = ("http://example.invalid/private?token=SECRET", "http://example.invalid/")

    def collect() -> tuple[object, list[str]]:
        connector = FakeConnector(
            [
                FakeExchange(302, headers={"Location": "/"}),
                FakeExchange(),
                FakeExchange(),
            ]
        )
        client = Session(config(), resolver=FakeResolver(), connector=connector, clock=FakeClock())
        report = run_recon(config(), urls, session=client, inspect_web=True)
        assert report.ok and report.requests_used == 3 and report.web is not None
        assert report.web.endpoints_observed == 2
        ids = [
            str(o.value)
            for a in report.assets
            for o in a.observations
            if o.kind == "web.endpoint_id"
        ]
        assert ids[1] == ids[2] and ids[0] != ids[1]
        assert hashlib.sha256(urls[0].encode()).hexdigest() not in ids
        payload = json.loads(render_json(report))
        assert (
            payload["schema_version"] == "4" and "tcp" not in payload and "discovery" not in payload
        )
        assert payload["findings"] == [] and payload["vulnerability_assessment"] == "not_performed"
        assert "SECRET" not in render_json(report) + render_text(report)
        assert "/private" not in render_json(report)
        return report, ids

    _, one = collect()
    _, two = collect()
    assert not set(one) & set(two)


class InspectedFake(FakeConnector):
    def open_inspected(
        self,
        target: Target,
        address: Address,
        method: str,
        deadline: Deadline,
        profile: Profile,
        on_tls: object,
    ) -> Exchange:
        from collections.abc import Callable

        callback = cast(Callable[[TLSInfo], None], on_tls)
        callback(verified_metadata(cast(ssl.SSLSocket, fake_tls())))
        raise OSError("SECRET")  # HTTP failed after a verified TLS handshake.


def test_tls_evidence_survives_http_failure_and_raw_error_is_not_exported() -> None:
    client = Session(
        config(), resolver=FakeResolver(), connector=InspectedFake(), clock=FakeClock()
    )
    report = run_recon(config(), ("https://example.invalid",), session=client, inspect_web=True)
    assert not report.ok and report.assets[0].status == "partial" and report.requests_used == 1
    assert [e.source for e in report.assets[0].evidence] == ["dns_resolution", "tls_handshake"]
    values = {o.kind: o.value for o in report.assets[0].observations}
    assert values["tls.verified"] is True and values["tls.protocol"] == "TLSv1.3"
    assert not any(o.kind == "http.status" for o in report.assets[0].observations)
    assert "SECRET" not in render_json(report)


def test_noninspecting_connector_cannot_invent_tls_metadata() -> None:
    connector = FakeConnector()
    client = Session(config(), resolver=FakeResolver(), connector=connector, clock=FakeClock())
    report = run_recon(config(), ("https://example.invalid",), session=client, inspect_web=True)
    assert report.assets[0].reason == "tls_metadata_unavailable" and not connector.calls
    assert not any(o.kind == "tls.verified" for o in report.assets[0].observations)


def test_plain_scan_schema_is_unchanged() -> None:
    connector = FakeConnector()
    client = Session(config(), resolver=FakeResolver(), connector=connector, clock=FakeClock())
    report = run_recon(config(), ("http://example.invalid",), session=client)
    payload = json.loads(render_json(report))
    assert payload["schema_version"] == "1" and "web" not in payload
    assert all(
        "port" not in e and "subject_name" not in e
        for a in payload["assets"]
        for e in a["evidence"]
    )


@pytest.mark.parametrize("failure", ["late", "metadata", "http"])
def test_inspected_socket_cleanup_and_no_unverified_or_late_event(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import pasopati.transport as module

    raw, wrapped, context = Mock(), fake_tls(), Mock()
    clock = FakeClock()

    def wrap(*args: object, **kwargs: object) -> object:
        if failure == "late":
            clock.sleep(4)
        return wrapped

    context.wrap_socket.side_effect = wrap
    if failure == "metadata":
        wrapped.getpeercert.side_effect = lambda binary_form=False: b"x" * 65537
    monkeypatch.setattr(socket, "socket", Mock(return_value=raw))
    monkeypatch.setattr(module, "tls_context", lambda: context)
    monkeypatch.setattr(http.client, "HTTPResponse", Mock(side_effect=OSError("SECRET")))
    events: list[TLSInfo] = []
    with pytest.raises((PolicyError, OSError)):
        SocketConnector().open_inspected(
            Target("example.invalid", "https", 443),
            ipaddress.ip_address("8.8.8.8"),
            "GET",
            Deadline(10, clock),
            get_profile("safe"),
            events.append,
        )
    raw.connect.assert_called_once_with(("8.8.8.8", 443))
    context.wrap_socket.assert_called_once_with(raw, server_hostname="example.invalid")
    wrapped.close.assert_called_once_with()
    if failure == "http":
        assert len(events) == 1
    else:
        assert not events
        wrapped.sendall.assert_not_called()
