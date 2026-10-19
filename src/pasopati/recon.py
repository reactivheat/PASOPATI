"""Explicit-seed inventory only. Collection, evidence and outcomes, not vulnerability claims."""

import hashlib
import hmac
import secrets
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urljoin
from uuid import uuid4

from pasopati import get_version
from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.profiles import get_profile
from pasopati.redaction import header_summary, page_title, report_url
from pasopati.targets import parse_target
from pasopati.transport import OBSERVED_HEADERS, Hop, Resolution, Session, TLSHandshake
from pasopati.web_metadata import RULESET, web_observations

MAX_TARGETS = 256
MAX_INPUT_BYTES = 1024 * 1024
MAX_URL_LENGTH = 4096
REASONS = frozenset(
    {
        "invalid_target",
        "excluded",
        "not_allowlisted",
        "address_forbidden",
        "port_denied",
        "timeout",
        "dns_failed",
        "network_failed",
        "redirect_loop",
        "redirect_limit",
        "https_downgrade",
        "invalid_response",
        "encoding_denied",
        "body_too_large",
        "method_denied",
        "budget_exhausted",
        "not_authorized",
        "passive_profile",
        "tls_verification_failed",
        "tls_failed",
        "tls_metadata_unavailable",
    }
)
Outcome = Literal["completed", "partial", "denied", "error", "skipped"]
Value = str | int | bool | tuple[str, ...] | None


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def normalize_targets(values: Iterable[str]) -> tuple[str, ...]:
    """Validate the WHOLE bounded batch before any DNS; preserve input order."""
    result: dict[str, None] = {}
    total = 0
    for count, value in enumerate(values, 1):
        try:
            total += len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise PolicyError("invalid_target", 2) from exc
        if count > MAX_TARGETS or total > MAX_INPUT_BYTES or len(value) > MAX_URL_LENGTH:
            raise PolicyError("invalid_targets", 2)
        result[parse_target(value, require_url=True).url] = None
    if not result:
        raise PolicyError("invalid_targets", 2)
    return tuple(result)


def load_targets(path: Path) -> tuple[str, ...]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise PolicyError("invalid_targets", 2)
        lines = data.decode("utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PolicyError("targets_io", 2) from exc
    return tuple(
        line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
    )


def require_network(config: Config) -> None:
    if not config.authorized:
        raise PolicyError("not_authorized")
    if not get_profile(config.profile).network_enabled:
        raise PolicyError("passive_profile")


@dataclass(frozen=True)
class Observation:
    kind: str
    value: Value
    evidence_id: str
    confidence: str = "observed"


@dataclass(frozen=True)
class Evidence:
    id: str
    source: str
    authorized_target: str
    url: str | None
    collected_at: str
    method: str
    tool: str
    tool_version: str
    confidence: str = "observed"
    addresses: tuple[str, ...] = ()
    connected_address: str | None = None
    http_status: int | None = None
    redirect_destination: str | None = None
    subject_name: str | None = None
    query_name: str | None = None
    query_type: str | None = None
    port: int | None = None
    transport: str | None = None


@dataclass(frozen=True)
class Asset:
    id: str
    target: str
    status: Outcome
    reason: str
    evidence: tuple[Evidence, ...]
    observations: tuple[Observation, ...]


@dataclass(frozen=True)
class SourceStatus:
    source: str
    status: str
    reason: str
    candidates: int = 0
    discarded: int = 0
    input_digest: str | None = None


@dataclass(frozen=True)
class WildcardCheck:
    parent: str
    status: str
    evidence: tuple[Evidence, ...] = ()
    observations: tuple[Observation, ...] = ()


@dataclass(frozen=True)
class DiscoveryDetails:
    domain: str
    sources: tuple[SourceStatus, ...]
    resolve_requested: bool
    provider_queries_disclosed: bool
    dns_queries_used: int = 0
    provider_http_attempts: int = 0
    provider_evidence: tuple[Evidence, ...] = ()
    wildcard_checks: tuple[WildcardCheck, ...] = ()


@dataclass(frozen=True)
class TCPDetails:
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    dns_queries_used: int
    tcp_attempts: int
    max_addresses_per_host: int
    payloads_sent: bool = False
    service_identification: str = "not_performed"


@dataclass(frozen=True)
class WebDetails:
    endpoints_observed: int
    endpoint_identity: str = "hmac-sha256-per-run/1"
    fingerprint_ruleset: str = RULESET
    tls_coverage: str = "verified_leaf_and_single_negotiation_only"
    endpoint_mapping: str = "explicit_urls_and_allowed_redirects_no_crawl"


@dataclass(frozen=True)
class RunReport:
    run_id: str
    tool_version: str
    started_at: str
    finished_at: str
    profile: str
    requests_used: int
    include_titles: bool
    assets: tuple[Asset, ...]
    discovery: DiscoveryDetails | None = None
    tcp: TCPDetails | None = None
    web: WebDetails | None = None

    @property
    def ok(self) -> bool:
        if self.discovery is not None:
            return all(s.status == "completed" for s in self.discovery.sources) and all(
                a.status == "completed" for a in self.assets
            )
        return bool(self.assets) and all(a.status == "completed" for a in self.assets)

    @property
    def status(self) -> str:
        if self.ok:
            return "completed"
        collected = any(a.evidence for a in self.assets) or (
            self.discovery is not None and bool(self.discovery.provider_evidence)
        )
        return "partial" if collected else "failed"

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        if self.web is None:
            del data["web"]
        if self.tcp is None:
            del data["tcp"]  # Preserve existing schema 1/2 shapes, including nested evidence.
        if self.tcp is None and self.web is None:
            evidence_groups = [a["evidence"] for a in data["assets"]]
            if data["discovery"] is not None:
                evidence_groups.append(data["discovery"]["provider_evidence"])
                evidence_groups.extend(c["evidence"] for c in data["discovery"]["wildcard_checks"])
            for group in evidence_groups:
                for item in group:
                    del item["port"], item["transport"]
        if self.discovery is None:
            del data["discovery"]  # Preserve M2A's schema-1 shape.
        if self.discovery is None and self.tcp is None and self.web is None:
            for asset in data["assets"]:
                for item in asset["evidence"]:
                    for key in ("subject_name", "query_name", "query_type"):
                        del item[key]
        return {
            "schema_version": "4"
            if self.web is not None
            else "3"
            if self.tcp is not None
            else ("2" if self.discovery is not None else "1"),
            "report_type": "pasopati.recon",
            "tool": "PASOPATI",
            **data,
            "ok": self.ok,
            "status": self.status,
            "summary": {
                state: sum(a.status == state for a in self.assets)
                for state in ("completed", "partial", "denied", "error", "skipped")
            },
            "findings": [],
            "vulnerability_assessment": "not_performed",
            "coverage": (
                "explicit_web_endpoints_verified_tls_no_crawl_or_vulnerability_assessment"
                if self.web is not None
                else "explicit_tcp_connect_only_no_payloads_or_service_identification"
                if self.tcp is not None
                else "bounded_subdomain_candidates_no_automatic_http_probing"
                if self.discovery is not None
                else "explicit_urls_only_no_crawling_or_subdomain_discovery"
            ),
            "redaction": "url_paths_and_queries_withheld_header_values_restricted",
        }


def run_recon(
    config: Config,
    targets: Iterable[str],
    *,
    include_titles: bool = False,
    inspect_web: bool = False,
    session: Session | None = None,
    timestamp: Callable[[], str] = utc_now,
) -> RunReport:
    urls = normalize_targets(targets)
    require_network(config)
    version = get_version()
    client = session or Session(config)
    if client.config != config:
        raise PolicyError("invalid_config", 2)
    started = timestamp()
    endpoint_key = secrets.token_bytes(32) if inspect_web else b""
    endpoint_ids: set[str] = set()
    assets: list[Asset] = []
    for index, url in enumerate(urls, 1):
        identifier = f"asset-{index:04d}"
        evidence: list[Evidence] = []
        observations: list[Observation] = []
        trace_urls: list[str] = [url]

        def observe(
            event: Resolution | Hop | TLSHandshake,
            *,
            identifier: str = identifier,
            url: str = url,
            evidence: list[Evidence] = evidence,
            observations: list[Observation] = observations,
            trace_urls: list[str] = trace_urls,
        ) -> None:
            eid = f"{identifier}-e{len(evidence) + 1:03d}"
            common = Evidence(
                id=eid,
                authorized_target=report_url(url),
                url=report_url(event.url),
                collected_at=timestamp(),
                tool="PASOPATI",
                tool_version=version,
                source="",
                method="",
            )
            if isinstance(event, Resolution):
                evidence.append(
                    replace(
                        common,
                        source="dns_resolution" if event.dns_performed else "ip_literal",
                        method="DNS A+AAAA" if event.dns_performed else "literal",
                        addresses=event.addresses,
                    )
                )
                observations.append(
                    Observation(
                        "dns.addresses" if event.dns_performed else "target.literal_address",
                        event.addresses,
                        eid,
                    )
                )
                return
            if isinstance(event, TLSHandshake):
                evidence.append(
                    replace(
                        common,
                        source="tls_handshake",
                        method="TLS handshake",
                        connected_address=event.connected_address,
                        addresses=(event.connected_address,),
                        port=parse_target(event.url, require_url=True).port,
                        transport="tls",
                    )
                )
                observations.append(Observation("tls.verified", True, eid))
                for key, value in asdict(event.info).items():
                    observations.append(Observation("tls." + key, value, eid))
                return
            try:
                destination = urljoin(event.url, event.location) if event.location else None
            except ValueError:
                destination = "[invalid-url]"
            trace_urls.append(event.url)
            if destination:
                trace_urls.append(destination)
            evidence.append(
                replace(
                    common,
                    source="http_response",
                    method="GET",
                    addresses=event.resolved_addresses,
                    connected_address=event.connected_address,
                    http_status=event.status,
                    redirect_destination=report_url(destination) if destination else None,
                )
            )
            observations.append(Observation("http.status", event.status, eid))
            headers = dict(event.headers)
            if inspect_web:
                endpoint = hmac.new(
                    endpoint_key, event.url.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                endpoint_ids.add(endpoint)
                observations.append(Observation("web.endpoint_id", endpoint, eid))
                if type(event.http_version) is int and event.http_version in {10, 11}:
                    observations.append(
                        Observation("http.version", f"HTTP/1.{event.http_version - 10}", eid)
                    )
                for item in web_observations(
                    headers, https=parse_target(event.url, require_url=True).scheme == "https"
                ):
                    observations.append(Observation(item.kind, item.value, eid, item.confidence))
            for header in OBSERVED_HEADERS:
                key = header.lower()
                value = header_summary(key, headers[key]) if key in headers else None
                observations.append(
                    Observation(
                        "header." + key,
                        value,
                        eid,
                        "tentative" if key in {"server", "x-powered-by"} and value else "observed",
                    )
                )

        state: Outcome = "completed"
        reason = "observed"
        try:
            result = (
                client.fetch(
                    url, observe=observe, sample_body=True, inspect_web=True, observe_tls=observe
                )
                if inspect_web
                else client.fetch(url, observe=observe, sample_body=True)
            )
            if result.body_truncated:
                state, reason = "partial", "body_sampled"
            if include_titles:
                title = page_title(result.body, result.content_type, tuple(trace_urls))
                if title is not None:
                    observations.append(Observation("http.title", title, evidence[-1].id))
            observations.append(
                Observation("http.body_sample_truncated", result.body_truncated, evidence[-1].id)
            )
        except PolicyError as exc:
            reason = exc.code if exc.code in REASONS else "network_failed"
            if evidence:
                state = "partial"
            elif reason == "budget_exhausted":
                state = "skipped"
            elif reason in {"excluded", "not_allowlisted", "address_forbidden", "port_denied"}:
                state = "denied"
            else:
                state = "error"
        assets.append(
            Asset(identifier, report_url(url), state, reason, tuple(evidence), tuple(observations))
        )
    return RunReport(
        str(uuid4()),
        version,
        started,
        timestamp(),
        config.profile,
        client.requests_used,
        include_titles,
        tuple(assets),
        web=WebDetails(len(endpoint_ids)) if inspect_web else None,
    )
