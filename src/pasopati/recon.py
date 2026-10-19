"""Explicit-seed inventory only. Collection, evidence and outcomes, not vulnerability claims."""

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
from pasopati.transport import OBSERVED_HEADERS, Hop, Resolution, Session

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
    url: str
    collected_at: str
    method: str
    tool: str
    tool_version: str
    confidence: str = "observed"
    addresses: tuple[str, ...] = ()
    connected_address: str | None = None
    http_status: int | None = None
    redirect_destination: str | None = None


@dataclass(frozen=True)
class Asset:
    id: str
    target: str
    status: Outcome
    reason: str
    evidence: tuple[Evidence, ...]
    observations: tuple[Observation, ...]


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

    @property
    def ok(self) -> bool:
        return bool(self.assets) and all(a.status == "completed" for a in self.assets)

    @property
    def status(self) -> str:
        if self.ok:
            return "completed"
        return "partial" if any(a.evidence for a in self.assets) else "failed"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "report_type": "pasopati.recon",
            "tool": "PASOPATI",
            **asdict(self),
            "ok": self.ok,
            "status": self.status,
            "summary": {
                state: sum(a.status == state for a in self.assets)
                for state in ("completed", "partial", "denied", "error", "skipped")
            },
            "findings": [],
            "vulnerability_assessment": "not_performed",
            "coverage": "explicit_urls_only_no_crawling_or_subdomain_discovery",
            "redaction": "url_paths_and_queries_withheld_header_values_restricted",
        }


def run_recon(
    config: Config,
    targets: Iterable[str],
    *,
    include_titles: bool = False,
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
    assets: list[Asset] = []
    for index, url in enumerate(urls, 1):
        identifier = f"asset-{index:04d}"
        evidence: list[Evidence] = []
        observations: list[Observation] = []
        trace_urls: list[str] = [url]

        def observe(
            event: Resolution | Hop,
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
            result = client.fetch(url, observe=observe, sample_body=True)
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
    )
