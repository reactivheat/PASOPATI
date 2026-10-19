"""Bounded candidate acquisition/parsing. No implicit providers or network clients."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from pasopati.core.errors import PolicyError
from pasopati.discovery_options import Source as Source
from pasopati.recon import SourceStatus
from pasopati.targets import domain_rule

MAX_CANDIDATES = 256
MAX_ENTRIES = 4096
MAX_INPUT_BYTES = 1024 * 1024
MAX_PROVIDER_BYTES = 65536
MAX_JSON_DEPTH = 32


@dataclass(frozen=True)
class Candidate:
    name: str
    source: str
    reference: str


@dataclass(frozen=True)
class DiscoveryPlan:
    domain: str
    sources: tuple[Source, ...]
    candidates: tuple[Candidate, ...]
    source_status: tuple[SourceStatus, ...]
    resolve: bool
    allow_provider_queries: bool


def base_domain(value: str) -> str:
    try:
        normalized = domain_rule(value)
    except PolicyError as exc:
        raise PolicyError("invalid_domain", 2) from exc
    if normalized.startswith("*."):
        raise PolicyError("invalid_domain", 2)
    return normalized


def candidate_name(value: str, domain: str) -> str:
    normalized = domain_rule(value)
    concrete = normalized[2:] if normalized.startswith("*.") else normalized
    if concrete != domain and not concrete.endswith("." + domain):
        raise PolicyError("invalid_candidates", 2)
    return normalized


def _read_lines(path: Path) -> tuple[tuple[tuple[int, str], ...], str]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise PolicyError("invalid_candidates", 2)
        text = data.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise PolicyError("candidates_io", 2) from exc
    lines = tuple(
        (n, line.strip())
        for n, line in enumerate(text.splitlines(), 1)
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not lines or len(lines) > MAX_ENTRIES:
        raise PolicyError("invalid_candidates", 2)
    return lines, hashlib.sha256(data).hexdigest()


def prepare_discovery(
    domain: str,
    sources: tuple[Source, ...],
    *,
    candidates_file: Path | None = None,
    wordlist: Path | None = None,
    resolve: bool = False,
    allow_provider_queries: bool = False,
) -> DiscoveryPlan:
    domain = base_domain(domain)
    sources = tuple(dict.fromkeys(sources))
    if (
        not sources
        or (Source.FILE in sources) != (candidates_file is not None)
        or (Source.WORDLIST in sources) != (wordlist is not None)
        or any(s not in Source for s in sources)
    ):
        raise PolicyError("invalid_discovery", 2)
    if Source.CRTSH in sources and not allow_provider_queries:
        raise PolicyError("provider_consent_required", 2)
    candidates: list[Candidate] = []
    statuses: list[SourceStatus] = []
    unique: set[str] = set()
    for source, path in ((Source.FILE, candidates_file), (Source.WORDLIST, wordlist)):
        if path is None:
            continue
        lines, digest = _read_lines(path)
        names: dict[str, Candidate] = {}
        for number, line in lines:
            if source == Source.WORDLIST and ("*" in line or line.endswith(".")):
                raise PolicyError("invalid_candidates", 2)
            try:
                name = candidate_name(line if source == Source.FILE else f"{line}.{domain}", domain)
            except PolicyError as exc:
                raise PolicyError("invalid_candidates", 2) from exc
            names.setdefault(name, Candidate(name, source.value, f"line:{number}"))
        unique.update(names)
        if len(unique) > MAX_CANDIDATES:
            raise PolicyError("invalid_candidates", 2)
        candidates.extend(names.values())
        statuses.append(
            SourceStatus(
                source.value, "completed", "source_complete", len(names), input_digest=digest
            )
        )
    return DiscoveryPlan(
        domain, sources, tuple(candidates), tuple(statuses), resolve, allow_provider_queries
    )


def _unique_object(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise PolicyError("provider_invalid")
        result[key] = value
    return result


def _no_constant(value: str) -> NoReturn:
    raise PolicyError("provider_invalid")


def _check_json_depth(root: object) -> None:
    pending = [(root, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise PolicyError("provider_invalid")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def parse_crtsh(data: bytes, domain: str) -> tuple[tuple[Candidate, ...], SourceStatus]:
    if len(data) > MAX_PROVIDER_BYTES:
        raise PolicyError("body_too_large")
    try:
        rows: object = json.loads(
            data.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_constant=_no_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PolicyError("provider_invalid") from exc
    _check_json_depth(rows)
    if not isinstance(rows, list) or len(rows) > MAX_ENTRIES:
        raise PolicyError("provider_invalid")
    candidates: dict[str, Candidate] = {}
    discarded = 0
    malformed = False
    entries = 0
    truncated = False
    for row_number, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
            malformed = True
            discarded += 1
            continue
        certificate_id = row.get("id")
        reference = f"row:{row_number}"
        if (type(certificate_id) is int and 0 < certificate_id < 10**20) or (
            isinstance(certificate_id, str)
            and certificate_id.isascii()
            and certificate_id.isdigit()
            and 0 < len(certificate_id) <= 20
        ):
            reference = f"certificate:{certificate_id}"
        for line in row["name_value"].splitlines():
            entries += 1
            if entries > MAX_ENTRIES:
                truncated = True
                break
            try:
                name = candidate_name(line.strip(), domain)
            except PolicyError:
                discarded += 1  # Unrelated SANs/unsupported identities are not targets.
                continue
            if name not in candidates and len(candidates) >= MAX_CANDIDATES:
                truncated = True
                continue
            candidates.setdefault(name, Candidate(name, Source.CRTSH.value, reference))
        if entries > MAX_ENTRIES:
            break
    partial = truncated or malformed
    return tuple(candidates.values()), SourceStatus(
        Source.CRTSH.value,
        "partial" if partial else "completed",
        "candidate_limit"
        if truncated
        else ("provider_invalid_rows" if malformed else "source_complete"),
        len(candidates),
        discarded,
    )
