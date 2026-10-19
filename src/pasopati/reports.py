"""JSON/TXT renderers of one normalized inventory, never independent analysis."""

import json
import os
from pathlib import Path

from pasopati.core.errors import PolicyError
from pasopati.i18n import Language, tr
from pasopati.recon import RunReport


def render_json(report: RunReport, language: Language = Language.EN) -> str:
    return json.dumps({"language": language.value, **report.to_dict()}, ensure_ascii=True, indent=2)


def render_text(report: RunReport, language: Language = Language.EN) -> str:
    attempts_key = "discovery_attempts" if report.discovery is not None else "recon_requests"
    lines = [
        f"PASOPATI {report.tool_version} — "
        f"{tr(language, 'discovery_title' if report.discovery is not None else 'recon_title')}",
        f"{report.run_id} | {report.started_at} — {report.finished_at}",
        f"{tr(language, 'recon_status')}: {tr(language, 'scan_' + report.status)}",
        f"{tr(language, attempts_key)}: {report.requests_used}",
        tr(
            language,
            "discovery_limitations" if report.discovery is not None else "recon_limitations",
        ),
        "",
    ]
    if report.discovery is not None:
        details = report.discovery
        lines.append(f"{tr(language, 'discovery_domain')}: {details.domain}")
        lines.append(
            tr(
                language,
                "discovery_counts",
                dns=details.dns_queries_used,
                http=details.provider_http_attempts,
            )
        )
        if details.provider_queries_disclosed:
            lines.append(tr(language, "provider_disclosure"))
        for source in details.sources:
            lines.append(f"  {source.source}: {source.status} — {tr(language, source.reason)}")
            lines.append(f"    candidates: {source.candidates}; discarded: {source.discarded}")
            if source.input_digest is not None:
                lines.append(f"    SHA-256: {source.input_digest}")
        for check in details.wildcard_checks:
            lines.append(f"  Wildcard {check.parent}: {check.status}")
        # Render the same stored provenance used in JSON, not a recomputed conclusion.
        for evidence in details.provider_evidence:
            lines.append(f"  {evidence.id} | {evidence.source} | {evidence.collected_at}")
            lines.append(f"    {evidence.method} {evidence.url}")
            if evidence.addresses:
                lines.append("    IP: " + ", ".join(evidence.addresses))
            if evidence.http_status is not None:
                lines.append(f"    HTTP: {evidence.http_status}")
        for check in details.wildcard_checks:
            for evidence in check.evidence:
                subject = evidence.query_name or evidence.subject_name or evidence.url or ""
                lines.append(
                    f"  {evidence.id} | {evidence.collected_at} | "
                    f"{evidence.method} {subject} | {', '.join(evidence.addresses)}"
                )
        lines.append("")
    for asset in report.assets:
        lines.extend(
            [
                f"{asset.id} | {asset.target}",
                f"  {tr(language, 'scan_' + asset.status)}: {tr(language, asset.reason)}",
            ]
        )
        for evidence in asset.evidence:
            subject = evidence.query_name or evidence.subject_name or evidence.url or ""
            lines.append(f"  {evidence.id} | {evidence.source} | {evidence.collected_at}")
            lines.append(f"    {evidence.method} {subject}")
            if evidence.addresses:
                lines.append("    IP: " + ", ".join(evidence.addresses))
            if evidence.redirect_destination:
                lines.append("    Location: " + evidence.redirect_destination)
        for observation in asset.observations:
            lines.append(
                f"  {observation.kind}: "
                f"{json.dumps(observation.value, ensure_ascii=False)} "
                f"[{observation.confidence}; {observation.evidence_id}]"
            )
        lines.append("")
    lines.append(tr(language, "recon_no_findings_claim"))
    return "\n".join(lines) + "\n"


def prepare_output(directory: Path) -> None:
    """Reserve a NEW output directory before traffic. Existing files/symlinks are refused."""
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        raise PolicyError("report_io") from exc


def write_reports(report: RunReport, directory: Path, language: Language = Language.EN) -> None:
    try:
        for name, content in (
            ("report.json", render_json(report, language)),
            ("report.txt", render_text(report, language)),
        ):
            # O_EXCL also refuses an existing symlink; private mode on POSIX.
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content + ("\n" if name.endswith(".json") else ""))
    except OSError as exc:
        raise PolicyError("report_io") from exc
