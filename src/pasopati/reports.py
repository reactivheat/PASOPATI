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
    lines = [
        f"PASOPATI {report.tool_version} — {tr(language, 'recon_title')}",
        f"{report.run_id} | {report.started_at} — {report.finished_at}",
        f"{tr(language, 'recon_status')}: {tr(language, 'scan_' + report.status)}",
        f"{tr(language, 'recon_requests')}: {report.requests_used}",
        tr(language, "recon_limitations"),
        "",
    ]
    for asset in report.assets:
        lines.extend(
            [
                f"{asset.id} | {asset.target}",
                f"  {tr(language, 'scan_' + asset.status)}: {tr(language, asset.reason)}",
            ]
        )
        for evidence in asset.evidence:
            lines.append(f"  {evidence.id} | {evidence.source} | {evidence.collected_at}")
            lines.append(f"    {evidence.method} {evidence.url}")
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
