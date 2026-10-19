"""Active reconnaissance is isolated from offline commands and enabled explicitly."""

from pathlib import Path
from typing import Annotated

import typer

from pasopati.config import load_config
from pasopati.core.errors import InstallationError, PolicyError
from pasopati.policy_cli import failure


def scan(
    ctx: typer.Context,
    target: Annotated[str | None, typer.Argument(help="Explicit HTTP/HTTPS URL.")] = None,
    targets_file: Annotated[
        Path | None, typer.Option("--targets-file", help="UTF-8 URL list, at most 256 entries.")
    ] = None,
    config: Annotated[Path, typer.Option("--config", help="Authorized project TOML.")] = Path(
        "pasopati.toml"
    ),
    output: Annotated[
        Path | None, typer.Option("--output", help="New directory for JSON/TXT; never overwrite.")
    ] = None,
    include_titles: Annotated[
        bool,
        typer.Option(
            "--include-titles", help="Opt in to title samples; may contain sensitive data."
        ),
    ] = False,
    web_details: Annotated[
        bool, typer.Option("--web-details", help="Opt in to verified TLS and bounded web metadata.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="One JSON document, without ANSI.")
    ] = False,
) -> None:
    """Inventory explicit, authorized URLs. No crawling, exploitation or vulnerability verdicts."""
    # Offline commands do not even import the network implementation.
    from pasopati import get_version
    from pasopati.recon import load_targets, normalize_targets, require_network, run_recon
    from pasopati.reports import prepare_output, render_json, render_text, write_reports

    try:
        if target is None and targets_file is None:
            raise PolicyError("invalid_targets", 2)
        loaded = load_config(config)
        values = ((target,) if target is not None else ()) + (
            load_targets(targets_file) if targets_file is not None else ()
        )
        urls = normalize_targets(values)
        require_network(loaded)
        get_version()  # Metadata and local output errors must fail before any target traffic.
        if output is not None:
            prepare_output(output)
        report = run_recon(loaded, urls, include_titles=include_titles, inspect_web=web_details)
        if output is not None:
            write_reports(report, output, ctx.obj.language)
    except PolicyError as exc:
        failure(ctx, exc, json_output)
        return
    except InstallationError:
        failure(ctx, PolicyError("installation_error"), json_output)
        return
    except KeyboardInterrupt:
        failure(ctx, PolicyError("interrupted"), json_output)
        return
    typer.echo(
        render_json(report, ctx.obj.language)
        if json_output
        else render_text(report, ctx.obj.language),
        color=False,
    )
    raise typer.Exit(0 if report.ok else 1)
