"""Explicit discovery controls; offline acquisition imports no network runtime."""

from pathlib import Path
from typing import Annotated

import typer

from pasopati.config import load_config
from pasopati.core.errors import InstallationError, PolicyError
from pasopati.discovery_options import Source
from pasopati.policy_cli import failure

discover_app = typer.Typer(help="Discover bounded candidates; no automatic target HTTP probing.")


@discover_app.command("subdomains")
def subdomains(
    ctx: typer.Context,
    domain: str,
    sources: Annotated[
        list[Source] | None, typer.Option("--source", help="Explicit source; repeatable.")
    ] = None,
    candidates_file: Annotated[Path | None, typer.Option("--candidates-file")] = None,
    wordlist: Annotated[
        Path | None, typer.Option("--wordlist", help="Relative name prefixes.")
    ] = None,
    config: Annotated[Path, typer.Option("--config")] = Path("pasopati.toml"),
    resolve: Annotated[
        bool, typer.Option("--resolve", help="Opt in to scoped A/AAAA validation.")
    ] = False,
    allow_provider_queries: Annotated[
        bool, typer.Option("--allow-provider-queries", help="Consent to sending DOMAIN to crt.sh.")
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", help="New JSON/TXT report directory.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="One JSON document; no ANSI.")
    ] = False,
) -> None:
    """Import/generate/collect domain candidates. CT claims are not proof of live hosts."""
    from pasopati import get_version
    from pasopati.discovery import run_discovery, validate_discovery
    from pasopati.discovery_sources import prepare_discovery
    from pasopati.reports import prepare_output, render_json, render_text, write_reports

    try:
        loaded = load_config(config)
        plan = prepare_discovery(
            domain,
            tuple(sources or ()),
            candidates_file=candidates_file,
            wordlist=wordlist,
            resolve=resolve,
            allow_provider_queries=allow_provider_queries,
        )
        validate_discovery(loaded, plan)
        get_version()
        if output is not None:
            prepare_output(output)
        report = run_discovery(loaded, plan)
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
