"""Explicit TCP inventory CLI, with input/output preflight before network construction."""

from pathlib import Path
from typing import Annotated

import typer

from pasopati.config import load_config
from pasopati.core.errors import InstallationError, PolicyError
from pasopati.policy_cli import failure


def ports(
    ctx: typer.Context,
    host: Annotated[
        str | None, typer.Argument(help="One explicit domain or IP, not a CIDR/URL.")
    ] = None,
    port_list: Annotated[
        str, typer.Option("--ports", help="Explicit comma-separated numeric ports.")
    ] = "",
    targets_file: Annotated[Path | None, typer.Option("--targets-file")] = None,
    config: Annotated[Path, typer.Option("--config")] = Path("pasopati.toml"),
    output: Annotated[Path | None, typer.Option("--output", help="New JSON/TXT directory.")] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="One ANSI-free JSON document.")
    ] = False,
) -> None:
    """TCP-connect inventory only. No payloads, port-derived service guesses or admin rights."""
    from pasopati import get_version
    from pasopati.port_inventory import (
        normalize_hosts,
        parse_ports,
        run_port_inventory,
        validate_inventory,
    )
    from pasopati.recon import load_targets
    from pasopati.reports import prepare_output, render_json, render_text, write_reports

    try:
        loaded = load_config(config)
        values = ([host] if host is not None else []) + (
            list(load_targets(targets_file)) if targets_file is not None else []
        )
        hosts, selected = normalize_hosts(values), parse_ports(port_list)
        validate_inventory(loaded, hosts, selected)
        get_version()
        if output is not None:
            prepare_output(output)
        report = run_port_inventory(loaded, hosts, selected)
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
