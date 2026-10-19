"""Typer commands and Rich presentation. Checks live in doctor.py."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pasopati import get_version
from pasopati.branding import render_banner
from pasopati.core.errors import ExitCode, InstallationError
from pasopati.discovery_cli import discover_app
from pasopati.doctor import run_doctor
from pasopati.i18n import Language, tr
from pasopati.policy_cli import config_app, initialize, profiles_app, scope_app
from pasopati.scan_cli import scan

app = typer.Typer(
    help="PASOPATI - Scoped subdomain/DNS/HTTP recon, offline policy and diagnostics.",
    add_completion=False,
    no_args_is_help=False,
    pretty_exceptions_enable=False,
)
app.command("init")(initialize)
app.command("scan")(scan)
app.add_typer(discover_app, name="discover")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")
app.add_typer(profiles_app, name="profiles")


@dataclass(frozen=True)
class Options:
    language: Language
    no_banner: bool


def _installed_version(language: Language) -> str:
    try:
        return get_version()
    except InstallationError as exc:
        typer.echo(tr(language, "installation_error"), err=True)
        raise typer.Exit(ExitCode.FAILURE) from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"PASOPATI {_installed_version(Language.EN)}")
        raise typer.Exit(ExitCode.SUCCESS)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    lang: Annotated[Language, typer.Option(help="Message language: en or id.")] = Language.EN,
    no_banner: Annotated[
        bool, typer.Option("--no-banner", help="Suppress the ASCII banner.")
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show installed package version and exit.",
        ),
    ] = False,
) -> None:
    ctx.obj = Options(lang, no_banner)
    if ctx.invoked_subcommand is None:
        console = Console()
        package_version = _installed_version(lang)
        if not no_banner:
            render_banner(console, package_version, lang)
        else:
            console.print(f"PASOPATI {package_version}", markup=False, highlight=False)
        console.print(tr(lang, "quick_start"), style="bold")
        for command, key in (
            ("pasopati --help", "quick_help"),
            ("pasopati doctor", "quick_doctor"),
            ("pasopati doctor --json", "quick_json"),
        ):
            console.print(f"  {command}  {tr(lang, key)}", markup=False, highlight=False)
        console.print(tr(lang, "foundation"), markup=False, highlight=False)


@app.command()
def doctor(
    ctx: typer.Context,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON only, without a banner or ANSI escapes.")
    ] = False,
    config_dir: Annotated[
        Path | None,
        typer.Option(help="Inspect this config directory instead of the platform default."),
    ] = None,
) -> None:
    """Check local prerequisites offline; optional tools are never executed or installed."""
    options: Options = ctx.obj
    report = run_doctor(options.language, config_dir)
    if json_output:
        typer.echo(json.dumps(report.to_dict(), ensure_ascii=True, indent=2))
    else:
        console = Console()
        if not options.no_banner:
            # The package check also handles missing metadata, so diagnostics remain available.
            try:
                package_version = get_version()
            except InstallationError:
                package_version = "?"
            render_banner(console, package_version, options.language)
        console.print(tr(options.language, "doctor_title"), style="bold")
        for check in report.checks:
            status = tr(options.language, check.status)
            requirement = tr(options.language, "required" if check.required else "optional")
            style = {"pass": "green", "warn": "yellow", "fail": "red"}[check.status]
            console.print(
                f"{status} | {tr(options.language, check.name)} ({requirement})",
                style=style,
                markup=False,
                highlight=False,
            )
            console.print(f"  {check.details}", markup=False, highlight=False)
            if check.recommendation:
                console.print(
                    f"  {tr(options.language, 'recommendation')}: {check.recommendation}",
                    markup=False,
                    highlight=False,
                )
        console.print(tr(options.language, "ready" if report.ok else "not_ready"), markup=False)
    raise typer.Exit(ExitCode.SUCCESS if report.ok else ExitCode.FAILURE)


def main() -> None:
    """Installed console script entry point."""
    app()
