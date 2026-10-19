"""Offline M1B CLI; no transport import or network initialization."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pasopati import get_version
from pasopati.branding import render_banner
from pasopati.config import init_config, load_config
from pasopati.core.errors import PolicyError
from pasopati.i18n import Language, tr
from pasopati.profiles import PROFILES, get_profile
from pasopati.scope import Scope

config_app = typer.Typer(help="Validate project configuration offline.")
scope_app = typer.Typer(help="Check textual scope offline; no DNS or connectivity checks.")
profiles_app = typer.Typer(help="Inspect policies; no scanning is performed.")
ConfigOption = Annotated[Path, typer.Option("--config", help="Project TOML file.")]
JsonOption = Annotated[bool, typer.Option("--json", help="Emit JSON only.")]


def emit(ctx: typer.Context, payload: dict[str, object], json_output: bool, code: int = 0) -> None:
    language: Language = ctx.obj.language
    reason = str(payload["reason"])
    payload = {
        "schema_version": "1",
        "language": language.value,
        **payload,
        "message": tr(language, reason),
    }
    if json_output:
        typer.echo(json.dumps(payload, ensure_ascii=True, indent=2))
    else:
        console = Console()
        if not ctx.obj.no_banner:
            render_banner(console, get_version(), language)
        console.print(str(payload["message"]), markup=False, highlight=False)
        if "dns_checked" in payload:
            console.print(tr(language, "offline_scope"), markup=False)
        if "profiles" in payload or "profile" in payload:
            console.print(
                json.dumps(payload.get("profiles", payload.get("profile")), indent=2),
                markup=False,
                highlight=False,
            )
    raise typer.Exit(code)


def failure(ctx: typer.Context, error: PolicyError, json_output: bool) -> None:
    emit(ctx, {"ok": False, "reason": error.code}, json_output, error.exit_code)


def initialize(
    ctx: typer.Context,
    path: Annotated[Path, typer.Option("--path")] = Path("pasopati.toml"),
    json_output: JsonOption = False,
) -> None:
    """Create a passive, unauthorized configuration without overwriting files."""
    try:
        init_config(path)
    except PolicyError as exc:
        failure(ctx, exc, json_output)
        return
    emit(ctx, {"ok": True, "reason": "config_created"}, json_output)


@config_app.command("validate")
def validate(
    ctx: typer.Context,
    config: ConfigOption = Path("pasopati.toml"),
    json_output: JsonOption = False,
) -> None:
    try:
        loaded = load_config(config)
    except PolicyError as exc:
        failure(ctx, exc, json_output)
        return
    emit(ctx, {"ok": True, "reason": "config_valid", "profile": loaded.profile}, json_output)


@scope_app.command("check")
def check(
    ctx: typer.Context,
    target: str,
    config: ConfigOption = Path("pasopati.toml"),
    json_output: JsonOption = False,
) -> None:
    try:
        result = Scope(load_config(config)).check(target)
    except PolicyError as exc:
        failure(ctx, exc, json_output)
        return
    emit(
        ctx,
        {
            "ok": result.allowed,
            "allowed": result.allowed,
            "reason": result.reason,
            "dns_checked": False,
            "connectivity_checked": False,
        },
        json_output,
        0 if result.allowed else 1,
    )


@profiles_app.command("list")
def list_profiles(ctx: typer.Context, json_output: JsonOption = False) -> None:
    emit(
        ctx,
        {"ok": True, "reason": "profiles_info", "profiles": [asdict(p) for p in PROFILES.values()]},
        json_output,
    )


@profiles_app.command("show")
def show_profile(ctx: typer.Context, name: str, json_output: JsonOption = False) -> None:
    try:
        profile = get_profile(name)
    except PolicyError as exc:
        failure(ctx, exc, json_output)
        return
    emit(ctx, {"ok": True, "reason": "profiles_info", "profile": asdict(profile)}, json_output)
