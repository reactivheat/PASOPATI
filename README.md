# PASOPATI

[Bahasa Indonesia](README.id.md)

Reconnaissance & Exposure Analysis Framework. **M1A: CLI foundation, version 0.1.0.**
This milestone provides local environment diagnostics. It does not scan targets or
detect vulnerabilities. The design favors isolated installation, small modules,
predictable output, minimal dependencies, and evidence over unsupported findings.

## Available now

- Installable Python 3.12+ package, `pasopati` executable, and `python -m pasopati`.
- ASCII arrow branding, compact narrow-terminal layout, and Rich terminal formatting.
- English/Indonesian informational messages (`--lang en|id`).
- Offline `doctor`, structured JSON, and explicit exit codes.
- pytest, Ruff, mypy, and a Linux/Windows CI workflow for Python 3.12–3.14.

## Installation

From a local checkout, on Kali with Python 3.12+ and pipx available:

```bash
python3 --version
pipx install .
pipx ensurepath
# Open a new terminal if PATH changed.
pasopati --version
pasopati doctor
```

The proposed repository is `https://github.com/reactivheat/pasopati-recon`;
its availability has not been verified. The distribution name `pasopati-recon`
has not been reserved or published. Use a local checkout until publication.
See [installation](docs/en/installation.md) for Kali prerequisites, the conditional
clone workflow, Windows setup, and a repeatable Kali verification checklist.
Never install this project into the system-managed Python environment.

## Usage and command reference

```text
pasopati
pasopati --help
pasopati --version
pasopati doctor
pasopati doctor --json
pasopati --lang id doctor
pasopati --no-banner doctor
python -m pasopati --help
```

Global options go before the command. Doctor additionally accepts `--config-dir PATH`.
Exit codes: `0` successful/required checks pass, `1` required check or installation
failure, `2` invalid CLI usage. Missing optional tools do not change success to failure.
JSON has stable English identifiers and localized details; it contains no banner or ANSI.
Read the [quick start](docs/en/quick-start.md) and [full command reference](docs/en/commands.md).

## Architecture

```text
src/pasopati/
  __init__.py       installed version via importlib.metadata
  __main__.py       module entry point
  cli.py            Typer commands and presentation
  branding.py       responsive ASCII banner
  i18n.py           EN/ID messages
  doctor.py         offline checks and structured result
  core/errors.py    installation error and exit codes
```

See [AGENTS.md](AGENTS.md) for future scope/transport boundaries and the normalized
TXT/JSON/HTML report contract. These future components are not implemented.

## Development and tests

PowerShell, from this workspace (activation is optional):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -v --basetemp=.local/pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m build
```

Linux/macOS contributors can use `python3 -m venv .venv`, then substitute
`.venv/bin/python` for the Windows interpreter above. Tests do not need network
access or scanning tools. Installation/build dependency downloads may need internet.
CI is configured; a hosted CI result is not claimed until it actually runs.

## Planned features

M1B: scope configuration, scan profiles, and scope-aware transport.
Later: passive discovery; DNS/subdomains; HTTP, TLS and security headers; service,
web/API inventory; exposure/misconfiguration detection; CVE intelligence;
evidence-backed findings; differential analysis; asset relationships; plugins;
reproducible local security labs; TXT/JSON/HTML reports.
`init`, `scan`, `report`, `diff`, and `demo` are planned and are not registered commands.

## Screenshots and demos

No screenshots or videos are supplied yet. Capture genuine output following
[screenshot guidance](docs/assets/screenshots/README.md) and
[demo guidance](docs/assets/demos/README.md). No illustrative scan results are presented.

## Current limitations

- Validated on Windows 11/Python 3.12.10 and Kali WSL2/Python 3.13.2. A standalone
  Kali VM/native desktop terminal and hosted CI are not yet verified.
- On a WSL Windows mount, pytest file-descriptor capture failed before collection;
  `--capture=sys` ran all tests successfully. See the installation checklist.
- Typer help/usage errors remain English; project messages support EN/ID.
- Doctor detects optional tools on PATH without executing or checking their versions.
- Doctor briefly writes/removes a temporary probe in the config directory or nearest
  existing ancestor. It creates no persistent configuration. This does not guarantee
  future writes after permissions or storage change.
- No scanning, scope enforcement engine, persistent storage, or report exporters yet.
- The owner has not selected a license. No license grant is supplied.

## Contributing, security, and scope

Read [AGENTS.md](AGENTS.md), use a virtual environment, add meaningful offline tests,
run the checks above, and keep documentation bilingual. Review changes before commits
or publication. Do not include credentials, local diagnostics, or sensitive scan data.
Future network operations require explicit target authorization and allowlisting,
DNS/redirect scope validation, bounded rates/concurrency/timeouts/request budgets,
and evidence provenance. No automatic exploitation or sensitive-body persistence.
M1A performs no network reconnaissance. Licensing must be resolved before distribution.
