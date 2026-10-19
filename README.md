# PASOPATI

[Bahasa Indonesia](README.id.md)

Reconnaissance & Exposure Analysis Framework. **M2C TCP-connect inventory, version 0.1.0 (unreleased).**
Explicit-source candidates, scoped DNS, authorized URL and bounded TCP inventory.
See [subdomains](docs/en/discovery.md), [recon and the local lab](docs/en/recon.md),
and [scope](docs/en/configuration.md).
TCP usage: [explicit ports and the local fixture](docs/en/ports.md).
This is not a vulnerability scanner. The design favors isolated installation, small modules,
predictable output, minimal dependencies, and evidence over unsupported findings.

## Available now

- Installable Python 3.12+ package, `pasopati` executable, and `python -m pasopati`.
- ASCII arrow branding, compact narrow-terminal layout, and Rich terminal formatting.
- English/Indonesian informational messages (`--lang en|id`).
- Offline `doctor`, structured JSON, and explicit exit codes.
- Strict TOML configuration, non-overwriting `init`, and offline scope checks.
- Immutable passive/safe policies and an internal HTTP/HTTPS API with IP pinning,
  DNS/redirect validation, TLS verification, shared budgets and bounded responses.
- `scan` for explicit URL batches, DNS/HTTP evidence and honest partial/error outcomes.
- Normalized JSON/TXT output, conservative redaction and opt-in title samples.
- `discover subdomains`: offline file/wordlist candidates, opt-in crt.sh queries,
  scoped A/AAAA validation and qualified wildcard DNS observations with provenance.
- `ports`: explicit host/port TCP connects, all-answer scope validation, actual
  open/refused/error evidence and shared limits; no payload or service guesses.
- Reproducible local-only lab: `python -m pasopati.lab`; no external target required.
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

Source: [reactivheat/PASOPATI](https://github.com/reactivheat/PASOPATI).
The distribution name `pasopati-recon` has not been reserved or published on PyPI.
See [installation](docs/en/installation.md) for Kali prerequisites, the
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
pasopati init --path pasopati.toml
pasopati config validate --config pasopati.toml --json
pasopati scope check https://example.invalid --config pasopati.toml --json
pasopati profiles list --json
pasopati profiles show safe --json
pasopati scan --help
pasopati discover subdomains --help
pasopati ports --help
```

Global options go before the command. Doctor additionally accepts `--config-dir PATH`.
Exit codes: `0` successful/required checks pass, `1` required check or installation
failure, `2` invalid CLI usage. Missing optional tools do not change success to failure.
JSON has stable English identifiers and localized details; it contains no banner or ANSI.
Policy commands use 0 for success/match, 1 for denial or I/O/operational failure,
2 for invalid arguments/configuration/profile. Scope check never tests DNS/connectivity.
Read the [quick start](docs/en/quick-start.md) and [full command reference](docs/en/commands.md).
For actual collection, follow the [local lab and scan guide](docs/en/recon.md).
For an offline first discovery run and explicit provider consent, follow
[the subdomain guide](docs/en/discovery.md). Discovery does not auto-probe websites.
For TCP, follow [the port inventory guide](docs/en/ports.md); explicit port input is mandatory.
`init` remains passive/unauthorized. Scanning requires explicit target authorization,
safe profile and allowlisting; exit 1 includes partial/denied/skipped coverage.

## Architecture

```text
src/pasopati/
  __init__.py       installed version via importlib.metadata
  __main__.py       module entry point
  cli.py            Typer commands and presentation
  branding.py       responsive ASCII banner
  i18n.py           EN/ID messages
  doctor.py         offline checks and structured result
  config.py         strict TOML and exclusive template creation
  targets.py        shared target/domain normalization
  scope.py          offline and resolved-address policy
  profiles.py       immutable built-in budgets
  policy_cli.py     offline configuration/scope/profile CLI
  transport.py      pinned HTTP/HTTPS, DNS lifetime, resource limits
  limits.py         shared logical-attempt/rate/deadline budget
  dns_client.py     bounded A/AAAA responses and negative results
  scoped_dns.py     scope-aware DNS and per-parent wildcard checks
  discovery_*.py    explicit source options, bounded parsing and CLI
  discovery.py      candidate/DNS/provider evidence orchestration
  ports_cli.py      explicit TCP input and output preflight
  port_inventory.py scoped DNS snapshot and TCP evidence collection
  tcp.py            numeric TCP connects and conservative OS error classification
  scan_cli.py       explicit active scan command and preflight
  recon.py          normalized inventory, evidence and outcomes
  redaction.py      conservative URL/header/title reporting boundary
  reports.py        shared-model JSON/TXT rendering and exclusive output
  lab.py            explicit local-only reproducible HTTP fixture
  core/errors.py    installation error and exit codes
```

See [configuration](docs/en/configuration.md), [transport](docs/en/transport.md),
and [AGENTS.md](AGENTS.md). Scan schema 1, discovery 2 and TCP 3 share one JSON/TXT model.
HTML export, vulnerability analysis and historical comparison remain future work.

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
`.venv/bin/python` for the Windows interpreter above. Tests need no external network
or scanning tools. Integration tests use restricted loopback sockets; real TLS tests
generate temporary certificates using OpenSSL (explicit skip if unavailable).
Installation/build dependency downloads may need internet. Inspect actual results
under [GitHub Actions](https://github.com/reactivheat/PASOPATI/actions).

## Planned features

See the [capability roadmap and comparison criteria](docs/en/roadmap.md).
For native Kali VirtualBox documentation, use the [manual demo guide](docs/en/kali-vm-demo.md).

After M2C: deeper verified web/TLS observations (M2D).
Later: additional discovery providers; TLS certificate inventory; service,
web/API inventory; exposure/misconfiguration detection; CVE intelligence;
evidence-backed findings; differential analysis; asset relationships; plugins;
additional reproducible labs; HTML reports.
Standalone `report`, `diff`, and `demo` remain planned, unregistered commands.

## Screenshots and demos

Screenshots/GIFs are deferred until feature work is complete. Capture genuine output following
[screenshot guidance](docs/assets/screenshots/README.md) and
[demo guidance](docs/assets/demos/README.md). No illustrative scan results are presented.

## Current limitations

- M2C local validation: 306 tests each on Windows 11/Python 3.12.10 and Kali
  WSL2/Python 3.13.2, plus fresh-wheel entry points outside the checkout. A standalone
  Kali VM/native desktop terminal is not yet verified; hosted results are linked above.
- On a WSL Windows mount, pytest file-descriptor capture failed before collection;
  `--capture=sys` ran all tests successfully. See the installation checklist.
- Typer help/usage errors remain English; project messages support EN/ID.
- Doctor detects optional tools on PATH without executing or checking their versions.
- Doctor briefly writes/removes a temporary probe in the config directory or nearest
  existing ancestor. It creates no persistent configuration. This does not guarantee
  future writes after permissions or storage change.
- HTTP inventory covers explicit URLs only. Subdomain discovery returns candidates,
  not automatically authorized/live/unique hosts. No crawling, CVE checks or vulnerability
  verdicts. JSON/TXT persistence requires explicit `--output`.
- crt.sh is a third-party disclosure, opt-in and availability-dependent. Its path is
  fixture-tested, not validated by a live public query. DNS budgets count logical
  lookups, not resolver retransmission packets. See [discovery limits](docs/en/discovery.md).
- Non-root paths/queries are withheld; titles are off by default and heuristic
  redaction cannot guarantee that opt-in titles contain no unknown sensitive data.
- The scheduler is sequential. HTTP probes the first validated IP. TCP considers all validated
  answers within shared limits and makes no application-level service identification.
- IPv6 policy is unit tested. DNS uses numeric
  OS-configured servers, not hosts files/mDNS/DoH; no fallback public resolver.
  TCP includes an IPv6 loopback integration case when the stack is available;
  no external IPv6 transport or IPv6 HTTP claim is made.
- The owner has not selected a license. No license grant is supplied.

## Contributing, security, and scope

Read [AGENTS.md](AGENTS.md), use a virtual environment, add meaningful offline tests,
follow [contribution guidance](CONTRIBUTING.md) and [security reporting](SECURITY.md),
run the checks above, and keep documentation bilingual. Review changes before commits
or publication. Do not include credentials, local diagnostics, or sensitive scan data.
Network operations require explicit target authorization and allowlisting,
DNS/redirect scope validation, bounded rates/concurrency/timeouts/request budgets,
and evidence provenance. No automatic exploitation or sensitive-body persistence.
`scan` performs target HTTP; `ports` performs explicit authorized TCP connects;
discovery DNS/provider traffic is explicitly opt-in.
Policy commands remain offline. No external
targets were scanned for development validation. Licensing must be resolved before distribution.
