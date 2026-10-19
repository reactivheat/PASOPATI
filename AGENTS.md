# PASOPATI development contract

## Scope and implementation status

M1A implements packaging, CLI presentation, EN/ID messages, and offline local
environment diagnostics. M1B adds strict TOML, scope checks, built-in profiles,
and an internal bounded HTTP/HTTPS transport. Registered commands are `doctor`,
`init`, `config validate`, `scope check`, and `profiles list/show`. Do not add
scanners, crawling, databases, plugins, or empty engines until their milestone is
explicitly requested. Planned commands: `scan`, `report`, `diff`, `demo`.

Use Python 3.12+, a `src/` layout, Typer and Rich, standard-library facilities,
type annotations, explicit errors, and small testable components. Keep packaging
version in pyproject.toml; runtime reads importlib.metadata. Never invent a version
when metadata is missing. Do not hardcode developer paths or require admin rights.

## Working practices and checks

Inspect current files and preserve user changes. Use isolated environments and
avoid global package or Git configuration changes. Do not commit or push unless
the owner requests it. No license has been selected; do not choose one for the owner.
The owner authorized checkpoint commits/pushes to https://github.com/reactivheat/PASOPATI.
Do not publish packages, tags or releases under that authorization. The distribution
name remains unreserved.

From a development environment installed with `python -m pip install -e ".[dev]"`:

```text
python -m pytest -v --basetemp=.local/pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m build
```

On Windows use `.venv\Scripts\python.exe`; on Linux `.venv/bin/python`.
Never claim unexecuted tests, hosted CI runs, screenshots, benchmarks, or platform
validation. Keep docs in EN/ID consistent. CLI-generated help remains English for M1A.
Do not persist secrets, diagnostics containing local paths, or sensitive scan data
in tracked files. Run subprocess entry-point tests from outside the checkout.

## Current boundaries

- `cli.py`: argument parsing, output, exit status. No environment-check logic.
- `branding.py`: ASCII presentation and narrow-terminal fallback.
- `i18n.py`: messages, stable keys, matching placeholder sets.
- `doctor.py`: local checks and immutable results; no networking, installations, or
  execution of discovered binaries. Temporary write probes must be cleaned up.
- `core/errors.py`: shared error and exit-code vocabulary.
- JSON stdout must be one parseable document, even with forced terminal colors.
  Keep status/check identifiers stable; localize descriptive messages only.
- Missing optional Git/pipx/Nmap/Nuclei/Subfinder does not fail M1A. Python,
  installed metadata, usable configuration path, and write capability are required.

## Future architecture (documented contracts, not implemented)

M1B implements scope configuration, explicit profiles, and scope-aware transport.
M2 discovery/analysis modules must depend on those shared controls,
not construct bypass network clients. Keep collection, evidence, analysis, and
rendering separate. Introduce abstractions only when real callers need them.

Current transport invariants are documented in docs/en/transport.md and docs/id/transport.md.
All target DNS addresses must pass policy before numeric socket.connect; do not replace
this with a check followed by a client that resolves again. dnspython is required for
bounded DNS lifetime; do not use blocking getaddrinfo with a post-hoc timeout check.
Keep TLS verification/original SNI, immutable passive/safe profiles and shared per-session
rate/concurrency/request budgets. No proxy, auth, cookie, TLS key log or body persistence.
All CLI policy commands stay offline; transport is internal until explicitly exposed.
Keep ordinary tests offline; integration fixtures may use guarded numeric loopback
only. Generate test TLS credentials in temporary directories; never commit keys.
pytest_configure creates basetemp's parent for fresh checkouts. Installed executable
lookup must use sysconfig's scripts path, not assume it is next to sys.executable.

Before any target network traffic, require explicit authorization and target
allowlisting. Validate DNS answers and every redirect against scope, including
address changes/rebinding and private/reserved address policy. Use rate limits,
bounded concurrency, explicit connect/read/total timeouts, and request budgets.
HTTP probing must use safe methods and bounded responses; never automatically
exploit, expand to unapproved targets, or persist sensitive response bodies.
Sanitize secrets in URLs, headers, evidence, logs and reports. Retain evidence
provenance (source, authorized target, collection time, method, tool/version and
confidence) and distinguish observations from inferred vulnerabilities. Optional
tool adapters must use argument arrays, timeouts and validated scope, never shell
interpolation. Test these controls offline against local fixtures before live use.

## Future report contract

One normalized, versioned data model must feed every renderer, including assets,
observations, evidence provenance, findings, confidence, severity and run metadata.
Do not independently recompute findings inside renderers.

- `report.txt`: human-readable UTF-8, no ANSI, usable with terminal readers.
- `report.json`: structured machine-readable output with an explicit schema version.
- `report.html`: static, portable, self-contained, no external CDNs; evidence,
  findings and risk summaries; escape all untrusted content.

The doctor JSON schema is an environment diagnostic, not the future scan-report
schema. No report exporter or normalized scan model is required in M1A.
