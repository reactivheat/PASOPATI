# PASOPATI development contract

## Scope and implementation status

M1A implements packaging, CLI presentation, EN/ID messages, and offline local
environment diagnostics. M1B adds strict TOML, scope checks, built-in profiles,
and bounded HTTP/HTTPS transport. M2A adds explicit-seed DNS/HTTP inventory through
`scan`, normalized provenance/observations, JSON/TXT output and a loopback lab.
M2B adds explicit-source `discover subdomains`: local candidate/wordlist input,
opt-in crt.sh queries and scope-checked A/AAAA/wildcard observations.
M2C adds `ports`: explicit, bounded TCP-connect inventory; no application payloads,
banner reads or port-number-derived service/version guesses.
Registered commands are `doctor`, `init`, `config validate`, `scope check`,
`profiles list/show`, `scan`, `discover subdomains` and `ports`. Do not add crawling,
vulnerability checks, databases, plugins or empty engines until requested.
Planned standalone commands: `report`, `diff`, `demo`.

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

## Architecture and collection controls

M1B implements scope configuration, explicit profiles, and scope-aware transport.
M2A collection and future discovery/analysis modules depend on those shared controls,
not construct bypass network clients. Keep collection, evidence, analysis, and
rendering separate. Introduce abstractions only when real callers need them.

Current transport invariants are documented in docs/en/transport.md and docs/id/transport.md.
All target DNS addresses must pass policy before numeric socket.connect; do not replace
this with a check followed by a client that resolves again. dnspython is required for
bounded DNS lifetime; do not use blocking getaddrinfo with a post-hoc timeout check.
Keep TLS verification/original SNI, immutable passive/safe profiles and shared per-session
rate/concurrency/request budgets. No proxy, auth, cookie, TLS key log or body persistence.
All CLI policy commands stay offline. `scan` performs explicit target HTTP traffic;
`discover subdomains` is offline by default for file/wordlist sources. --resolve
opts into DNS; crtsh requires explicit source selection and --allow-provider-queries.
Provider queries disclose the domain to a third party, require safe/authorized
configuration and an explicitly allowed base domain. Never silently add *.DOMAIN.
Provider Session has a separate exact crt.sh:443 policy with no private addresses;
it does not widen target scope. No custom provider URL/headers/credentials CLI.
limits.RequestBudget is shared by provider HTTP hops and DNS RR lookups. Limits
count logical attempts, not DNS wire retransmissions; lifetimes are bounded.
Wildcard probes require scope, three random labels per immediate parent and at
most four probed parents. Qualify possible/unchecked wildcard results; never
materialize certificate wildcard patterns as actual hosts. No automatic target HTTP.
Candidate inputs and provider JSON are bounded, deduplicated and label-boundary
checked before use. Preserve source/reference/digest and real DNS/attempt evidence;
NXDOMAIN, no A/AAAA, timeout and provider failure are distinct outcomes.
M2A JSON shape stays schema 1; discovery uses schema 2 in the same RunReport and
JSON/TXT renderers. DNS query_name/query_type and candidate subject_name are not URLs.
No raw provider body, local source path, cookies, credentials or arbitrary fields
in reports. Existing output directories are refused before provider construction.
M2C uses the same Scope, ScopedDNS and RequestBudget; never use a socket hostname
or a new unchecked resolver. Require safe/authorized config, explicit hosts and
numeric ports (no CIDR/range expansion). All A/AAAA addresses must pass policy
before any TCP attempt. Resolve once per host/run and pin that snapshot; no hidden
refresh/retry/fallback. Probe each validated address/port within the shared budget.
Bounds: 64 input hosts, 64 port entries, 256 deduplicated host/port pairs, at most
16 resolved addresses per host (fail closed above the limit, never clip silently).
Logical budget includes target DNS RR lookups and each TCP connect. Concurrency
ceiling 2; scheduler remains sequential. TCP total deadline 10s including limiter
waits, connect phase at most 3s. Close sockets on success/error/cancellation.
Only actual connection success is open; explicit OS refusal is refused. Timeout,
unreachable, reset, local errors and expired deadlines never imply closed/filtered.
No banner/TLS/application reads/writes or getservbyport service guesses. Schema 3
extends the common RunReport with TCP counters and evidence port/transport fields;
preserve the exact prior schema 1/2 shapes. Denied/unattempted endpoints must not
invent TCP evidence. Service identification remains explicitly not_performed.
The owner's permission to develop/push is NOT authorization for arbitrary targets.
`scan` requires authorized=true, a network-enabled profile and scope allowlisting.
Validate the entire bounded URL batch and reserve new report output before traffic.
Keep one Session per run; never reset budgets per target or add hidden retries.
Use transport resolution/response events for provenance, including partial results.
Never claim a DNS answer means a TCP connection succeeded. Literal IPs are not DNS results.
Default reports withhold every non-root URL path/query and raw header values.
Titles are opt-in, heuristically redacted, and never guaranteed secret-free.
No body/cookie/header dump, CVE inference, severity assignment or "secure" verdict.
JSON and TXT use the same versioned RunReport; files require explicit --output,
exclusive creation and no overwrites. A partial/denied/skipped/error result exits 1.
`python -m pasopati.lab` is an explicit local-only HTTP fixture, never auto-started.
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

M2A/M2B/M2C implement JSON/TXT inventory (scan schema 1, discovery 2, TCP 3). Findings remain empty and
vulnerability_assessment is not_performed; HTML/analysis/import/diff are future work.

One normalized, versioned data model must feed every renderer, including assets,
observations, evidence provenance, findings, confidence, severity and run metadata.
Do not independently recompute findings inside renderers.

- `report.txt`: human-readable UTF-8, no ANSI, usable with terminal readers.
- `report.json`: structured machine-readable output with an explicit schema version.
- `report.html`: static, portable, self-contained, no external CDNs; evidence,
  findings and risk summaries; escape all untrusted content.

The doctor JSON schema is an environment diagnostic, not the future scan-report
schema. No report exporter or normalized scan model is required in M1A.
