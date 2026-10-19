# M2A: explicit-seed DNS/HTTP inventory

[Bahasa Indonesia](../id/recon.md)

`scan` collects real responses from explicit, authorized HTTP/HTTPS URLs. This is
inventory, not a vulnerability scanner, crawler, subdomain enumerator or CVE matcher.
No network activity occurs when running `doctor`, `init`, `config`, `scope` or `profiles`.
M2B [subdomain discovery](discovery.md) is a separate command, offline for local
sources by default, with explicit DNS/provider opt-ins; `scan` does not invoke it.

## Authorization and input

Only scan systems for which you have permission. The project owner's permission
to develop/push code does not authorize third-party targets. In a project TOML:

- Set `authorized = true` only after obtaining permission for the actual targets.
- Select `profile = "safe"`; passive never sends requests.
- Explicitly allow domains/CIDRs and ports; exclusions take priority.
- A private lab additionally needs `allow_private = true` and an explicit CIDR.
- A successful offline `scope check` is not DNS, connectivity or authorization proof.

Use either one URL or a UTF-8 list, or combine them:

```text
pasopati scan https://your-authorized-host.example/ --config pasopati.toml --json
pasopati --lang id scan --targets-file targets.txt --config pasopati.toml --output reports/run-001
```

These are syntax examples, not evidence that those targets exist or were scanned.
Every entry must include `http://` or `https://`. No automatic scheme guessing,
domain expansion, discovered-link following or port enumeration occurs. The
whole batch is validated before traffic: at most 256 entries (before deduplication),
4,096 characters per URL and 1 MiB of UTF-8 input. Blank lines and full-line `#`
comments are ignored in lists; duplicates retain the first canonical occurrence.
Credentials, fragments, ambiguous IPs and non-HTTP schemes are rejected without
echoing the input. An invalid entry prevents the entire batch from running.

## Reproduce on your own computer

From an installed checkout, start the fixture in terminal A:

```text
python -m pasopati.lab --port 8765
```

It binds **only 127.0.0.1**, uses an unprivileged port, logs no request URLs and
stops with Ctrl+C. It is never started automatically. Terminal B, from the checkout:

```text
pasopati scan --targets-file examples/lab-targets.txt --config examples/lab.toml --output reports/lab-001 --include-titles --json
```

Expected fixture contract: three deduplicated targets, four request attempts,
root response 200, one relative redirect to root, and `/missing` response 404.
The root's opt-in title is `PASOPATI local lab`. Exit 0 means collection completed;
the 404 remains an HTTP observation, not a vulnerability. Use a new output directory
on every run. The config authorizes this synthetic loopback lab only.

Additional negative fixtures, using the same config:

```text
pasopati scan http://127.0.0.1:8765/outside --config examples/lab.toml --json
pasopati scan http://127.0.0.1:8765/large --config examples/lab.toml --json
pasopati scan http://127.0.0.1:8765/sensitive --config examples/lab.toml --include-titles --json
```

`/outside` yields a partial result with `not_allowlisted` without requesting the
external destination. `/large` yields `body_sampled`: at most 64 KiB is retained
in memory, with no body persisted. Both exit 1 intentionally. `/sensitive` tests
heuristic title redaction; the synthetic secret must not appear in the report.
Fixture expectations are asserted in `tests/test_scan_local.py`, not fabricated
production results. Run the full test suite to verify on your platform.

## What is collected

One shared M1B Session controls the whole run: GET only, 50 attempts, aggregate
1 request/second, concurrency ceiling 2, at most three redirects per seed, numeric
IP pinning, verified TLS/original SNI and no retry/proxy/auth/cookie forwarding.
The initial M2A scheduler is deliberately sequential; a concurrency ceiling is
not a claim of parallel throughput. DNS/connect/read/total deadlines remain
bounded; total deadline is 10 seconds per seed including redirects and waiting.
The 50-attempt budget includes failed DNS/connect attempts and redirect hops.
It is not a guarantee that all 256 permitted input entries will be completed.

Each seed records all validated A/AAAA answers, the one selected connected IP
when a response is received, status, sanitized redirect destination, selected
header observations and optional title. A literal IP is labeled `ip_literal`,
not a DNS lookup. Only the first validated IP is attempted; other DNS answers
are not independently probed and no fallback occurs. A failed TLS verification
is a collection failure, never a reason to disable verification.

Resolution and response provenance is retained even when a later step fails.
An address resolution alone does not prove connectivity. No evidence is invented
for failed DNS, denied connections or unvisited redirect destinations.
Successful responses can be 4xx/5xx; HTTP status is not a vulnerability verdict.
Large bodies are sampled without decompression; truncation is explicitly partial.
The original strict `Session.fetch()` API still rejects oversized bodies unless
the caller explicitly enables bounded sampling.

## Report contract and privacy

By default only stdout is produced. `--json` emits exactly one JSON document,
including application errors, without a banner/ANSI. `--output NEW_DIRECTORY`
explicitly persists `report.json` and UTF-8, ANSI-free `report.txt`. The new directory
is reserved before traffic. Existing outputs are refused, not overwritten;
files are exclusively created with private permissions on POSIX. OS permissions
still control access on Windows. Disk-full/interruption may leave incomplete
files or an empty reserved directory; errors exit 1. Use a new directory to retry.
Do not commit real scan reports or target lists; the root `reports/` is ignored.

Both renderers consume the same `RunReport`, never recompute findings:

- `schema_version = "1"`, `report_type = "pasopati.recon"`: distinct from doctor JSON.
- Run ID, installed tool version, UTC timestamps, profile and request-attempt count.
- Per-asset IDs, redacted target, outcome and stable reason code.
- Evidence IDs, source, authorized seed, observed URL, UTC time, method, tool/version,
  DNS answers, connected IP, HTTP status and redirect destination where actually observed.
- Observations reference evidence IDs and mark `observed` or `tentative` confidence.
- `summary` counts completed/partial/denied/error/skipped assets.
- `findings = []`, `vulnerability_assessment = "not_performed"`, explicit seed-only coverage.

Every non-root URL path and the entire query are withheld, including query keys.
Different paths may therefore display alike; stable asset/evidence IDs distinguish
them within a run. Use your original private target list for reproducibility.
Raw bodies and cookies are never persisted. Selected headers retain presence,
recognized media type, a few fixed tokens or a recognized product candidate;
unknown media types retain presence only to avoid exporting arbitrary header data;
no arbitrary header dumps, versions, CSP nonces or cookie values are exported.
A Server/X-Powered-By candidate is tentative and can be forged; missing headers
are observations only, without severity or a confirmed vulnerability claim.

Titles are **off by default**. `--include-titles` opts into a bounded UTF-8 HTML
title sample (no browser/JavaScript). Known secret patterns, reflected path/query
fragments, email addresses and control characters are removed/withheld. Analysis
and output lengths are bounded. This is heuristic, NOT a guarantee against
unknown sensitive content. Do not enable titles for sensitive/authenticated pages.
TLS certificate inventory, HTML export, report import and historical comparison
are not implemented in M2A.

## Outcomes and validation

- Exit 0: every seed completed collection. This does not mean any target is secure.
- Exit 1: operational failure, denied/skipped/partial coverage or failed output write.
- Exit 2: invalid input/configuration. Typer parsing errors retain Typer's text format.
- An aborted run reports `interrupted`, not a completed inventory.

Tests cover all M1A/M1B regressions, real loopback DNS/HTTP/verified TLS, live local
CLI collection, redirect denial, bounded samples, partial evidence, shared budgets,
redaction, JSON cleanliness, no overwrites and wheel entry points outside the checkout.
Offline tests remain socket-blocked; integration opts into numeric loopback only.
No external target or IPv6 transport result is claimed by these tests.
