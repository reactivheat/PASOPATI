# Changelog

## Unreleased — M2D

- Add opt-in `scan --web-details` using the same scoped Session/requests, with verified
  leaf DER SHA-256, UTC validity, negotiated TLS/cipher metadata and SAN counts only.
- Preserve verified handshake provenance before HTTP; classify verification/TLS/
  metadata failure without insecure retry or unverified fingerprints.
- Add private per-run HMAC endpoint identities and fixed, versioned tentative
  header product rules plus bounded HSTS/CSP/Allow summaries; no raw header export.
- Add web/TLS schema 4 in the shared JSON/TXT RunReport, preserving schemas 1–3,
  local HTTPS/privacy/deadline regressions and clean-wheel CLI checks.

No crawling, cipher/chain/revocation audit, SAN target expansion, CVE/severity verdict,
package publication, tag, release or license selected. Version stays unreleased 0.1.0.

## Unreleased — M2C

- Add explicit `ports` TCP-connect inventory with bounded host/port inputs, all-answer
  DNS scope checks, numeric pinning and shared DNS/TCP logical budgets/deadlines.
- Record actual open/refused/timeout/unreachable/reset/local-error evidence; never
  infer closed/filtered from a timeout or a service from a port number. No payloads.
- Extend the shared JSON/TXT RunReport with TCP schema 3, preserving schema 1/2 wire
  shapes. Record connect provenance, port/transport, safe OS codes and partial coverage.
- Add loopback TCP/DNS fixtures, IPv6 when available, cleanup/zero-payload regressions,
  clean-wheel executable/module checks and bilingual functional guides.

No raw/SYN/UDP scan, banner grabbing, service/version identification, CVE verdicts,
package publication, tag, release or license selected. Version remains unreleased 0.1.0.

## Unreleased — M2B

- Add explicit-source `discover subdomains` with offline file/wordlist candidates,
  optional disclosed crt.sh queries, strict input/provider bounds and source digests.
- Add opt-in scoped A/AAAA validation, distinct negative/failure outcomes, actual
  TTL/attempt evidence and bounded per-parent wildcard checks with qualified confidence.
- Share logical budgets/rate/deadline controls across provider HTTP and DNS lookups;
  provider policy never widens target scope or automatically probes discovered hosts.
- Extend the common inventory model/renderers with discovery schema 2 while preserving
  scan schema 1; keep empty valid provider results distinct from failed queries.
- Add offline/loopback regressions, installed-entry-point discovery checks and bilingual
  functional guides. Visual documentation remains deferred; no external target scan.

No port/service engine, crawling, vulnerability analysis, package publication, tag,
release or license selected. Version remains unreleased 0.1.0.

## Unreleased — M2A

- Add authorized, explicit-seed `scan` with bounded UTF-8 batch input and deduplication.
- Retain actual DNS/literal and HTTP-hop provenance, partial failures, shared request
  budgets and honest completed/partial/denied/error/skipped inventory outcomes.
- Add bounded body sampling for inventory while retaining the strict default API;
  handle malformed redirects without leaking raw input or bypassing scope.
- Add one versioned inventory model for JSON/TXT, explicit exclusive output, conservative
  URL/header redaction and opt-in, bounded, heuristically redacted title samples.
- Add local-only HTTP lab, synthetic configuration/targets, end-to-end tests and
  bilingual inventory documentation. No external-target scan used for validation.
- Extend clean-wheel CI to real local recon through both installed entry points;
  add contribution/security-reporting guidance without choosing a license.

No crawling, subdomain discovery, vulnerability/CVE claims, HTML report, package
publication, tag, release or license selected. Version remains unreleased 0.1.0.

## Unreleased — M1B

- Add strict bounded TOML, exclusive template initialization, immutable profiles,
  and offline domain/IP/URL scope decisions with localized reason messages.
- Add internal HTTP/HTTPS transport with bounded DNS lifetime (dnspython), numeric
  IP pinning, TLS/SNI verification, safe redirects and shared resource budgets.
- Add loopback HTTP, DNS and verified TLS tests, deterministic policy/deadline tests,
  guarded integration sockets and installed-entry-point checks outside the checkout.
- Fix pytest basetemp parent initialization for fresh clones and console-script
  discovery on hosted Python installations; extend clean-wheel CI smoke coverage.
- Update bilingual configuration/transport/installation/CLI guides and repository URL.

No scan command, report exporters, package publication, tag, release or license added.

## 0.1.0 — M1A (unreleased)

- Add src-layout packaging and installed CLI/module entry points for Python 3.12+.
- Add ASCII branding, narrow-terminal fallback, English/Indonesian project messages.
- Add offline doctor with ten checks, optional integrations, JSON and exit codes.
- Add pytest, Ruff, mypy, build validation, and Linux/Windows CI configuration.
- Add bilingual documentation and future security/report architecture contracts.

No scanning, network reconnaissance or vulnerability detection is implemented.
License selection and repository/package publication remain pending.
