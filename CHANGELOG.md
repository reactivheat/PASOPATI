# Changelog

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
