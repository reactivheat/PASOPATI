# Contributing

[Bahasa Indonesia](docs/id/contributing.md)

PASOPATI is an unreleased, public-source project intended for authorized recon.
The owner has not selected a license; public visibility is not a license grant.
Do not assume redistribution rights. No bounty or support SLA is offered.

Read [AGENTS.md](AGENTS.md) and [the recon contract](docs/en/recon.md). Keep changes
small, typed, bilingual and testable. Do not add hidden network clients, automatic
scope expansion, insecure TLS, exploit payloads or unproven vulnerability claims.
Every collector must use the shared scope/transport/budget controls. New tests
stay offline unless using explicitly guarded numeric-loopback fixtures.

Use a project virtual environment; never modify global Python/Git settings.
Run pytest, Ruff lint/format, mypy, build and pip check as documented in the
[README](README.md). Test the wheel from outside the checkout, not only editable
source imports. Report executed platforms, failures/skips and limitations accurately.
Do not invent benchmark, accuracy or CI results. OpenSSL-dependent TLS tests must
skip explicitly if the fixture cannot be generated, never disable verification.

Never commit real target lists, scan reports, credentials, TLS keys or local
diagnostics. Use only synthetic loopback examples in tests and documentation.
Respect existing work and obtain owner approval for release/publication/license
changes. For vulnerabilities, follow [SECURITY.md](SECURITY.md), not public disclosure
of sensitive details in an issue or pull request.
