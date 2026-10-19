# M2D: evidence-backed web and verified TLS observations

[Bahasa Indonesia](../id/web-tls.md) · [Scan](recon.md) · [Commands](commands.md)

`scan --web-details` extends explicit URL inventory without increasing its requests.
It adds verified leaf-certificate/negotiation metadata, private run-local endpoint
identities, supported header summaries and transparent tentative product rules.
It is not a crawler, browser, TLS auditor or vulnerability/CVE detector.

## Usage and reproducible first run

Start the existing local fixture in another terminal:

```text
python -m pasopati.lab --port 8765
```

From an installed checkout:

```text
pasopati scan --targets-file examples/lab-targets.txt --config examples/lab.toml --web-details --output reports/web-lab-001 --json
```

The fixture is HTTP, so it produces endpoint/header evidence but **no TLS evidence**.
Missing TLS observations on HTTP do not mean a certificate check failed. This example
retains the existing fixture's four attempts/three seeds. It never follows HTML links.
Use a new output directory each run. See [the lab guide](recon.md) for fixture details.

For actual authorized HTTPS, provide explicit URLs and a private allowlisted TOML:

```text
pasopati scan https://your-authorized-host.example/ --config pasopati.toml --web-details --json
```

This is syntax, not evidence that a target exists or permission to test it. Require
`authorized = true`, safe profile, allowed ports/domains/CIDRs and matching address
policy. Shared DNS/IP pinning, redirect/downgrade checks, one-unit/second rate,
50-hop budget, concurrency ceiling two and 3s connect+TLS/5s read/10s total deadlines
remain unchanged. No added requests, protocol enumeration, port discovery or retry.
The scheduler is sequential and HTTP attempts the first validated IP only.

## TLS evidence: what is actually verified

On each HTTPS hop, the original hostname/IP is checked using the normal Python/
OpenSSL client context and local trust store. No insecure switch, untrusted-certificate
fallback or verification bypass exists. A metadata observer runs only after successful
verification and within the connect+TLS deadline, before sending the HTTP request.
It records the actual numeric connected IP, target URL with path/query withheld,
port, UTC collection time, method and installed tool version.

`tls.*` observations reference that handshake evidence:

- `verified = true`: successful local trust/hostname validation, not a universal trust verdict.
- `leaf_sha256`: SHA-256 of the verified leaf's DER bytes, **not** SPKI or a chain fingerprint.
- `not_before`, `not_after`: leaf validity timestamps in UTC.
- `protocol`, `cipher`, `cipher_bits`: this connection's negotiated TLS version,
  cipher and symmetric cipher bits; not certificate key size or all supported suites.
- `san_dns_count`, `san_ip_count`, `san_other_count`: SAN entry counts, not discovered targets.

No PEM/DER, certificate subject/issuer/serial, SAN values, session keys or private keys
are exported. Certificate size is bounded to 64 KiB and SAN entries to 4,096. TLS 1.2/
1.3 metadata is supported; other metadata is an explicit unsupported outcome, not
a fabricated result. Successful TLS evidence survives subsequent HTTP/header/body
failure, but does not imply an HTTP response was received. A verified handshake with
no HTTP response has no invented HTTP status or endpoint identity.

With this option, failed certificate verification reports `tls_verification_failed`;
other TLS errors report `tls_failed`, unavailable/bounded metadata reports
`tls_metadata_unavailable`. No unverified fingerprint is supplied and no insecure
retry occurs. System `SSL_CERT_FILE`/trust configuration is respected; the production
context deliberately ignores `SSLKEYLOGFILE`. Configure trusted private CAs locally,
not by disabling verification. Tests use temporary local certificates.

Limitations: no complete chain inventory, OCSP/CRL/revocation/CT status guarantee,
certificate key/signature analysis, cipher enumeration, expiry finding/severity,
HTTPS application-health verdict or public-target/platform validation claim.
See [Python's TLS API](https://docs.python.org/3.12/library/ssl.html#ssl.SSLSocket.getpeercert).

## Endpoint mapping without disclosing private paths

Each actual HTTP response gets `web.endpoint_id`: a full HMAC-SHA256 of its canonical
URL using a fresh random 32-byte key for that run. The key is never exported.
Repeated identical URLs within a run share an ID; distinct paths/queries can be
distinguished even though their visible URL is redacted. These are **run-local**
identities, not historical comparison IDs, public hashes, or evidence of hidden endpoints.
`web.endpoints_observed` counts distinct response URLs, including allowed redirects.
Denied/unvisited links and TLS-only handshakes do not create endpoint records.
HTTP protocol version is included when observed by the real response parser.

Mapping is restricted to supplied URLs and allowed redirect hops. No link extraction,
JavaScript, robots/sitemap fetch, directory guessing or automatic discovery import.
Input/body/redirection bounds are unchanged; large samples still produce partial
coverage. `--include-titles` remains separate and off by default, with its documented
heuristic privacy limitations. Real host/IP/certificate fingerprints remain sensitive
recon data even with redacted paths; do not commit real reports or target lists.

## Transparent header observations

All values below come from the same actual HTTP response evidence, not extra probes:

| Observation | Contract |
| --- | --- |
| `fingerprint.server`, `fingerprint.x-powered-by` | Recognized product prefix only, always tentative |
| Matching `.rule` | Stable `header-prefix/1:HEADER:PRODUCT` rule ID |
| `hsts.*` | Supported max-age/includeSubDomains/preload tokens and whether received over HTTPS |
| `csp.recognized_directives` | Allowlisted directive names only, never sources/nonces/hashes/report URLs |
| `http.advertised_methods` | Supported Allow tokens only; no such methods are executed |

Product rules reuse the documented case-insensitive prefix boundary `[/\s;]` or end
of value. Known labels: nginx, apache, caddy, microsoft-iis, openresty, gunicorn,
uvicorn, express, php, asp.net. Arbitrary/unknown values and versions are withheld.
These headers can be forged; a matched prefix proves only the response advertised it.
No CVE inference or confirmed technology/version claim.

Parsers accept at most 8,192 characters per inspected header. HSTS supports up to
16 unique directives and an unquoted 1–10 digit max-age. Zero means a removal token,
not a vulnerability; a preload token does not prove browser preload inclusion.
HTTP-delivered HSTS is recorded as not received over HTTPS, not an enforced policy.
CSP supports at most 64 directive segments and does not evaluate policy effectiveness
or multiple combined policies. Allow supports at most 32 fixed method tokens.
Unsupported/oversized/ambiguous inputs get explicit support flags rather than raw
values or a "missing/secure/vulnerable" verdict. No Set-Cookie values are inspected/exported.

References: [HSTS specification](https://www.rfc-editor.org/rfc/rfc6797),
[CSP specification](https://www.w3.org/TR/CSP3/). Supported subsets are not full browser parsers.

## Reports and outcomes

Both renderers use the same `RunReport`. This opt-in uses `schema_version = "4"`,
`web` coverage/ruleset/endpoint metadata, handshake evidence and referenced observations.
Without it, scan schema 1 remains unchanged; discovery schema 2 and TCP schema 3 also
keep their previous wire shapes. `findings = []` and `vulnerability_assessment = "not_performed"`.
JSON is one ANSI-free document. `--output NEW_DIRECTORY` explicitly writes UTF-8
JSON/TXT, never overwrites, and reserves output before traffic.

Exit 0 means requested collection completed, not secure targets or valid findings.
Exit 1 includes TLS/HTTP failure, partial/denied/skipped/budget/output failure;
existing evidence remains qualified. Exit 2 means invalid input/configuration.
Cancellation is not reported as completed. Tests cover local HTTPS trust/hostname
success/failure, HTTP failure after TLS, SNI/numeric pinning, cleanup/deadlines,
secret-free metadata, no crawling, old-schema regressions and clean-wheel CLI paths.
Screenshot/GIF and native VM documentation remain deferred.
