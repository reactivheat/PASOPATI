# M2B: scoped subdomain candidates and DNS validation

[Bahasa Indonesia](../id/discovery.md) · [Commands](commands.md)

`discover subdomains` combines explicitly selected sources, deduplicates names and
optionally collects A/AAAA evidence. It does not automatically probe candidate
websites, enumerate ports, change your allowlist or infer vulnerabilities.

## First run without network access

From an installed checkout:

```text
pasopati discover subdomains example.invalid --source file --candidates-file examples/discovery-candidates.txt --source wordlist --wordlist examples/discovery-wordlist.txt --config examples/discovery.toml --output reports/discovery-offline-001 --json
```

These synthetic `.invalid` inputs need no DNS server or third-party account.
The example config is passive and unauthorized. Without `--resolve` or the
`crtsh` source, importing/generating names is offline, even with a safe profile.
Candidates are **unverified**, including those matching the configured scope.
`scope.allowed` records offline policy matching, not connectivity or legal permission.
An excluded candidate may be retained as source data offline; with `--resolve`
it is denied before DNS. A collected certificate wildcard remains a pattern,
never a concrete host or an inferred apex host.

## Sources and input boundaries

At least one repeatable `--source` is required; nothing is enabled implicitly:

| Source | Required input | Behavior |
| --- | --- | --- |
| `file` | `--candidates-file FILE` | Fully qualified domain candidates, including wildcard patterns |
| `wordlist` | `--wordlist FILE` | Relative prefixes such as `www`, `api`, `dev.api`; append `.DOMAIN` |
| `crtsh` | `--allow-provider-queries` | One bounded Certificate Transparency query to crt.sh |

Local files are UTF-8 (optional BOM), at most 1 MiB each, with 1–4,096 nonempty,
non-comment entries. Blank lines and full-line `#` comments are ignored.
At most 256 unique candidates are retained across sources. Domains use strict
label boundaries and normalized IDNA names; `example.invalid.evil.invalid` is
not a child of `example.invalid`. URLs, IPs, invalid names and out-of-domain
local input reject the whole batch before traffic. Wordlists do not accept
wildcards or trailing dots. No built-in large wordlist is supplied.

Duplicate names retain each contributing source, its first line/certificate
reference and a SHA-256 digest for each local input. Local filesystem paths
and raw source/provider bodies are not exported. Provider SANs unrelated to the
requested domain are discarded, not followed or echoed as targets.

## Opt into DNS only for authorized scope

Create a private TOML for systems you are authorized to assess. This is syntax,
not authorization for a real domain:

```toml
schema_version = 1
profile = "safe"
authorized = true

[scope]
allow_domains = ["your-authorized-domain.example", "*.your-authorized-domain.example"]
exclude_domains = ["excluded.your-authorized-domain.example"]
```

The base domain and every queried candidate/random probe must be allowed.
`*.DOMAIN` does not authorize the apex; explicitly list both if both are approved.
Do not add the wildcard unless the actual engagement permits it. Permitted private
lab addresses additionally require explicit CIDRs and `allow_private = true`;
exclusions win. Link-local, metadata and other forbidden special-use ranges remain
denied. See [configuration](configuration.md).

```text
pasopati discover subdomains your-authorized-domain.example --source wordlist --wordlist your-prefixes.txt --resolve --config pasopati.toml --output reports/discovery-dns-001 --json
```

`--resolve` distinguishes `dns_resolved`, `dns_nxdomain`, `dns_no_address`, timeout,
resolver failure, forbidden addresses and incomplete coverage. Responses retain
actual addresses and TTL when available. A/AAAA answers do not prove an open port,
HTTP availability, ownership or a unique host. Recursive DNS may follow CNAMEs;
the returned address set still passes address policy. No connection is made to
any candidate address, and CNAME destinations are not added as candidate targets.

Before resolving a subdomain, probe three random labels at its **immediate parent**,
only if all probe names are in scope. Cache each parent's result; probe at most
four parents per run. Any positive probe yields `possible`, even with rotating IPs.
`clear` means only that these three probes were negative during this run; it is
not proof that wildcard DNS never exists. Scope/length/budget/failure limits are
reported as unchecked or inconclusive. A resolved candidate with a possible
wildcard has tentative hostname confidence; unchecked wildcard coverage is partial.

## Optional third-party CT query

Selecting crt.sh sends the base domain to a third party and reveals the query to
your configured DNS resolver. Certificate records may be stale, missing, or shared;
they are candidate claims, not proof of a live host. Require safe profile,
`authorized = true`, an allowed base domain and explicit provider-query consent:

```text
pasopati discover subdomains your-authorized-domain.example --source crtsh --allow-provider-queries --config pasopati.toml --json
```

Add `--resolve` separately to request scoped target DNS validation. Without it,
crt.sh still uses outbound HTTPS/provider DNS; "passive CT" does **not** mean offline.
The fixed request is `https://crt.sh/?q=%25.DOMAIN&output=json`. A separate exact
`crt.sh:443` policy checks public provider addresses, TLS and each redirect, retains
target exclusions and never widens target scope. No custom provider URL, auth,
headers or credentials flag is exposed. No application retry or alternate provider.

Non-200, timeout, invalid JSON, excessive nesting or responses above 64 KiB are
explicit failures. At most 4,096 rows/name entries are parsed; truncation or malformed
rows produce partial source coverage. A valid empty JSON array is a completed query
with zero candidates, distinct from provider failure. Availability/rate limiting
of the public service is not guaranteed. The provider path is tested with fixtures;
no live crt.sh target query is claimed as development validation.

Interface references: [crt.sh web gateway](https://github.com/crtsh/crtsh-web),
[official database API implementation](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).
The bounded parser is independently implemented; no provider code is bundled.

## Budgets, reports and outcomes

One shared safe budget covers provider HTTP hops and target DNS A/AAAA lookups,
including wildcard checks: 50 logical attempt units, aggregate 1 unit/second,
concurrency ceiling 2. Each provider hop consumes one unit including its internal
provider DNS; each target RR lookup consumes one unit. NXDOMAIN stops that name's
remaining lookup. Per-name total deadline is 10 seconds including rate waits;
each DNS lifetime is at most 3 seconds. DNS uses numeric OS-configured resolvers,
no search suffixes, hosts/mDNS/DoH or fallback public resolver. dnspython may
retransmit or try configured nameservers within its lifetime: these are **logical
lookup limits, not wire-packet counters or packet-rate enforcement**.
See [transport](transport.md) and [dnspython's lifetime contract](https://dnspython.readthedocs.io/en/stable/resolver-class.html).

JSON/TXT consume the same `RunReport` as `scan`. Discovery uses `schema_version = "2"`;
existing scan schema 1 is unchanged. Additional `discovery` metadata includes source
status/digests, disclosure, DNS/provider counts and wildcard evidence. Evidence uses
`subject_name`, `query_name` and `query_type`, not fake URLs for DNS/local imports;
observations reference evidence IDs, timestamps and installed tool version.
Provider URL queries are withheld; no raw bodies, arbitrary headers or cookie values
are stored. Domain/IP names are still sensitive recon data: do not commit real reports.

`--json` emits one ANSI-free document. `--output NEW_DIRECTORY` explicitly creates
JSON/TXT, refusing existing outputs before networking. Use a new directory each run.
Exit 0 means all requested collection completed, **not** that every candidate is
live or unique: negative DNS answers and disclosed wildcard ambiguity are valid data.
Exit 1 includes provider failure, denied/partial/skipped DNS or output failure;
other selected sources may still contribute evidence. Exit 2 means invalid input/
configuration. `findings` stays empty and `vulnerability_assessment` is `not_performed`.
There is no completeness, speed or superiority claim against Sublist3r/Nmap.
