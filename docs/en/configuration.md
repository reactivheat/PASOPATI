# M1B configuration and offline policy

[Bahasa Indonesia](../id/configuration.md)

Create a project file with `pasopati init --path pasopati.toml`. Existing files
and symlinks are never overwritten. The initial policy is passive and unauthorized:

```toml
schema_version = 1
profile = "passive"
authorized = false

[scope]
allow_domains = ["example.invalid"]
allow_cidrs = []
exclude_domains = []
exclude_cidrs = []
ports = [80, 443]
allow_private = false
```

All four root fields are required. Scope fields have deny-by-default/empty
allowlist defaults, except ports 80/443. Unknown fields and incorrect types are
errors; booleans are not numbers. Files are limited to 64 KiB and rule/port lists
to 1024 entries each. CIDRs must have no host bits set. No implicit file discovery,
environment substitution, credentials, or executable configuration is supported.

```text
pasopati config validate --config pasopati.toml --json
pasopati scope check https://example.invalid --config pasopati.toml --json
pasopati profiles list --json
pasopati profiles show safe --json
pasopati --lang id --no-banner scope check example.invalid --config pasopati.toml
```

These commands never use DNS or HTTP. A scope match is NOT permission to connect;
the output explicitly sets `dns_checked` and `connectivity_checked` to false.
Authorization is a user acknowledgement, not proof of ownership or legal consent.
`doctor` remains independent of project configuration and offline.

Exact domains match only themselves. `*.example.invalid` matches subdomains at
DNS label boundaries, not the apex or `evil-example.invalid`. Exclusions always
win. Domain normalization uses Python's built-in IDNA 2003 codec, lowercase, and
one optional trailing dot; it does not implement UTS #46. IPv4/IPv6 CIDRs use
`ipaddress`; ambiguous numeric forms, zone identifiers, URL credentials, fragments,
control characters, non-HTTP schemes and invalid ports are rejected.

Nonpublic destinations are denied by default. Lab loopback/RFC1918/ULA access
needs all of: `authorized = true`, `allow_private = true`, explicit CIDR coverage,
and no exclusion. Link-local/metadata, unspecified, multicast, reserved,
documentation, shared address space and IPv6 transition mechanisms remain denied.

`passive` has no methods/network and budget 0. `safe` permits GET/HEAD with 50
requests/session, 1 request/second shared across callers, concurrency 2, 3 redirects,
connect 3s, read 5s, total operation 10s, body 64 KiB. Profiles are immutable built-in
policies; they cannot grant authorization or expand scope. M2A [scan](recon.md)
requires authorization, the safe profile and matching scope; policy commands stay offline.
M2B [discovery](discovery.md) defaults to offline local candidates; DNS and crt.sh
require explicit opt-ins, authorization and an allowlisted base domain. Discovery
shares the safe budget across provider hops and target DNS lookups, not wire packets.
M2C [ports](ports.md) additionally requires explicit numeric ports covered by
`scope.ports`. The same 50-unit budget covers DNS RR lookups and TCP connects;
literal targets need CIDRs, even when a related domain is allowed. Config schema stays 1.

Exit codes: 0 success/match; 1 scope denial or I/O/operational failure; 2 invalid
arguments/configuration/profile. Application JSON errors contain a stable reason
and localized message, never raw invalid input. Typer parser errors remain English
text. Global options precede the subcommand. JSON output never has a banner or ANSI.
