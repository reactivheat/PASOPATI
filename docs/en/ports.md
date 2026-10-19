# M2C: explicit TCP-connect inventory

[Bahasa Indonesia](../id/ports.md) · [Commands](commands.md)

`ports` tests TCP connection establishment to explicitly authorized host/port pairs.
It requires no administrator privileges, sends no application payload and reads no
banner. It does not identify services, versions, operating systems or vulnerabilities.
Port 443 is not automatically labeled HTTPS; open does not prove an application works.

## Reproduce locally

From an installed checkout, start the existing fixture in another terminal:

```text
python -m pasopati.lab --port 8765
```

Then:

```text
pasopati ports 127.0.0.1 --ports 8765 --config examples/lab.toml --json
pasopati --lang id ports --targets-file examples/tcp-lab-hosts.txt --ports 8765 --config examples/lab.toml --output reports/tcp-lab-001
```

Expected fixture behavior: one TCP attempt, `tcp.state = "open"`, no target DNS,
no HTTP request and no service identification. These are repeatable fixture
expectations, not fabricated production results. The checked-in config authorizes
only this loopback address/port; it is not a real-target authorization template.
Stop the fixture with Ctrl+C. Use a new output directory on every run.

## Authorization and explicit inputs

For other systems obtain actual permission, then set `authorized = true`, select
`profile = "safe"` and allow the exact domains/CIDRs and ports in your private TOML.
Defaults from `init` remain passive/unauthorized. Domain rules do not authorize
literal IP targets: those need explicit CIDR coverage. Supported private lab
addresses also need CIDRs and `allow_private = true`; forbidden special-use ranges
remain denied. Exclusions win. See [configuration](configuration.md).

```text
pasopati ports your-authorized-host.example --ports 22,80,443 --config pasopati.toml --output reports/tcp-001 --json
```

This is syntax, not a scanned target or permission to test it. `--ports` has no
default scan set: supply decimal numbers separated by commas, without spaces,
leading zeroes, ranges, names or signs. Each must be 1–65535. At most 64 port
entries before deduplication. `--targets-file` accepts bounded UTF-8 host/IP lines
(optional BOM, empty lines/full-line `#` comments ignored), not the URL list used
by `scan`. Combine one positional host and a file if needed. No URL, wildcard,
CIDR, ambiguous IP, credentials or `host:port` syntax. IPv6 is a bare address at
input and bracketed in endpoint display. No subnet expansion or reverse DNS.

Validate the whole input before network activity: file at most 1 MiB, at most 64
host entries before deduplication, canonical names/IDNA, at most 256 unique host/port
pairs. Invalid entries abort the entire batch. Out-of-scope hosts/ports instead
produce explicit denied outcomes with no DNS for wholly denied hosts. Discovered
subdomains are not automatically imported, authorized or probed.

## Connection controls and limits

The collector uses the same scope, scoped A/AAAA resolver and `RequestBudget` as
discovery. Resolve once per eligible host/run; require a complete successful DNS
answer set, then check **all** addresses before connecting to any. A mixed public/
forbidden answer, second-family failure, inconsistent answer or more than 16
addresses fails closed; no silent safe subset. Negative DNS answers retain evidence
but cannot complete TCP coverage. Original DNS timestamps/answers are reused in
each port asset with unique evidence IDs; this does not mean DNS was repeated.
TTL is observed metadata, not a freshness guarantee for every later endpoint.

Every attempted endpoint uses a validated numeric IP, not a socket hostname.
That pinned snapshot prevents check-then-re-resolve/rebinding at connection time.
No hidden refresh, retry, alternative resolver, proxy or automatic tool adapter.
All approved resolved addresses are considered for every approved requested port,
until the shared budget is exhausted. OS routing/NAT remains outside this library.

Safe policy: 50 logical units for the whole run, aggregate one unit/second,
concurrency ceiling two (current scheduler is sequential). Each A/AAAA lookup and
each TCP connect consumes one unit, including failures. NXDOMAIN stops that name's
remaining DNS query. dnspython retransmissions/nameserver attempts and OS TCP SYN
retransmissions are **not** wire-packet counters or packet-rate enforcement.
The input limit does not guarantee all pairs/addresses fit in 50 units.

Each DNS lookup name has the existing 10-second total/3-second query limits.
Each TCP endpoint has a 10-second total deadline including limiter waits and a
connect phase of at most three seconds or remaining time. Late results cannot
become accepted open/refused results. All sockets close on success, failure and
cancellation. The OS is not a hard-real-time scheduler. No application data is
sent/read, although ordinary TCP handshake/close packets and server-side logs occur.
See [Python's socket contract](https://docs.python.org/3.12/library/socket.html#socket.socket.connect)
and [OS error symbols](https://docs.python.org/3.12/library/errno.html).

## Interpret evidence, not port-number guesses

| `tcp.state` | Meaning |
| --- | --- |
| `open` | TCP connect returned success within its phase deadline |
| `refused` | OS explicitly reported connection refusal; may reflect a host or intermediary |
| `timeout` / `deadline_exceeded` | No accepted result within the bound; not closed/filtered |
| `unreachable` | OS reported an unreachable path; not a service-state verdict |
| `reset` | Reset/error during connection; not a service/version verdict |
| `local_error` / `error` | Local permission/resources/family or other OS failure; target state unknown |

DNS failure, policy denial and budget exhaustion produce **no fabricated TCP
attempt/state**. Evidence retains target host, attempted numeric IP, port, transport,
UTC collection time, method, installed version and the successful connected IP only
when observed. Observations reference evidence IDs, safe numeric OS error codes
where available and connect duration excluding rate waits. Durations are not network
RTT or performance benchmarks. Raw exception strings, banners, bodies and secrets
are never reported. No service inference via `getservbyport`, TLS or protocol probes.

JSON/TXT share the existing `RunReport`; TCP uses `schema_version = "3"`, keeps
`report_type = "pasopati.recon"`, and adds `tcp` metadata and evidence `port`/
`transport`. Scan schema 1 and discovery schema 2 wire shapes are unchanged.
`tcp.service_identification = "not_performed"`, `payloads_sent = false`, `findings = []`
and `vulnerability_assessment = "not_performed"`. Review real domain/IP inventories
as sensitive data; do not commit them. See [HTTP reports](recon.md) for output privacy.

`--json` emits one ANSI-free document. `--output NEW_DIRECTORY` explicitly saves
UTF-8 JSON/TXT and refuses existing output before any networking. Exit 0 means all
resolved/authorized requested endpoint attempts completed open/refused observation,
not that all ports are open or targets secure. Exit 1 includes partial/denied/skipped/
unknown/DNS/output failure. Exit 2 means invalid input/configuration. Cancellation
reports `interrupted`, not a completed inventory; files may be incomplete.

Tests cover guarded local DNS, real IPv4 and available IPv6 loopback TCP, successful
and refused connects, zero payload, cleanup, scope/limits, error classification and
installed entry points outside the checkout. IPv6 integration explicitly skips if
the OS cannot bind `::1`. No external target, SYN/raw/UDP scan, service detection,
Nmap parity or native VirtualBox validation is claimed.
