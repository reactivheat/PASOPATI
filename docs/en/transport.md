# Internal scope-aware transport (M1B)

[Bahasa Indonesia](../id/transport.md) · [Configuration](configuration.md)

`pasopati.transport.Session(config).fetch(url, method="GET")` is a Python API for
future modules, not a scan command. It returns immutable status/body/content-type
data in memory and never stores response bodies, cookies or headers on disk.
Do not print raw bodies or sensitive URLs in future callers. CLI policy commands
never import this transport and remain offline.

The caller must supply validated `Config` with explicit network authorization,
the `safe` profile and a matching scope. User acknowledgement does not establish
ownership/legal permission. Every redirected destination is checked again.

## Connection invariants

1. Reject unauthorized/passive/method/scope/port requests before target DNS.
2. Resolve both A and AAAA using OS-configured numeric DNS servers and dnspython;
   search suffixes and automatic DoH discovery are disabled. No fallback public
   resolver or system getaddrinfo is used. An empty/unsupported resolver setup
   fails closed; configure the OS resolver before using this API.
3. DNS uses a shared lifetime of at most 3 seconds (or the operation's remaining
   time), passed into each actual DNS query. This is why dnspython is the one
   added runtime dependency: a timeout check after blocking getaddrinfo is insufficient.
   See the [dnspython lifetime contract](https://dnspython.readthedocs.io/en/stable/resolver-class.html).
4. Reject the entire answer set if any address violates address policy/exclusions.
   A permitted domain may resolve to public addresses without separate CIDR rules;
   literal IP targets and nonpublic lab answers require explicit CIDR coverage.
5. Use numeric socket.connect for one validated address; no hidden hostname lookup,
   alternate-IP retry or automatic proxy. OS routing/NAT remains outside this library.
6. HTTPS uses system trust, certificate verification, original-host SNI and Host.
   TLS key logging is not enabled by SSLKEYLOGFILE. No insecure TLS option exists.

## Resource limits and response handling

One Session shares 50 attempts, aggregate 1 request/second and concurrency 2.
Budget is consumed before each attempted hop, including failed DNS/connect attempts.
There are no automatic retries. Redirects (301/302/303/307/308) consume the same
budget/rate gate and retain the method; GET/HEAD need no body conversion. Relative
locations work. Three redirects maximum; loops, missing locations, out-of-scope
destinations, non-HTTP schemes and HTTPS downgrades are rejected. Headers are fixed
per request; no credentials, cookies or sensitive headers can cross origins.

The 10-second monotonic operation deadline includes semaphore/rate waits, DNS,
connect, TLS, headers, body and all redirects. Connect+TLS share a 3-second phase;
socket reads/writes use at most 5 seconds or the remaining deadline. Every raw
receive rechecks the deadline, including trickling headers/chunk framing. Local OS
scheduling/trust-store I/O is not a hard real-time guarantee. A session is reusable
after failure; response/socket/semaphore/lock resources are closed/released.

Bodies are read incrementally and rejected above 64 KiB, even without Content-Length
or with chunked framing. HEAD does not read a body. Only identity encoding is accepted;
compressed responses are rejected rather than decompressed. No cookie jar, proxy
environment, authentication negotiation, credential forwarding, persistence or logging.

## Tests and limits

Tests use injected resolver/connector/clock plus real loopback HTTP, DNS and HTTPS
fixtures. Ordinary tests cannot open sockets. Integration sockets allow numeric
loopback only, including UDP sendto; external destinations are blocked. TLS tests
generate temporary certificates with OpenSSL, trust only the fixture certificate,
and verify that the wrong hostname is rejected. If OpenSSL is absent, that one
integration case explicitly skips; TLS settings and pinning still have unit tests.

DNS tests use local UDP servers, including an unresponsive server to prove lifetime
enforcement. IPv4/IPv6 policy is unit tested; actual IPv6 networking and public-target
transport are not claimed. The resolver does not use hosts files/mDNS or DoH/DoT.
This milestone does not implement asset discovery, scanning or vulnerability analysis.
