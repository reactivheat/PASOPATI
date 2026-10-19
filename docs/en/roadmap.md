# Capability roadmap and evidence requirements

[Bahasa Indonesia](../id/roadmap.md)

PASOPATI aims to support practitioners with connected, reproducible recon workflows.
"More powerful" is a goal, not a current capability or measured performance claim.
M2A performs real, authorized DNS/HTTP traffic; the local lab is a reproducible
verification environment, not a restriction that scanning works only offline.

## Present capability, not marketing

| Function | PASOPATI M2D | Next work |
| --- | --- | --- |
| Explicit authorized URL inventory | Implemented, bounded DNS/HTTP/HTTPS | Extend metadata carefully |
| Evidence, scope, shared limits, JSON/TXT | Implemented | Correlation and run comparison |
| Subdomain enumeration | Explicit file/wordlist/crt.sh candidates; opt-in scoped DNS/wildcard checks | Additional providers and separately measured coverage |
| Explicit TCP port inventory | Implemented, bounded numeric connects and qualified outcomes | Protocol/service metadata requires separate observations |
| Web/TLS observations | Opt-in verified leaf/negotiation, run-local endpoint identities, qualified header rules | Broader independently verified analysis; no complete TLS audit |
| Vulnerability/CVE validation | Not performed | Evidence-based checks with separate acceptance criteria |
| HTML reports, history/diff | Not implemented | Render the normalized model, never infer in renderers |

[Nmap's reference guide](https://nmap.org/book/man.html) documents host discovery,
port scanning, service/version and OS detection, among other functions. M2C adds
TCP-connect only, not raw/SYN/UDP, host discovery, service/version or OS detection.
[Sublist3r](https://github.com/aboul3la/Sublist3r) is a
subdomain enumeration tool; M2B now has its own bounded discovery workflow, not a
claim of equal coverage or speed. These projects are
references, not bundled dependencies, validated integrations or defeated benchmarks.

## Completed scope and proposed next milestones

1. **M2B — implemented domain/subdomain discovery.** See [the functional guide](discovery.md).
   Explicit file/wordlist/crt.sh sources, provider disclosure, shared logical budgets,
   provenance/digests, label-boundary checks and opt-in A/AAAA/wildcard observations.
   Discovered names remain candidates, not automatically authorized targets; no
   automatic HTTP probing. Fixtures verify behavior, not public-provider availability.
2. **M2C — implemented TCP port inventory.** See [the guide](ports.md). Explicit
   hosts/ports, all-answer validation, numeric connects, shared DNS/TCP budgets and
   qualified open/refused/unknown outcomes. No payloads, service/version guessing,
   raw/UDP probes or tool adapter. Service identification remains not_performed;
   application metadata is a later, separately evidenced capability.
3. **M2D — implemented web/TLS observations.** See [the guide](web-tls.md). Verified
   leaf fingerprint/validity, one negotiated protocol/cipher, SAN counts, private
   run-local endpoint mapping and bounded versioned header rules. Same scoped URL/
   redirect requests, no crawling/cipher enumeration or CVE verdicts. Raw certificates,
   SAN values, header secrets and endpoint keys are not exported; schemas 1–3 are preserved.
4. **M3 — practitioner workflow.** Cross-source asset correlation, portable escaped
   HTML reports, historical comparison, prioritization and independently validated
   exposure checks. All views use the normalized evidence model.

Every milestone requires an agreed contract and tests before implementation.
Do not silently grow M2A into an unrestricted scanner. Network safety is part of
recon correctness, not a performance option to disable for favorable measurements.

## Criteria for any comparison claim

- Version the fixtures, ground-truth inventory, tool/config/command, environment
  and measurement procedure. Compare only overlapping functions and equal scope.
- Record known assets found/missed, false positives/negatives and incomplete coverage.
  Do not infer general accuracy from a small synthetic lab.
- Measure actual request count, elapsed time, bytes and resource use under disclosed
  limits. Do not compare a one-request/second HTTP policy to unrestricted packet scans
  and claim a general winner. Report repeated-run variation, not cherry-picked timing.
- Test error paths, wildcard DNS, changes in answers, unresponsive services,
  redirects, TLS failures, redaction and cancellation as well as success.
- Use owned/authorized lab targets. Public deployment, real-target accuracy and
  native-platform validation require separate evidence. No screenshots/GIFs of
  desktop wallpaper or simulated output count as feature validation.

Before an open-source release: owner-selected license, verified private security
contact, contributor guidance, dependency/build review and a documented support
policy. A public repository alone is not a license grant. No release is authorized
or implied by this roadmap.
