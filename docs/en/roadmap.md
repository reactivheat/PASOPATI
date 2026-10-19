# Capability roadmap and evidence requirements

[Bahasa Indonesia](../id/roadmap.md)

PASOPATI aims to support practitioners with connected, reproducible recon workflows.
"More powerful" is a goal, not a current capability or measured performance claim.
M2A performs real, authorized DNS/HTTP traffic; the local lab is a reproducible
verification environment, not a restriction that scanning works only offline.

## Present capability, not marketing

| Function | PASOPATI M2A | Next work |
| --- | --- | --- |
| Explicit authorized URL inventory | Implemented, bounded DNS/HTTP/HTTPS | Extend metadata carefully |
| Evidence, scope, shared limits, JSON/TXT | Implemented | Correlation and run comparison |
| Subdomain enumeration | Not implemented | Candidate discovery and DNS validation |
| Host/port/service inventory | Not implemented | Explicit bounded TCP-connect inventory |
| TLS certificate inventory | Not implemented; certificate verification is enforced | Extract verified metadata |
| Vulnerability/CVE validation | Not performed | Evidence-based checks with separate acceptance criteria |
| HTML reports, history/diff | Not implemented | Render the normalized model, never infer in renderers |

[Nmap's reference guide](https://nmap.org/book/man.html) documents host discovery,
port scanning, service/version and OS detection, among other functions. M2A does
not implement those engines. [Sublist3r](https://github.com/aboul3la/Sublist3r) is a
subdomain enumeration tool; M2A does not enumerate subdomains. These projects are
references, not bundled dependencies, validated integrations or defeated benchmarks.

## Proposed milestones, not active features

1. **M2B — domain/subdomain discovery.** Explicit provider selection and disclosure
   of queries sent to third parties, bounded provider budgets, provenance and
   deduplication. Validate DNS and label boundaries; discovered names are candidates,
   not automatically authorized targets. No active probing outside approved scope.
2. **M2C — port/service inventory.** Start with unprivileged TCP-connect checks to
   explicitly allowed addresses/ports. Share scope, numeric pinning, deadlines,
   rate/concurrency/attempt budgets and cleanup controls. Do not mislabel timeouts
   as open/closed. Any external-tool adapter needs separate review, numeric targets,
   fixed argument arrays, bounded output/time and no shell or arbitrary NSE scripts.
3. **M2D — deeper web/TLS observations.** Verified certificate metadata, bounded
   endpoint mapping and transparent fingerprint rules with confidence. Metadata
   hints are not proof of a vulnerable version; no automatic exploitation.
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
