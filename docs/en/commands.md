# Command reference

[Bahasa Indonesia](../id/commands.md) · [README](../../README.md)

`pasopati [GLOBAL OPTIONS] COMMAND [OPTIONS]`

| Command/option | Behavior |
| --- | --- |
| `pasopati` | Banner, installed version, description, quick start |
| `--help` | Available commands/options; no decorative banner |
| `--version` | Installed distribution version from importlib.metadata; exit |
| `--lang en` / `--lang id` | Project message language; default English |
| `--no-banner` | Suppress branding; leave command results visible |
| `doctor` | Offline environment readiness, ten checks |
| `doctor --help` | Doctor options |
| `doctor --json` | One JSON document on stdout, no banner, color or prose |
| `doctor --config-dir PATH` | Inspect selected directory instead of platform default |
| `python -m pasopati` | Same CLI using the interpreter where installed |
| `init --path pasopati.toml` | Create passive unauthorized TOML; never overwrite |
| `config validate --config pasopati.toml [--json]` | Strict offline schema validation |
| `scope check TARGET --config pasopati.toml [--json]` | Offline scope match; no DNS/connectivity |
| `profiles list [--json]` | List immutable passive/safe policies |
| `profiles show safe [--json]` | Show a policy; does not execute it |
| `scan URL --config FILE [--json]` | Collect explicit, authorized DNS/HTTP inventory |
| `scan --targets-file FILE --config FILE` | Validate/deduplicate a bounded URL batch |
| `scan ... --output NEW_DIRECTORY` | Explicit JSON/TXT files, never overwrite |
| `scan ... --include-titles` | Opt into bounded, heuristically redacted titles |
| `scan ... --web-details` | Opt into verified TLS/header/endpoint metadata, schema 4, same requests |
| `ports HOST --ports 22,80,443 --config FILE [--json]` | Authorized, explicit TCP connects; no payloads or service guesses |
| `ports --targets-file FILE --ports 80,443 --config FILE` | Bounded host/IP list, not URL/CIDR/range expansion |
| `ports ... --output NEW_DIRECTORY` | Common JSON/TXT model, TCP schema 3, never overwrite |
| `discover subdomains DOMAIN --source file --candidates-file FILE` | Import domain candidates offline |
| `discover subdomains DOMAIN --source wordlist --wordlist FILE` | Generate candidates from relative prefixes offline |
| `discover subdomains DOMAIN --source crtsh --allow-provider-queries` | Explicit third-party CT query; safe/authorized config required |
| `discover subdomains ... --resolve` | Opt into scoped A/AAAA and bounded wildcard checks |
| `discover subdomains ... --config FILE --output NEW_DIRECTORY --json` | Common JSON/TXT model, discovery schema 2; no overwrite |
| `python -m pasopati.lab --port 8765` | Explicit local-only HTTP fixture, not a CLI subcommand |

Global options go before `doctor`, e.g. `pasopati --lang id --no-banner doctor`.
This follows Typer's [command callback convention](https://typer.tiangolo.com/tutorial/commands/callback/).
Typer-generated help and usage validation errors remain English. `--version` is
an eager option and returns before command execution. Diagnostic messages are
localized; command names, JSON keys, check names and statuses stay English.

## Doctor contract

Required: Python >=3.12, installed package metadata, a usable configuration
directory path and filesystem write capability. Informational/optional: OS/platform,
Git (source workflow only), pipx, Nmap, Nuclei, Subfinder. Binaries are detected using
PATH only, never executed. Non-Linux/Windows systems receive a warning.
No network access, package installation, config persistence or target scanning.

Default configuration path is `%APPDATA%/pasopati` on Windows (fallback
`~/AppData/Roaming/pasopati`) and `$XDG_CONFIG_HOME/pasopati` on Unix (fallback
`~/.config/pasopati`; relative XDG paths are ignored). A missing config directory
passes readiness when an existing ancestor is a directory and the write probe
passes. No directory is created. A regular-file collision or permission failure
is a required failure. A temporary write probe is cleaned up before returning.

JSON fields: `schema_version` (`"1"`), `language` (`"en"` or `"id"`), `ok` (boolean),
`checks` (ordered array). Each check includes `name`, `status` (`pass|warn|fail`),
`required` (boolean), `details`, `recommendation` (empty if none).
Check names: `python`, `platform`, `package`, `git`, `pipx`, `nmap`, `nuclei`,
`subfinder`, `config_dir`, `filesystem`. JSON is an environment diagnostic, not a scan report.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Root/help/version success, or every required doctor check passes |
| 1 | Required doctor check fails, or requested version metadata is unavailable |
| 2 | Invalid language, command, option, argument or other usage error |

JSON is still emitted for doctor failures. Optional warnings do not cause failure.
Do not infer that a reachable config ancestor guarantees all future writes.

## Planned commands

Standalone `report`, `diff`, `demo` are not implemented or registered. M2A
[scan and JSON/TXT reports](recon.md) use one normalized model; HTML remains future work.
See [AGENTS.md](../../AGENTS.md). M1B [configuration/scope/profiles](configuration.md)
and [transport](transport.md) remain available. Policy commands use exit 0
for success/match, 1 for denial/I/O/operational failure, 2 for invalid arguments,
configuration or profile. Application JSON errors preserve one document with stable
reason codes; Typer parser errors remain text. Invalid targets/config errors are
never echoed verbatim. `init` also accepts `--json`.

Scan requires explicit authorization, safe profile and matching scope. Exit 0
means complete inventory, not secure targets. Exit 1 includes partial/denied/error/
skipped coverage and output failure. Exit 2 means invalid input/configuration;
application failures support JSON, Typer parser failures remain text. Reports
include coverage/provenance and `vulnerability_assessment = "not_performed"`.
M2D [web/TLS details](web-tls.md) is a separate opt-in, not crawling, cipher
enumeration or a finding engine. Without it the previous scan schema 1 is unchanged.

See [subdomain discovery](discovery.md) for source selection, budgets, privacy and
wildcard confidence. Local file/wordlist discovery defaults to offline/unverified;
DNS/provider operations require explicit authorization and matching scope. Discovery
uses exit 0 for completed collection (including valid negative DNS/empty CT results),
1 for partial/denied/skipped/error/output failure and 2 for invalid inputs. It never
automatically probes discovered websites or changes the allowlist.

See [TCP inventory](ports.md) for authorization, pinned DNS snapshots, logical
budgets and state semantics. Exit 0 means complete open/refused collection, not
all ports open or targets secure; unknown/partial/denied/skipped/DNS/output failure
exits 1 and invalid input/configuration exits 2. Service identification is not performed.
