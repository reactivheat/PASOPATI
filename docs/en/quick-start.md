# Quick start

[Bahasa Indonesia](../id/quick-start.md) · [Installation](installation.md)

After installing into pipx or activating the contributor environment:

```text
pasopati
pasopati --help
pasopati --version
pasopati doctor
pasopati --lang id doctor
pasopati --no-banner doctor
pasopati doctor --json
python -m pasopati --help
pasopati init --path pasopati.toml
pasopati config validate --config pasopati.toml --json
pasopati scope check https://example.invalid --config pasopati.toml --json
pasopati profiles list --json
pasopati profiles show safe --json
```

The final command needs the interpreter where PASOPATI was installed. Root output
shows the banner, actual installed version, description and a short guide. Narrow
terminals use compact branding. Missing Nmap/Nuclei/Subfinder is expected and does
not fail the foundation. Doctor does not download or execute any external tool.

To inspect a different configuration location:

```text
pasopati doctor --config-dir ./local-config
```

Doctor does not create this directory. It checks the nearest existing ancestor
and briefly creates/writes/removes a temporary probe there. Use a user-owned path.
Required failures return 1 and include recommendations. For automation, parse JSON
and inspect `ok` plus `checks`; local paths may be sensitive, so review before sharing.
See [commands](commands.md) for the output contract and exit-code semantics.

The template is passive and unauthorized. `scope check` never resolves DNS or
connects; a match is not permission to connect. M2A `scan` requires target
authorization, safe profile and allowlisting. For a real, reproducible first run,
follow the [local lab guide](recon.md): start `python -m pasopati.lab` in a separate
terminal, then use the checked-in loopback-only examples from the checkout.
Reports are JSON/TXT inventories, not vulnerability verdicts. Non-root paths and
queries are withheld; titles require explicit opt-in. See [configuration](configuration.md)
and [transport](transport.md).

For the next capability, [subdomain discovery](discovery.md) starts offline with
synthetic file/wordlist examples. Select sources explicitly; DNS and third-party
queries are separate opt-ins, never automatic HTTP probing of discovered names.

M2C [TCP inventory](ports.md) uses explicit hosts and ports, the same authorization/
scope/limits, and numeric connects with no application payload or service guesses.
The existing loopback lab supports a first `ports` run too.
