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

There are no target arguments or scanning commands in M1A. Future scanning must
be explicitly authorized and bounded by scope before any network activity.
