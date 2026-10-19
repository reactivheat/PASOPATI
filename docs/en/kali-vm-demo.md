# Manual Kali VirtualBox demonstration

[Bahasa Indonesia](../id/kali-vm-demo.md)

Native VM demonstration is **pending**, not equivalent to the verified Kali WSL
tests. No SSH/password sharing is required for this manual workflow. Execute
these steps yourself in a terminal inside the VM. Do not enter passwords in chat.
Leave VM network/security settings unchanged. All demo targets are loopback.

## 1. Prepare an isolated installation

Check `python3 --version`: Python 3.12+ and venv support are required. If you have
not cloned PASOPATI, run from the intended **parent** directory:

```bash
git clone https://github.com/reactivheat/PASOPATI.git
cd PASOPATI
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m pasopati --version
.venv/bin/python -m pasopati scan --help
```

If the repository already exists, use it; do not create a nested PASOPATI folder
or discard changes. If venv/pip is unavailable, report the error rather than
installing globally or changing OS package protections. Dependency installation
may access package indexes; the recon demo itself needs no internet target.

## 2. Start the real local fixture (terminal A)

From the repository root:

```bash
.venv/bin/python -m pasopati.lab --port 8765
```

Leave this running. It listens only on 127.0.0.1. If the port is occupied, stop
and select a different unprivileged port consistently in the command and a private
copy of the lab config; do not terminate unrelated processes.

## 3. Collect evidence (terminal B)

Open another terminal in the same repository root:

```bash
.venv/bin/python -m pasopati --lang id scan http://127.0.0.1:8765/ --config examples/lab.toml --output reports/vm-demo-001 --include-titles
echo "exit=$?"
```

Expected fixture: one completed seed, one request attempt, HTTP 200 and the opt-in
title `PASOPATI local lab`; JSON/TXT files in `reports/vm-demo-001`. Exit 0 confirms
collection, not security. If output exists, use a new directory; do not overwrite.
For the full three-seed/four-request fixture use `--targets-file examples/lab-targets.txt`
instead of the single URL. Also demonstrate `/outside` and `/large` producing
explicit partial results/exit 1 as explained in [recon](recon.md).

## 4. Capture genuine documentation

Maximize the guest terminal so the command and result are legible. Capture actual
help/version and successful/partial lab results; never manufacture terminal output.
Record the source commit (`git rev-parse --short HEAD`), Python/tool/OS version,
terminal size, exact command, exit code and whether recording is real-time or sped up.
Review frames for personal paths, usernames, notifications and secrets before
publication. Do not disable OS privacy/security settings or verification for recording.

Send the result/screenshot for inspection before claiming native VM validation.
Do not publish desktop-only screenshots as proof PASOPATI ran. Existing Windows,
WSL and hosted CI results do not establish that this VM passed. Stop the fixture
in terminal A with Ctrl+C when finished; keep only synthetic demo reports for review.
