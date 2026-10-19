# Installation

[Bahasa Indonesia](../id/installation.md) · [README](../../README.md)

Requires Python 3.12+. Package availability on PyPI and the proposed GitHub remote
have not been verified. These instructions install the local source checkout.
Runtime dependencies are Typer and Rich; Git/pipx are workflow tools, while
Nmap/Nuclei/Subfinder are optional future integrations.

## Kali Linux: isolated user installation

The CLI and offline tests were validated on Kali WSL2 with Python 3.13.2, in addition
to Windows 11/Python 3.12.10. Standalone Kali VM/desktop verification remains open.
The apt commands below were not executed during validation; run them in your VM
if the prerequisites are missing:

```bash
sudo apt update
sudo apt install -y git pipx python3 python3-venv
python3 --version  # Must be 3.12 or newer; stop here otherwise.
```

Copy the project into the VM and enter its root (containing pyproject.toml).
Only after the owner publishes the proposed remote, this acquisition workflow applies:

```bash
git clone https://github.com/reactivheat/pasopati-recon.git
cd pasopati-recon
```

Install from the project root:

```bash
pipx install .
pipx ensurepath
# Open a new shell, or for this shell only:
export PATH="$HOME/.local/bin:$PATH"
command -v pasopati
pasopati --version
pasopati doctor
```

Do not use privileged pip or override system-managed Python protections.
If Python is too old, provision a Python 3.12+ interpreter in the VM and pass its
path with `pipx install --python /path/to/python .`.

## Editable contributor environment

Linux, from the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -v --basetemp=.local/pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python -m build
```

PowerShell, from the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\pasopati.exe --version
.\.venv\Scripts\pasopati.exe doctor
.\.venv\Scripts\python.exe -m pytest -v --basetemp=.local/pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m build
```

Activation is optional. If desired, use `.\.venv\Scripts\Activate.ps1`; if blocked,
use the explicit executable paths above without changing system execution policy.
On Linux use `source .venv/bin/activate`. Dependency installation may need internet;
the tests and doctor do not.

## Repeatable Kali verification checklist

With the pipx CLI installed, from the source root:

```bash
pasopati
pasopati --help
pasopati --version
pasopati doctor
pasopati doctor --json | python3 -m json.tool
pasopati --lang id doctor
pasopati --no-banner doctor
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pasopati --help
.venv/bin/python -m pytest -v --basetemp=.local/pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python -m build
(cd /tmp && pasopati --version && pasopati doctor --json | python3 -m json.tool)
```

Check each exit code; optional-tool warnings must still return 0. Confirm the banner
in both wide and narrow terminal windows. Confirm stdout from `--json` parses and
has no ANSI/banner. Repeat doctor with networking disabled; do not install tools
just to silence optional warnings. Record real OS/Python versions and outputs
before claiming Kali validation. A pipx environment does not expose the Python
module to unrelated system interpreters; `python -m pasopati` uses the interpreter
where the package is installed.

On a WSL Windows mount, pytest's file-descriptor capture can fail before collecting
tests (`FileNotFoundError` in capture's temporary-file truncate). The validated
workaround keeps the same test suite and assertions, capturing Python streams:

```bash
.venv/bin/python -m pytest -v --capture=sys --basetemp=.local/pytest
```

The local Kali validation used this option and passed all 35 tests. This is a
test-runner/mount limitation; native VM verification should also try the normal
command above. No host execution policy, system Python, or package-manager
protection needs to be changed.
