# Instalasi

[English](../en/installation.md) · [README](../../README.id.md)

Memerlukan Python 3.12+. Sumber tersedia di https://github.com/reactivheat/PASOPATI;
nama paket belum diterbitkan/dipesan di PyPI. Pasang checkout sumber. Dependensi
runtime adalah Typer, Rich dan dnspython. Git/pipx alat alur kerja; Nmap/Nuclei/Subfinder
merupakan integrasi mendatang yang opsional.

## Kali Linux: instalasi pengguna terisolasi

CLI dan tes offline sudah divalidasi di Kali WSL2/Python 3.13.2 serta Windows
11/Python 3.12.10. Verifikasi VM Kali mandiri/desktop masih terbuka. Perintah apt
berikut belum dijalankan saat validasi; jalankan di VM jika prasyarat belum tersedia:

```bash
sudo apt update
sudo apt install -y git pipx python3 python3-venv
python3 --version  # Wajib 3.12 atau lebih baru; berhenti jika belum sesuai.
```

Gunakan checkout yang ada, atau clone dari direktori induk (bukan di dalam PASOPATI):

```bash
git clone https://github.com/reactivheat/PASOPATI.git
cd PASOPATI
```

Pasang dari root proyek:

```bash
pipx install .
pipx ensurepath
# Buka shell baru, atau hanya untuk shell saat ini:
export PATH="$HOME/.local/bin:$PATH"
command -v pasopati
pasopati --version
pasopati doctor
```

Jangan gunakan pip berprivilege atau menonaktifkan perlindungan Python sistem.
Jika Python terlalu lama, sediakan interpreter Python 3.12+ di VM dan gunakan
`pipx install --python /path/to/python .`.

## Environment editable untuk kontributor

Linux, dari root proyek:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -v --basetemp=.local/pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python -m build
```

PowerShell, dari root proyek:

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

Aktivasi opsional dengan `.\.venv\Scripts\Activate.ps1`. Jika ditolak, gunakan
jalur executable langsung tanpa mengubah execution policy sistem. Di Linux gunakan
`source .venv/bin/activate`. Unduhan dependensi dapat membutuhkan internet;
doctor dan tes tidak membutuhkannya.

## Checklist verifikasi Kali yang dapat diulang

Dengan CLI pipx terpasang, dari root sumber:

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

Periksa setiap kode keluar; peringatan alat opsional tetap menghasilkan 0.
Periksa banner pada terminal lebar dan sempit. Pastikan stdout `--json` valid tanpa
ANSI/banner. Ulangi doctor ketika jaringan dinonaktifkan. Jangan memasang alat
hanya untuk menghilangkan peringatan opsional. Catat versi OS/Python dan keluaran
nyata sebelum mengklaim verifikasi Kali. Environment pipx tidak mengekspos modul
ke interpreter sistem lain; `python -m pasopati` memakai interpreter tempat paket dipasang.

Pada mount Windows WSL, capture file-descriptor pytest dapat gagal sebelum
mengumpulkan tes (`FileNotFoundError` ketika truncate berkas capture sementara).
Solusi yang terverifikasi tetap menjalankan suite dan assertion yang sama dengan
capture stream Python:

```bash
.venv/bin/python -m pytest -v --capture=sys --basetemp=.local/pytest
```

Validasi Kali lokal memakai opsi ini dan meluluskan seluruh suite. Ini keterbatasan
runner/mount; verifikasi VM native sebaiknya juga mencoba perintah normal di atas.
Tidak perlu mengubah execution policy host, Python sistem, atau perlindungan
package manager.
