# PASOPATI

[English](README.md)

Reconnaissance & Exposure Analysis Framework. **Inventaris URL M2A, versi 0.1.0 (belum dirilis).**
Koleksi DNS/HTTP berizin dari seed eksplisit, asal-usul bukti dan laporan JSON/TXT.
Lihat [recon dan lab lokal](docs/id/recon.md) serta [scope](docs/id/configuration.md).
Ini bukan pemindai kerentanan. Desain mengutamakan instalasi terisolasi,
modul kecil, keluaran konsisten, dependensi minimal, dan temuan berdasarkan bukti.

## Fitur tersedia

- Paket Python 3.12+, executable `pasopati`, dan `python -m pasopati`.
- Banner ASCII bermotif panah, tampilan ringkas untuk terminal sempit, dan Rich.
- Pesan Bahasa Inggris/Indonesia melalui `--lang en|id`.
- `doctor` offline, JSON terstruktur, dan kode keluar yang jelas.
- TOML strict, `init` tanpa overwrite, dan pemeriksaan scope offline.
- Profil passive/safe immutable dan API internal HTTP/HTTPS dengan IP pinning,
  validasi DNS/redirect, verifikasi TLS, budget bersama, serta batas respons.
- `scan` untuk batch URL eksplisit, bukti DNS/HTTP dan outcome parsial/error yang jelas.
- JSON/TXT dari model bersama, penyamaran konservatif dan judul halaman opt-in.
- Lab lokal reproducible: `python -m pasopati.lab`; tanpa target eksternal.
- pytest, Ruff, mypy, serta konfigurasi CI Linux/Windows untuk Python 3.12–3.14.

## Instalasi

Dari checkout lokal di Kali dengan Python 3.12+ dan pipx tersedia:

```bash
python3 --version
pipx install .
pipx ensurepath
# Buka terminal baru jika PATH berubah.
pasopati --version
pasopati doctor
```

Sumber: [reactivheat/PASOPATI](https://github.com/reactivheat/PASOPATI).
Nama distribusi `pasopati-recon` belum dipesan atau diterbitkan di PyPI.
Lihat [panduan instalasi](docs/id/installation.md) untuk prasyarat Kali, alur clone,
pengaturan Windows, dan checklist verifikasi Kali.
Jangan memasang proyek ke lingkungan Python yang dikelola sistem operasi.

## Penggunaan dan referensi CLI

```text
pasopati
pasopati --help
pasopati --version
pasopati doctor
pasopati doctor --json
pasopati --lang id doctor
pasopati --no-banner doctor
python -m pasopati --help
pasopati init --path pasopati.toml
pasopati config validate --config pasopati.toml --json
pasopati scope check https://example.invalid --config pasopati.toml --json
pasopati profiles list --json
pasopati profiles show safe --json
pasopati scan --help
```

Opsi global ditempatkan sebelum perintah. Doctor juga menerima `--config-dir PATH`.
Kode keluar: `0` berhasil/pemeriksaan wajib lulus, `1` pemeriksaan wajib atau
instalasi gagal, `2` penggunaan CLI tidak valid. Alat opsional yang tidak tersedia
tidak membuat instalasi gagal. JSON memakai identifier Inggris yang stabil dan
pesan terlokalisasi; tidak ada banner atau ANSI.
Perintah kebijakan memakai 0 untuk berhasil/cocok, 1 untuk penolakan atau kegagalan
I/O/operasi, 2 untuk argumen/konfigurasi/profil invalid. Scope check tanpa DNS/koneksi.
Baca [panduan singkat](docs/id/quick-start.md) dan [referensi lengkap](docs/id/commands.md).
Untuk koleksi nyata, ikuti [panduan scan dan lab lokal](docs/id/recon.md).
`init` tetap passive/tanpa otorisasi. Scan memerlukan izin target, profil safe
dan allowlist; exit 1 mencakup hasil parsial/ditolak/dilewati.

## Arsitektur

```text
src/pasopati/
  __init__.py       versi dari importlib.metadata
  __main__.py       entry point modul
  cli.py            perintah Typer dan presentasi
  branding.py       banner ASCII responsif
  i18n.py           katalog pesan EN/ID
  doctor.py         pemeriksaan offline dan hasil terstruktur
  config.py         TOML strict dan pembuatan template eksklusif
  targets.py        normalisasi target/domain bersama
  scope.py          kebijakan offline dan alamat hasil DNS
  profiles.py       batas profil bawaan immutable
  policy_cli.py     CLI konfigurasi/scope/profil offline
  transport.py      HTTP/HTTPS pinned, lifetime DNS, batas sumber daya
  scan_cli.py       perintah scan aktif eksplisit dan preflight
  recon.py          inventaris ternormalisasi, bukti dan outcome
  redaction.py      batas pelaporan URL/header/judul konservatif
  reports.py        renderer JSON/TXT bersama dan output eksklusif
  lab.py            fixture HTTP lokal reproducible yang dijalankan eksplisit
  core/errors.py    kesalahan instalasi dan kode keluar
```

Lihat [konfigurasi](docs/id/configuration.md), [transport](docs/id/transport.md),
dan [AGENTS.md](AGENTS.md). M2A memakai satu model inventaris JSON/TXT ternormalisasi.
Ekspor HTML, analisis kerentanan dan perbandingan historis masih tahap mendatang.

## Pengembangan dan pengujian

PowerShell dari workspace ini; aktivasi environment tidak wajib:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -v --basetemp=.local/pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m build
```

Di Linux/macOS, buat environment dengan `python3 -m venv .venv`, lalu ganti
interpreter Windows di atas dengan `.venv/bin/python`. Tes tanpa jaringan eksternal
atau binary pemindai. Integrasi memakai socket loopback terbatas; tes TLS nyata
membuat sertifikat sementara melalui OpenSSL (skip eksplisit jika tidak tersedia).
Unduhan dependensi instalasi/build dapat memerlukan internet. Hasil hosted aktual
tersedia di [GitHub Actions](https://github.com/reactivheat/PASOPATI/actions).

## Fitur direncanakan

Lihat [roadmap kemampuan dan kriteria pembanding](docs/id/roadmap.md).
Untuk dokumentasi Kali VirtualBox native, ikuti [panduan demo manual](docs/id/kali-vm-demo.md).

Setelah M2A: discovery lebih luas melalui transport bersama dan kontrak bukti.
Tahap berikutnya: discovery pasif; subdomain; inventaris sertifikat TLS;
inventaris layanan, web/API; deteksi paparan/salah konfigurasi; intelijen CVE;
temuan berbukti; analisis perbedaan; relasi aset; plugin; lab keamanan lokal yang
reproducible tambahan; laporan HTML.
Perintah mandiri `report`, `diff`, dan `demo` masih rencana, belum terdaftar di CLI.

## Screenshot dan demo

Belum ada screenshot atau video. Rekam keluaran nyata mengikuti
[panduan screenshot](docs/assets/screenshots/README.md) dan
[panduan demo](docs/assets/demos/README.md). Tidak ada hasil pemindaian rekaan.

## Keterbatasan saat ini

- Divalidasi di Windows 11/Python 3.12.10 dan Kali WSL2/Python 3.13.2. VM Kali
  mandiri/terminal desktop native belum diverifikasi; hasil hosted ditautkan di atas.
- Di mount Windows WSL, capture file-descriptor pytest gagal sebelum koleksi;
  `--capture=sys` berhasil menjalankan seluruh tes. Lihat checklist instalasi.
- Bantuan dan kesalahan penggunaan dari Typer masih Inggris; pesan proyek mendukung EN/ID.
- Doctor hanya mendeteksi alat opsional di PATH, tidak menjalankan atau memeriksa versinya.
- Doctor menulis/menghapus berkas uji sementara di direktori konfigurasi atau induk
  terdekat yang tersedia. Tidak membuat konfigurasi permanen. Hasil bukan jaminan
  izin atau ruang penyimpanan tidak akan berubah.
- Inventaris hanya URL eksplisit: tanpa crawling, discovery subdomain, pemeriksaan
  CVE atau vonis kerentanan. Penyimpanan JSON/TXT memerlukan `--output` eksplisit.
- Path non-root/query disamarkan; judul nonaktif secara default. Penyamaran heuristik
  tidak menjamin judul opt-in bebas dari informasi sensitif yang belum dikenal.
- Scheduler awal sekuensial dan hanya mencoba IP tervalidasi pertama.
- Policy IPv6 diuji; transport IPv6 nyata belum diklaim. DNS memakai server numerik
  OS, bukan hosts file/mDNS/DoH; tanpa fallback resolver publik.
- Pemilik belum memilih lisensi. Belum ada pemberian lisensi.

## Kontribusi, keamanan, dan scope

Baca [AGENTS.md](AGENTS.md), [panduan kontribusi](docs/id/contributing.md), dan
[pelaporan keamanan](SECURITY.md). Gunakan environment terisolasi, tambahkan tes
offline bermakna, jalankan pemeriksaan, dan perbarui kedua bahasa. Tinjau perubahan
sebelum commit/publikasi. Jangan sertakan kredensial, diagnostik lokal, atau data
pemindaian sensitif. Operasi jaringan wajib memiliki izin target dan
allowlist, validasi DNS/redirect, batas laju/concurrency/timeout/anggaran request,
serta asal-usul bukti. Tidak boleh ada eksploitasi otomatis atau penyimpanan
otomatis body sensitif. Hanya `scan` mengakses target; perintah kebijakan tetap offline.
Tidak ada pemindaian target eksternal untuk validasi pengembangan.
Keputusan lisensi perlu diselesaikan sebelum distribusi.
