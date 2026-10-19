# PASOPATI

[English](README.md)

Reconnaissance & Exposure Analysis Framework. **M1A: fondasi CLI, versi 0.1.0.**
Perintah kebijakan M1B tersedia; transport internal sedang divalidasi.
Lihat [konfigurasi dan scope](docs/id/configuration.md). Pemindaian target dan
deteksi kerentanan belum tersedia. Desain mengutamakan instalasi terisolasi,
modul kecil, keluaran konsisten, dependensi minimal, dan temuan berdasarkan bukti.

## Fitur tersedia

- Paket Python 3.12+, executable `pasopati`, dan `python -m pasopati`.
- Banner ASCII bermotif panah, tampilan ringkas untuk terminal sempit, dan Rich.
- Pesan Bahasa Inggris/Indonesia melalui `--lang en|id`.
- `doctor` offline, JSON terstruktur, dan kode keluar yang jelas.
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

Repositori yang direncanakan: `https://github.com/reactivheat/pasopati-recon`;
ketersediaannya belum diverifikasi. Nama distribusi `pasopati-recon` belum
dipesan atau diterbitkan. Gunakan checkout lokal sampai publikasi tersedia.
Lihat [panduan instalasi](docs/id/installation.md) untuk prasyarat Kali, alur clone
bersyarat, pengaturan Windows, dan checklist verifikasi Kali.
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
```

Opsi global ditempatkan sebelum perintah. Doctor juga menerima `--config-dir PATH`.
Kode keluar: `0` berhasil/pemeriksaan wajib lulus, `1` pemeriksaan wajib atau
instalasi gagal, `2` penggunaan CLI tidak valid. Alat opsional yang tidak tersedia
tidak membuat instalasi gagal. JSON memakai identifier Inggris yang stabil dan
pesan terlokalisasi; tidak ada banner atau ANSI.
Baca [panduan singkat](docs/id/quick-start.md) dan [referensi lengkap](docs/id/commands.md).

## Arsitektur

```text
src/pasopati/
  __init__.py       versi dari importlib.metadata
  __main__.py       entry point modul
  cli.py            perintah Typer dan presentasi
  branding.py       banner ASCII responsif
  i18n.py           katalog pesan EN/ID
  doctor.py         pemeriksaan offline dan hasil terstruktur
  core/errors.py    kesalahan instalasi dan kode keluar
```

[AGENTS.md](AGENTS.md) mencatat batas scope/transport dan kontrak laporan
TXT/JSON/HTML mendatang. Komponen tersebut belum diimplementasikan.

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
interpreter Windows di atas dengan `.venv/bin/python`. Tes tidak membutuhkan
internet atau binary pemindai. Unduhan dependensi instalasi/build dapat memerlukan
internet. CI sudah dikonfigurasi; hasil CI hosted hanya boleh diklaim setelah dijalankan.

## Fitur direncanakan

M1B: konfigurasi scope, profil pemindaian, dan transport yang mematuhi scope.
Tahap berikutnya: discovery pasif; DNS/subdomain; HTTP, TLS, security header;
inventaris layanan, web/API; deteksi paparan/salah konfigurasi; intelijen CVE;
temuan berbukti; analisis perbedaan; relasi aset; plugin; lab keamanan lokal yang
reproducible; laporan TXT/JSON/HTML.
`init`, `scan`, `report`, `diff`, dan `demo` masih rencana, belum terdaftar di CLI.

## Screenshot dan demo

Belum ada screenshot atau video. Rekam keluaran nyata mengikuti
[panduan screenshot](docs/assets/screenshots/README.md) dan
[panduan demo](docs/assets/demos/README.md). Tidak ada hasil pemindaian rekaan.

## Keterbatasan saat ini

- Divalidasi di Windows 11/Python 3.12.10 dan Kali WSL2/Python 3.13.2. VM Kali
  mandiri/terminal desktop native dan CI hosted belum diverifikasi.
- Di mount Windows WSL, capture file-descriptor pytest gagal sebelum koleksi;
  `--capture=sys` berhasil menjalankan seluruh tes. Lihat checklist instalasi.
- Bantuan dan kesalahan penggunaan dari Typer masih Inggris; pesan proyek mendukung EN/ID.
- Doctor hanya mendeteksi alat opsional di PATH, tidak menjalankan atau memeriksa versinya.
- Doctor menulis/menghapus berkas uji sementara di direktori konfigurasi atau induk
  terdekat yang tersedia. Tidak membuat konfigurasi permanen. Hasil bukan jaminan
  izin atau ruang penyimpanan tidak akan berubah.
- Pemindaian, engine pembatasan scope, penyimpanan, dan ekspor laporan belum tersedia.
- Pemilik belum memilih lisensi. Belum ada pemberian lisensi.

## Kontribusi, keamanan, dan scope

Baca [AGENTS.md](AGENTS.md), gunakan environment terisolasi, tambahkan tes offline
yang bermakna, jalankan pemeriksaan, dan perbarui kedua bahasa. Tinjau perubahan
sebelum commit/publikasi. Jangan sertakan kredensial, diagnostik lokal, atau data
pemindaian sensitif. Operasi jaringan mendatang wajib memiliki izin target dan
allowlist, validasi DNS/redirect, batas laju/concurrency/timeout/anggaran request,
serta asal-usul bukti. Tidak boleh ada eksploitasi otomatis atau penyimpanan
otomatis body sensitif. M1A tidak melakukan reconnaissance jaringan.
Keputusan lisensi perlu diselesaikan sebelum distribusi.
