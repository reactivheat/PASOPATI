# Referensi perintah

[English](../en/commands.md) · [README](../../README.id.md)

`pasopati [OPSI GLOBAL] PERINTAH [OPSI]`

| Perintah/opsi | Perilaku |
| --- | --- |
| `pasopati` | Banner, versi terpasang, deskripsi, panduan singkat |
| `--help` | Perintah/opsi tersedia; tanpa banner dekoratif |
| `--version` | Versi distribusi dari importlib.metadata; kemudian keluar |
| `--lang en` / `--lang id` | Bahasa pesan proyek; default Inggris |
| `--no-banner` | Sembunyikan branding; hasil perintah tetap ditampilkan |
| `doctor` | Kesiapan lingkungan offline, sepuluh pemeriksaan |
| `doctor --help` | Opsi doctor |
| `doctor --json` | Satu dokumen JSON di stdout, tanpa banner, warna, atau prosa |
| `doctor --config-dir PATH` | Periksa direktori pilihan menggantikan default platform |
| `python -m pasopati` | CLI yang sama memakai interpreter tempat paket dipasang |
| `init --path pasopati.toml` | Buat TOML pasif tanpa otorisasi; tidak menimpa |
| `config validate --config pasopati.toml [--json]` | Validasi schema strict offline |
| `scope check TARGET --config pasopati.toml [--json]` | Kecocokan scope offline, tanpa DNS/koneksi |
| `profiles list [--json]` | Daftar kebijakan passive/safe immutable |
| `profiles show safe [--json]` | Tampilkan kebijakan tanpa menjalankannya |

Opsi global sebelum `doctor`, misalnya `pasopati --lang id --no-banner doctor`.
Penempatan ini mengikuti [konvensi callback Typer](https://typer.tiangolo.com/tutorial/commands/callback/).
Bantuan dan kesalahan validasi dari Typer masih Inggris. `--version` bersifat
eager: selesai sebelum perintah dijalankan. Pesan diagnostik terlokalisasi;
nama perintah, key JSON, nama pemeriksaan, dan status tetap Inggris.

## Kontrak doctor

Wajib: Python >=3.12, metadata paket terpasang, jalur direktori konfigurasi layak,
dan kemampuan menulis berkas. Informasi/opsional: OS/platform, Git (untuk alur
sumber), pipx, Nmap, Nuclei, Subfinder. Binary hanya dideteksi lewat PATH, tidak
dijalankan. Sistem selain Linux/Windows mendapat peringatan. Tidak mengakses
jaringan, memasang paket, menyimpan konfigurasi, atau memindai target.

Default konfigurasi: `%APPDATA%/pasopati` di Windows (fallback
`~/AppData/Roaming/pasopati`), `$XDG_CONFIG_HOME/pasopati` di Unix (fallback
`~/.config/pasopati`; XDG relatif diabaikan). Direktori yang belum tersedia lulus
kesiapan jika induk tersedia berupa direktori dan uji tulis lulus. Tidak membuat
direktori. Benturan berkas biasa atau kegagalan izin menghasilkan kegagalan wajib.
Berkas uji sementara dibersihkan sebelum selesai.

Field JSON: `schema_version` (`"1"`), `language` (`"en"` atau `"id"`), `ok` (boolean),
`checks` (array berurutan). Setiap pemeriksaan memiliki `name`, `status`
(`pass|warn|fail`), `required` (boolean), `details`, `recommendation` (kosong jika
tidak diperlukan). Nama pemeriksaan: `python`, `platform`, `package`, `git`,
`pipx`, `nmap`, `nuclei`, `subfinder`, `config_dir`, `filesystem`.
JSON ini diagnostik lingkungan, bukan laporan pemindaian.

## Kode keluar

| Kode | Makna |
| --- | --- |
| 0 | Root/help/version berhasil atau semua pemeriksaan wajib doctor lulus |
| 1 | Pemeriksaan wajib gagal atau metadata versi yang diminta tidak tersedia |
| 2 | Bahasa, perintah, opsi, argumen, atau penggunaan CLI tidak valid |

JSON tetap dikeluarkan saat doctor gagal. Peringatan opsional tidak menyebabkan
kegagalan. Induk konfigurasi yang layak bukan jaminan semua penulisan mendatang.

## Perintah direncanakan

`scan`, `report`, `diff`, `demo` belum diimplementasikan atau didaftarkan.
Laporan mendatang memakai model normalisasi bersama untuk TXT/JSON/HTML; lihat
[AGENTS.md](../../AGENTS.md). M1B menyediakan [konfigurasi/scope/profil](configuration.md)
dan [transport internal](transport.md). Kode keluar kebijakan: 0 berhasil/cocok,
1 penolakan/I/O/kegagalan operasi, 2 argumen/konfigurasi/profil invalid. Kesalahan
aplikasi JSON tetap satu dokumen dengan reason stabil; kesalahan parser Typer tetap
teks. Input target/konfigurasi invalid tidak dicetak mentah. `init` juga menerima `--json`.
