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
| `scan URL --config FILE [--json]` | Koleksi inventaris DNS/HTTP eksplisit berizin |
| `scan --targets-file FILE --config FILE` | Validasi/deduplikasi batch URL berbatas |
| `scan ... --output DIREKTORI_BARU` | Simpan JSON/TXT secara eksplisit, tidak menimpa |
| `scan ... --include-titles` | Opt-in judul berbatas dengan penyamaran heuristik |
| `discover subdomains DOMAIN --source file --candidates-file FILE` | Impor kandidat domain offline |
| `discover subdomains DOMAIN --source wordlist --wordlist FILE` | Buat kandidat dari prefix relatif secara offline |
| `discover subdomains DOMAIN --source crtsh --allow-provider-queries` | Query CT pihak ketiga eksplisit; wajib config safe/berizin |
| `discover subdomains ... --resolve` | Opt-in A/AAAA berscope dan pemeriksaan wildcard berbatas |
| `discover subdomains ... --config FILE --output DIREKTORI_BARU --json` | Model JSON/TXT bersama, schema discovery 2; tanpa overwrite |
| `python -m pasopati.lab --port 8765` | Fixture HTTP lokal eksplisit, bukan subcommand CLI |

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

Perintah mandiri `report`, `diff`, `demo` belum diimplementasikan/didaftarkan.
M2A [scan dan laporan JSON/TXT](recon.md) memakai satu model bersama; HTML masih rencana.
Lihat [AGENTS.md](../../AGENTS.md). M1B menyediakan [konfigurasi/scope/profil](configuration.md)
dan [transport](transport.md). Kode keluar kebijakan: 0 berhasil/cocok,
1 penolakan/I/O/kegagalan operasi, 2 argumen/konfigurasi/profil invalid. Kesalahan
aplikasi JSON tetap satu dokumen dengan reason stabil; kesalahan parser Typer tetap
teks. Input target/konfigurasi invalid tidak dicetak mentah. `init` juga menerima `--json`.

Scan memerlukan izin eksplisit, profil safe dan scope yang cocok. Exit 0 berarti
inventaris lengkap, bukan target aman. Exit 1 mencakup partial/denied/error/skipped
dan gagal output. Exit 2 berarti input/konfigurasi invalid; kesalahan aplikasi
mendukung JSON, kesalahan parser Typer tetap teks. Laporan mencatat cakupan/bukti
dan `vulnerability_assessment = "not_performed"`.

Lihat [discovery subdomain](discovery.md) untuk sumber, budget, privasi dan confidence
wildcard. File/wordlist default offline/belum terverifikasi; DNS/provider memerlukan
otorisasi eksplisit dan scope cocok. Discovery memakai exit 0 untuk koleksi selesai
(termasuk jawaban DNS negatif/CT kosong valid), 1 untuk partial/denied/skipped/error/
output gagal dan 2 untuk input invalid. Tidak otomatis mengunjungi situs hasil
discovery atau mengubah allowlist.
