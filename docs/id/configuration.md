# Konfigurasi M1B dan kebijakan offline

[English](../en/configuration.md)

Buat berkas dengan `pasopati init --path pasopati.toml`. Berkas dan symlink yang
sudah ada tidak ditimpa. Template awal pasif dan tidak mengotorisasi jaringan:

```toml
schema_version = 1
profile = "passive"
authorized = false

[scope]
allow_domains = ["example.invalid"]
allow_cidrs = []
exclude_domains = []
exclude_cidrs = []
ports = [80, 443]
allow_private = false
```

Keempat field root wajib. Field scope memiliki default allowlist kosong/menolak
akses, kecuali port 80/443. Field asing, tipe salah, dan boolean sebagai angka
ditolak. Ukuran berkas maksimum 64 KiB; tiap daftar aturan/port maksimum 1024.
CIDR tidak boleh berisi host bits. Tidak ada pencarian berkas implisit, substitusi
environment, kredensial, atau konfigurasi executable.

```text
pasopati config validate --config pasopati.toml --json
pasopati scope check https://example.invalid --config pasopati.toml --json
pasopati profiles list --json
pasopati profiles show safe --json
pasopati --lang id --no-banner scope check example.invalid --config pasopati.toml
```

Seluruh perintah ini tanpa DNS/HTTP. Kecocokan scope BUKAN izin menghubungi target;
`dns_checked` dan `connectivity_checked` selalu false. Otorisasi adalah pengakuan
pengguna, bukan bukti kepemilikan atau izin hukum. `doctor` tetap offline dan
mandiri dari konfigurasi proyek.

Domain exact hanya cocok dengan dirinya. `*.example.invalid` mencakup subdomain
pada batas label DNS, bukan apex atau `evil-example.invalid`. Exclusions selalu
menang. Normalisasi memakai IDNA 2003 bawaan Python, lowercase, dan satu trailing
dot opsional; bukan UTS #46. IPv4/IPv6 memakai `ipaddress`. Angka IP ambigu,
zone identifier, URL berkredensial, fragment, karakter kontrol, scheme selain
HTTP/HTTPS, serta port invalid ditolak.

Alamat nonpublik ditolak secara default. Loopback/RFC1918/ULA untuk lab memerlukan
semuanya: `authorized = true`, `allow_private = true`, cakupan CIDR eksplisit,
dan tidak dikecualikan. Alamat link-local/metadata, unspecified, multicast,
reserved, dokumentasi, shared address space dan transisi IPv6 tetap ditolak.

`passive` tanpa metode/jaringan dan budget 0. `safe` hanya GET/HEAD, 50 request/sesi,
1 request/detik bersama semua pemanggil, concurrency 2, 3 redirect, connect 3s,
read 5s, total operasi 10s, body 64 KiB. Profil immutable tidak memberikan
otorisasi atau memperluas scope. M2A [scan](recon.md) memerlukan otorisasi,
profil safe dan scope yang cocok; perintah kebijakan tetap offline.

Kode keluar: 0 berhasil/cocok; 1 penolakan scope atau kegagalan I/O/operasi;
2 argumen/konfigurasi/profil invalid. Kesalahan aplikasi JSON memiliki reason
stabil dan pesan lokal tanpa input invalid mentah. Kesalahan parser Typer tetap
teks Inggris. Opsi global sebelum subcommand. JSON tanpa banner atau ANSI.
