# Panduan singkat

[English](../en/quick-start.md) · [Instalasi](installation.md)

Setelah instalasi pipx atau aktivasi environment kontributor:

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

Perintah terakhir memerlukan interpreter tempat PASOPATI dipasang. Keluaran root
berisi banner, versi terpasang, deskripsi, dan panduan singkat. Terminal sempit
menggunakan branding ringkas. Nmap/Nuclei/Subfinder yang tidak tersedia tidak
membuat fondasi gagal. Doctor tidak mengunduh atau menjalankan alat eksternal.

Untuk memeriksa lokasi konfigurasi lain:

```text
pasopati doctor --config-dir ./local-config
```

Doctor tidak membuat direktori ini. Doctor memeriksa induk terdekat yang tersedia
dan sementara membuat/menulis/menghapus berkas uji di sana. Gunakan jalur milik
pengguna. Kegagalan wajib menghasilkan kode 1 dan rekomendasi. Untuk otomasi,
parse JSON dan periksa `ok` serta `checks`; jalur lokal dapat sensitif, tinjau
sebelum dibagikan. Lihat [referensi](commands.md) untuk kontrak keluaran dan kode keluar.

Template pasif tanpa otorisasi. `scope check` tanpa DNS/koneksi; kecocokan bukan
izin menghubungi target. M2A `scan` memerlukan otorisasi target, profil safe dan
allowlist. Untuk run pertama yang nyata/reproducible, ikuti [panduan lab lokal](recon.md):
jalankan `python -m pasopati.lab` di terminal lain, lalu pakai contoh loopback-only
dari checkout. Laporan JSON/TXT adalah inventaris, bukan vonis kerentanan.
Path non-root/query disamarkan; judul memerlukan opt-in. Lihat
[konfigurasi](configuration.md) dan [transport](transport.md).

Kemampuan berikutnya, [discovery subdomain](discovery.md), dimulai offline dengan
contoh file/wordlist sintetis. Pilih sumber eksplisit; DNS dan query pihak ketiga
merupakan opt-in terpisah, bukan HTTP otomatis ke nama hasil discovery.

M2C [inventaris TCP](ports.md) memakai host/port eksplisit, otorisasi/scope/batas
bersama dan koneksi numerik tanpa payload aplikasi atau tebakan layanan.
Lab loopback yang sudah ada juga mendukung run `ports` pertama.

M2D [`scan --web-details`](web-tls.md) menambah metadata web/TLS berbukti tanpa
request tambahan atau crawling. Judul tetap opt-in terpisah; fixture HTTP tanpa bukti
TLS, sedangkan HTTPS wajib lolos verifikasi trust/hostname lokal.
