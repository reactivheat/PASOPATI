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

Belum ada perintah pemindaian. Pemindaian mendatang memerlukan
izin eksplisit dan pembatasan scope sebelum aktivitas jaringan.
M1B menambahkan argumen target untuk scope offline, tanpa resolve DNS atau koneksi.
Template pasif tanpa otorisasi; kecocokan scope bukan izin menghubungi target.
Lihat [konfigurasi](configuration.md) dan [transport internal](transport.md).
