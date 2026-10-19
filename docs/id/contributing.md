# Berkontribusi

[English](../../CONTRIBUTING.md)

PASOPATI adalah proyek sumber publik yang belum dirilis untuk recon berizin.
Pemilik belum memilih lisensi; repositori publik bukan pemberian lisensi.
Jangan menganggap hak redistribusi sudah diberikan. Tidak ada bounty atau SLA dukungan.

Baca [AGENTS.md](../../AGENTS.md) dan [kontrak recon](recon.md). Perubahan harus kecil,
bertipe, bilingual dan dapat diuji. Jangan menambah client jaringan tersembunyi,
perluasan scope otomatis, TLS insecure, payload exploit atau klaim kerentanan tanpa
bukti. Semua kolektor memakai scope/transport/budget bersama. Tes tetap offline,
kecuali fixture loopback numerik yang dijaga secara eksplisit.

Gunakan virtual environment proyek; jangan mengubah Python/Git global. Jalankan
pytest, Ruff lint/format, mypy, build dan pip check sesuai [README](../../README.id.md).
Uji wheel dari luar checkout, bukan hanya impor sumber editable. Laporkan platform,
gagal/skip dan keterbatasan secara akurat; jangan mengarang benchmark, akurasi atau
hasil CI. Jika fixture TLS tidak dapat dibuat tanpa OpenSSL, skip secara eksplisit;
jangan mematikan verifikasi.

Jangan commit daftar target nyata, laporan, kredensial, kunci TLS atau diagnostik
lokal. Gunakan contoh loopback sintetis untuk tes/dokumentasi. Hormati perubahan
yang ada dan minta persetujuan pemilik untuk rilis/publikasi/perubahan lisensi.
Untuk kerentanan, ikuti [SECURITY.md](../../SECURITY.md); jangan membuka detail sensitif
di issue atau pull request publik.
