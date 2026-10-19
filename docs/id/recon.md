# M2A: inventaris DNS/HTTP dari URL eksplisit

[English](../en/recon.md)

`scan` mengumpulkan respons nyata dari URL HTTP/HTTPS eksplisit yang berizin.
Ini inventaris, bukan pemindai kerentanan, crawler, enumerator subdomain atau
pencocok CVE. `doctor`, `init`, `config`, `scope`, dan `profiles` tetap offline.

## Otorisasi dan input

Periksa hanya sistem yang Anda punya izin untuk uji. Izin pemilik proyek untuk
mengembangkan/push kode tidak mengizinkan pemindaian target pihak ketiga.
Dalam konfigurasi proyek:

- Set `authorized = true` hanya setelah memperoleh izin untuk target sebenarnya.
- Pilih `profile = "safe"`; passive tidak mengirim request.
- Allowlist domain/CIDR dan port secara eksplisit; exclusions lebih diutamakan.
- Lab privat juga memerlukan `allow_private = true` dan CIDR eksplisit.
- `scope check` yang cocok bukan bukti DNS, konektivitas, ataupun otorisasi.

Gunakan satu URL, daftar UTF-8, atau gabungkan keduanya:

```text
pasopati scan https://your-authorized-host.example/ --config pasopati.toml --json
pasopati --lang id scan --targets-file targets.txt --config pasopati.toml --output reports/run-001
```

Ini contoh sintaks, bukan bukti target tersebut ada atau sudah dipindai. Tiap
entri wajib `http://` atau `https://`. Tidak ada tebakan scheme, perluasan domain,
pengikutan tautan hasil discovery atau enumerasi port. Seluruh batch divalidasi
sebelum trafik: maksimal 256 entri sebelum deduplikasi, 4.096 karakter per URL,
dan 1 MiB input UTF-8. Baris kosong serta komentar satu baris berawalan `#`
diabaikan; duplikat mempertahankan urutan kemunculan URL kanonis pertama.
Kredensial, fragmen, IP ambigu dan scheme non-HTTP ditolak tanpa mencetak input.
Satu entri invalid menggagalkan seluruh batch sebelum jaringan.

## Reproduksi pada komputer sendiri

Dari checkout yang sudah diinstal, jalankan fixture di terminal A:

```text
python -m pasopati.lab --port 8765
```

Server mengikat **hanya 127.0.0.1**, memakai port tanpa hak admin, tidak mencatat
URL request, dan berhenti dengan Ctrl+C. Tidak pernah dijalankan otomatis.
Terminal B, dari checkout:

```text
pasopati scan --targets-file examples/lab-targets.txt --config examples/lab.toml --output reports/lab-001 --include-titles --json
```

Kontrak fixture: tiga target setelah deduplikasi, empat percobaan request,
respons root 200, satu redirect relatif ke root, dan respons `/missing` 404.
Judul root jika opt-in ialah `PASOPATI local lab`. Exit 0 berarti koleksi selesai;
404 tetap observasi HTTP, bukan kerentanan. Gunakan direktori output baru setiap
run. Konfigurasi contoh hanya mengotorisasi lab loopback sintetis ini.

Fixture negatif tambahan dengan konfigurasi yang sama:

```text
pasopati scan http://127.0.0.1:8765/outside --config examples/lab.toml --json
pasopati scan http://127.0.0.1:8765/large --config examples/lab.toml --json
pasopati scan http://127.0.0.1:8765/sensitive --config examples/lab.toml --include-titles --json
```

`/outside` menghasilkan parsial `not_allowlisted` tanpa meminta tujuan eksternal.
`/large` menghasilkan `body_sampled`: maksimal 64 KiB disimpan dalam memori,
tanpa persistensi body. Keduanya sengaja exit 1. `/sensitive` menguji penyamaran
judul secara heuristik; rahasia sintetis tidak boleh muncul dalam laporan.
Ekspektasi fixture diuji dalam `tests/test_scan_local.py`, bukan hasil produksi
rekaan. Jalankan suite lengkap untuk memverifikasi platform Anda.

## Data yang dikumpulkan

Satu Session M1B dipakai bersama sepanjang run: GET saja, 50 percobaan, laju
agregat 1 request/detik, batas concurrency 2, maksimal tiga redirect per seed,
IP pinning numerik, TLS/SNI tervalidasi, tanpa retry/proxy/auth/penerusan cookie.
Scheduler awal M2A sengaja sekuensial; batas concurrency bukan klaim throughput
paralel. Deadline DNS/koneksi/read/total tetap dibatasi; total 10 detik per seed
termasuk redirect dan waktu menunggu. Anggaran 50 termasuk kegagalan DNS/koneksi
dan setiap hop redirect. Bukan jaminan seluruh 256 entri input akan selesai.

Tiap seed mencatat seluruh jawaban A/AAAA yang tervalidasi, satu IP tersambung
ketika respons diterima, status, tujuan redirect tersanitasi, observasi header
terpilih dan judul opsional. IP literal diberi label `ip_literal`, bukan lookup
DNS. Hanya IP tervalidasi pertama dicoba; IP lainnya tidak diperiksa satu per satu
dan tidak ada fallback. Kegagalan verifikasi TLS adalah kegagalan koleksi,
bukan alasan mematikan verifikasi.

Asal-usul resolusi dan respons dipertahankan walaupun tahap berikutnya gagal.
Resolusi alamat saja tidak membuktikan konektivitas. Tidak ada bukti rekaan untuk
DNS gagal, koneksi ditolak atau tujuan redirect yang tidak dikunjungi. Respons
4xx/5xx tetap dapat menjadi koleksi berhasil; status HTTP bukan vonis kerentanan.
Body besar diambil sampelnya tanpa dekompresi; pemotongan ditandai parsial.
API `Session.fetch()` lama tetap menolak body terlalu besar kecuali caller
secara eksplisit mengaktifkan sampling berbatas.

## Kontrak laporan dan privasi

Default hanya stdout. `--json` menghasilkan satu dokumen JSON, termasuk kesalahan
aplikasi, tanpa banner/ANSI. `--output DIREKTORI_BARU` secara eksplisit menyimpan
`report.json` dan `report.txt` UTF-8 tanpa ANSI. Direktori baru dicadangkan sebelum
trafik. Output lama ditolak, tidak ditimpa; berkas dibuat eksklusif dengan izin
privat pada POSIX. Akses Windows mengikuti izin OS. Disk penuh/interupsi dapat
meninggalkan berkas tidak lengkap atau direktori kosong; kesalahan exit 1.
Gunakan direktori baru untuk mengulang. Jangan commit laporan/daftar target nyata;
direktori root `reports/` sudah diabaikan Git.

Kedua renderer membaca satu `RunReport`, tidak menghitung temuan secara terpisah:

- `schema_version = "1"`, `report_type = "pasopati.recon"`: berbeda dari JSON doctor.
- ID run, versi alat terpasang, waktu UTC, profil dan jumlah percobaan request.
- ID aset, target tersamarkan, outcome dan reason code stabil.
- ID bukti, sumber, seed berizin, URL observasi, waktu UTC, metode, alat/versi,
  jawaban DNS, IP tersambung, status HTTP dan tujuan redirect jika benar diamati.
- Observasi merujuk ID bukti dan confidence `observed` atau `tentative`.
- `summary` menghitung aset completed/partial/denied/error/skipped.
- `findings = []`, `vulnerability_assessment = "not_performed"`, cakupan seed eksplisit.

Setiap path URL non-root dan seluruh query disamarkan, termasuk nama parameter.
Path berbeda dapat tampil sama; ID aset/bukti membedakannya dalam satu run.
Pakai daftar target privat asli untuk reproduksi. Body mentah dan cookie tidak
disimpan. Header terpilih hanya menyimpan keberadaan, media type ternormalisasi,
beberapa token tetap atau kandidat produk dikenal; tanpa dump header arbitrer,
versi, nonce CSP atau nilai cookie. Kandidat Server/X-Powered-By bersifat tentatif
dan dapat dipalsukan. Header yang tidak ada hanya observasi, tanpa severity atau
klaim kerentanan terkonfirmasi.

Judul **nonaktif secara default**. `--include-titles` mengaktifkan sampel judul
HTML UTF-8 berbatas, tanpa browser/JavaScript. Pola rahasia dikenal, fragmen
path/query yang terefleksi, alamat email dan karakter kontrol disamarkan/dibuang.
Panjang analisis serta output dibatasi. Ini heuristik, BUKAN jaminan tidak adanya
informasi sensitif yang belum dikenal. Jangan aktifkan untuk halaman sensitif
atau terautentikasi. Inventaris sertifikat TLS, ekspor HTML, impor laporan dan
perbandingan historis belum diimplementasikan di M2A.

## Outcome dan validasi

- Exit 0: koleksi seluruh seed selesai, bukan berarti target aman.
- Exit 1: kegagalan operasi, cakupan denied/skipped/partial atau gagal menulis output.
- Exit 2: input/konfigurasi invalid. Kesalahan parser Typer tetap berupa teks Typer.
- Run yang dihentikan melaporkan `interrupted`, bukan inventaris lengkap.

Tes mencakup regresi M1A/M1B, DNS/HTTP/TLS terverifikasi loopback nyata, koleksi CLI
lokal, penolakan redirect, sampel berbatas, bukti parsial, budget bersama,
penyamaran, JSON bersih, tanpa overwrite dan entry point wheel di luar checkout.
Tes offline tetap memblokir socket; integrasi hanya mengizinkan loopback numerik.
Tes ini tidak mengklaim validasi target eksternal atau transport IPv6 nyata.
