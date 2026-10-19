# M2D: observasi web berbukti dan TLS terverifikasi

[English](../en/web-tls.md) · [Scan](recon.md) · [Perintah](commands.md)

`scan --web-details` memperluas inventaris URL eksplisit tanpa menambah request.
Opsi ini menambah metadata sertifikat leaf/negosiasi terverifikasi, identitas endpoint
privat lokal run, ringkasan header dan aturan produk transparan yang tentative.
Bukan crawler, browser, auditor TLS atau detektor kerentanan/CVE.

## Penggunaan dan run pertama yang dapat diulang

Jalankan fixture lokal di terminal lain:

```text
python -m pasopati.lab --port 8765
```

Dari checkout yang sudah dipasang:

```text
pasopati scan --targets-file examples/lab-targets.txt --config examples/lab.toml --web-details --output reports/web-lab-001 --json
```

Fixture memakai HTTP, sehingga menghasilkan bukti endpoint/header tetapi **tanpa
bukti TLS**. Tidak adanya observasi TLS pada HTTP bukan berarti pemeriksaan sertifikat
gagal. Contoh ini tetap memakai empat percobaan/tiga seed fixture sebelumnya dan tidak
mengikuti tautan HTML. Pakai direktori output baru tiap run. Lihat [panduan lab](recon.md).

Untuk HTTPS nyata berizin, berikan URL eksplisit dan TOML privat dengan allowlist:

```text
pasopati scan https://your-authorized-host.example/ --config pasopati.toml --web-details --json
```

Ini sintaks, bukan bukti target ada atau izin untuk mengujinya. Wajib `authorized = true`,
profil safe, port/domain/CIDR diizinkan dan kebijakan alamat cocok. Kontrol DNS/IP
pinning, redirect/downgrade, laju satu unit/detik, budget 50 hop, concurrency maksimal
dua serta deadline connect+TLS 3s/read 5s/total 10s tetap. Tanpa request tambahan,
enumerasi protokol, discovery port atau retry. Scheduler sekuensial; HTTP mencoba
hanya IP tervalidasi pertama.

## Bukti TLS: apa yang benar-benar diverifikasi

Pada tiap hop HTTPS, hostname/IP asli diperiksa memakai konteks klien Python/OpenSSL
normal dan trust store lokal. Tanpa opsi insecure, fallback sertifikat tidak dipercaya
atau bypass verifikasi. Observer metadata hanya berjalan setelah verifikasi sukses
dalam deadline connect+TLS, sebelum request HTTP dikirim. Bukti mencatat IP numerik
koneksi aktual, URL dengan path/query disamarkan, port, waktu UTC, metode dan versi alat.

Observasi `tls.*` merujuk bukti handshake tersebut:

- `verified = true`: trust/hostname lokal berhasil, bukan vonis kepercayaan universal.
- `leaf_sha256`: SHA-256 DER leaf terverifikasi, **bukan** SPKI atau fingerprint chain.
- `not_before`, `not_after`: timestamp masa berlaku leaf dalam UTC.
- `protocol`, `cipher`, `cipher_bits`: versi TLS, cipher dan bit cipher simetris yang
  dinegosiasikan pada koneksi ini; bukan ukuran kunci sertifikat atau semua suite didukung.
- `san_dns_count`, `san_ip_count`, `san_other_count`: jumlah entri SAN, bukan target discovery.

Tanpa ekspor PEM/DER, subject/issuer/serial, nilai SAN, session key atau private key.
Sertifikat dibatasi 64 KiB dan entri SAN 4.096. Metadata TLS 1.2/1.3 didukung; metadata
lain menghasilkan unsupported eksplisit, bukan hasil rekaan. Bukti TLS sukses tetap
ada jika HTTP/header/body sesudahnya gagal, tetapi tidak berarti ada respons HTTP.
Handshake terverifikasi tanpa respons HTTP tidak membuat status HTTP/identitas endpoint rekaan.

Dengan opsi ini, verifikasi sertifikat gagal memakai `tls_verification_failed`;
error TLS lain `tls_failed`; metadata tidak tersedia/berbatas `tls_metadata_unavailable`.
Tidak ada fingerprint tidak terverifikasi atau retry insecure. `SSL_CERT_FILE`/
pengaturan trust sistem dihormati; konteks produksi sengaja mengabaikan `SSLKEYLOGFILE`.
Konfigurasikan CA privat tepercaya secara lokal, bukan mematikan verifikasi. Tes
memakai sertifikat lokal sementara.

Batas: tanpa inventaris chain lengkap, jaminan OCSP/CRL/revocation/CT, analisis
kunci/signature sertifikat, enumerasi cipher, temuan kedaluwarsa/severity, vonis
kesehatan aplikasi HTTPS atau klaim validasi target publik/platform baru. Lihat
[API TLS Python](https://docs.python.org/3.12/library/ssl.html#ssl.SSLSocket.getpeercert).

## Pemetaan endpoint tanpa membuka path privat

Tiap respons HTTP aktual memperoleh `web.endpoint_id`: HMAC-SHA256 penuh URL kanonis
dengan kunci acak 32 byte baru untuk run itu. Kunci tidak diekspor. URL identik dalam
run memiliki ID sama; path/query berbeda dapat dibedakan meski URL terlihat disamarkan.
Ini identitas **lokal run**, bukan ID pembanding historis, hash publik atau bukti endpoint
tersembunyi. `web.endpoints_observed` menghitung URL respons berbeda, termasuk redirect
yang diizinkan. Tautan ditolak/tidak dikunjungi dan handshake tanpa HTTP tidak membuat
rekaman endpoint. Versi protokol HTTP dicatat bila teramati parser respons nyata.

Pemetaan hanya URL masukan dan hop redirect berizin. Tanpa ekstraksi link, JavaScript,
fetch robots/sitemap, tebakan direktori atau impor discovery otomatis. Batas input/
body/redirect tetap; sampel besar tetap parsial. `--include-titles` terpisah dan default
nonaktif dengan keterbatasan privasi heuristik yang sudah dijelaskan. Host/IP/fingerprint
sertifikat nyata tetap data recon sensitif meski path disamarkan; jangan commit laporan
atau daftar target nyata.

## Observasi header transparan

Semua nilai berikut berasal dari bukti respons HTTP yang sama, bukan probe tambahan:

| Observasi | Kontrak |
| --- | --- |
| `fingerprint.server`, `fingerprint.x-powered-by` | Prefix produk dikenal saja, selalu tentative |
| `.rule` yang sesuai | ID aturan stabil `header-prefix/1:HEADER:PRODUCT` |
| `hsts.*` | Token max-age/includeSubDomains/preload didukung dan apakah diterima melalui HTTPS |
| `csp.recognized_directives` | Nama directive dalam allowlist, tanpa sumber/nonce/hash/URL laporan |
| `http.advertised_methods` | Token Allow didukung saja; metode itu tidak dieksekusi |

Aturan produk memakai prefix case-insensitive dengan batas `[/\s;]` atau akhir nilai.
Label dikenal: nginx, apache, caddy, microsoft-iis, openresty, gunicorn, uvicorn,
express, php, asp.net. Nilai arbitrer/tidak dikenal serta versi disamarkan. Header
dapat dipalsukan; prefix cocok hanya membuktikan respons mengiklankannya. Tanpa
inferensi CVE atau klaim teknologi/versi terkonfirmasi.

Parser menerima maksimal 8.192 karakter per header yang diperiksa. HSTS mendukung
maksimal 16 directive unik dan max-age 1–10 digit tanpa kutip. Nol adalah token
penghapusan, bukan kerentanan; token preload bukan bukti masuk daftar preload browser.
HSTS lewat HTTP dicatat tidak diterima melalui HTTPS, bukan policy ditegakkan.
CSP maksimal 64 segmen directive dan tidak mengevaluasi efektivitas policy atau
gabungan beberapa policy. Allow maksimal 32 token metode tetap. Input unsupported/
besar/ambigu mendapat flag dukungan eksplisit, bukan nilai mentah atau vonis
"hilang/aman/rentan". Nilai Set-Cookie tidak diperiksa/diekspor.

Referensi: [spesifikasi HSTS](https://www.rfc-editor.org/rfc/rfc6797),
[spesifikasi CSP](https://www.w3.org/TR/CSP3/). Subset ini bukan parser browser lengkap.

## Laporan dan outcome

Kedua renderer memakai `RunReport` yang sama. Opt-in ini menggunakan `schema_version = "4"`,
metadata `web` tentang cakupan/aturan/endpoint, bukti handshake dan observasi terkait.
Tanpanya schema scan 1 tetap; bentuk schema discovery 2 dan TCP 3 juga tidak berubah.
`findings = []` dan `vulnerability_assessment = "not_performed"`. JSON satu dokumen tanpa
ANSI. `--output DIREKTORI_BARU` menulis JSON/TXT UTF-8 secara eksplisit, tanpa overwrite,
dan mereservasi output sebelum trafik.

Exit 0 berarti koleksi diminta selesai, bukan target aman atau temuan valid. Exit 1
mencakup kegagalan TLS/HTTP, partial/denied/skipped/budget/output; bukti yang
ada tetap diberi keterangan. Exit 2 berarti input/konfigurasi invalid. Pembatalan
bukan selesai. Tes mencakup HTTPS lokal trust/hostname benar/salah, HTTP gagal sesudah
TLS, SNI/pinning numerik, cleanup/deadline, metadata tanpa rahasia, tanpa crawling,
regresi schema lama dan jalur CLI wheel bersih. Screenshot/GIF dan dokumentasi VM native
tetap ditunda.
