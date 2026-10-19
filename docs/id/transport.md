# Transport internal dengan pembatasan scope (M1B)

[English](../en/transport.md) · [Konfigurasi](configuration.md)

`pasopati.transport.Session(config).fetch(url, method="GET")` adalah API Python
untuk modul mendatang, bukan perintah scan. Hasil immutable berisi status/body/
content-type di memori. Tidak menyimpan body, cookie atau header ke disk. Pemanggil
mendatang tidak boleh mencetak body/URL sensitif. CLI kebijakan tetap offline dan
tidak mengimpor transport ini.

Pemanggil wajib memberikan `Config` tervalidasi dengan otorisasi jaringan eksplisit,
profil `safe`, serta scope yang cocok. Pengakuan pengguna bukan bukti kepemilikan/
izin hukum. Setiap tujuan redirect diperiksa lagi.

## Invariant koneksi

1. Tolak otorisasi/profil/metode/scope/port yang tidak sesuai sebelum DNS target.
2. Resolve A dan AAAA dengan server DNS numerik dari OS melalui dnspython; tanpa
   search suffix, discovery DoH otomatis, fallback resolver publik, atau getaddrinfo.
   Konfigurasi resolver kosong/tidak didukung ditolak; perbaiki resolver OS sebelum
   memakai API ini.
3. Lifetime bersama DNS maksimum 3 detik atau sisa deadline, diteruskan ke tiap
   query nyata. dnspython adalah satu tambahan dependensi runtime karena pemeriksaan
   waktu setelah getaddrinfo memblokir tidak memadai. Lihat
   [kontrak lifetime dnspython](https://dnspython.readthedocs.io/en/stable/resolver-class.html).
4. Tolak seluruh jawaban jika ada alamat melanggar kebijakan/exclusion. Domain
   diizinkan dapat resolve ke alamat publik tanpa CIDR tambahan; target IP literal
   dan jawaban lab nonpublik memerlukan CIDR eksplisit.
5. Socket.connect hanya menerima satu IP numerik tervalidasi. Tanpa resolve ulang,
   retry ke alamat lain, atau proxy otomatis. Routing/NAT OS di luar kendali library.
6. HTTPS memakai trust sistem, verifikasi sertifikat, SNI dan Host hostname asli.
   SSLKEYLOGFILE tidak mengaktifkan penyimpanan kunci TLS. Tidak ada opsi TLS insecure.

## Batas sumber daya dan respons

Satu Session berbagi budget 50 percobaan, laju agregat 1 request/detik, concurrency 2.
Budget dikurangi sebelum tiap hop, termasuk kegagalan DNS/koneksi. Tanpa retry
otomatis. Redirect 301/302/303/307/308 memakai budget/rate yang sama dan tetap
memakai metode awal (GET/HEAD). Mendukung Location relatif. Maksimum tiga redirect;
loop, Location kosong, keluar scope, scheme terlarang dan downgrade HTTPS ditolak.
Header dibangun ulang tetap; tanpa penerusan kredensial/cookie/header sensitif.

Deadline monotonic 10 detik mencakup antrean semaphore/rate, DNS, connect, TLS,
header, body dan seluruh redirect. Connect+TLS berbagi fase 3 detik. Read/write
socket maksimum 5 detik atau sisa deadline. Tiap receive mentah mengecek deadline,
termasuk header/chunk yang menetes. Penjadwalan OS/I/O trust store bukan jaminan
hard real-time. Session dapat dipakai lagi setelah gagal; resource respons/socket/
semaphore/lock selalu ditutup/dilepas.

Body dibaca bertahap dan ditolak di atas 64 KiB tanpa bergantung pada Content-Length,
termasuk framing chunked. HEAD tanpa pembacaan body. Hanya encoding identity;
kompresi ditolak, bukan didekompresi. Tanpa cookie jar, proxy environment,
negosiasi autentikasi, penerusan kredensial, penyimpanan atau logging.

## Tes dan keterbatasan

Tes memakai resolver/connector/clock injeksi serta fixture HTTP/DNS/HTTPS loopback
nyata. Tes biasa tidak dapat membuka socket. Socket integrasi hanya mengizinkan
loopback numerik, termasuk UDP sendto; tujuan eksternal diblokir. Tes TLS membuat
sertifikat sementara dengan OpenSSL, mempercayai sertifikat fixture, dan memastikan
hostname yang salah ditolak. Jika OpenSSL tidak tersedia, satu kasus integrasi itu
ditandai skip secara eksplisit; unit test pengaturan TLS/pinning tetap berjalan.

Tes DNS memakai server UDP lokal, termasuk server tidak responsif untuk membuktikan
lifetime. Policy IPv4/IPv6 diuji; jaringan IPv6 nyata dan transport target publik
belum diklaim. Resolver tidak memakai hosts file/mDNS atau DoH/DoT.
Milestone ini belum menyediakan discovery aset, scanning, atau analisis kerentanan.
