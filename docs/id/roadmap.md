# Roadmap kemampuan dan persyaratan bukti

[English](../en/roadmap.md)

PASOPATI ditujukan untuk alur recon praktisi yang terhubung dan reproducible.
"Lebih powerful" adalah tujuan, bukan klaim kemampuan atau performa yang sudah
diukur. M2A melakukan trafik DNS/HTTP nyata dan berizin; lab lokal adalah lingkungan
verifikasi yang dapat diulang, bukan berarti pemindaian hanya bisa offline.

## Kemampuan aktual, bukan pemasaran

| Fungsi | PASOPATI M2B | Tahap berikutnya |
| --- | --- | --- |
| Inventaris URL eksplisit berizin | Ada, DNS/HTTP/HTTPS berbatas | Perluas metadata secara teruji |
| Bukti, scope, batas bersama, JSON/TXT | Ada | Korelasi dan perbandingan run |
| Enumerasi subdomain | Kandidat file/wordlist/crt.sh eksplisit; DNS/wildcard berscope opt-in | Provider tambahan dan pengukuran cakupan terpisah |
| Inventaris host/port/layanan | Belum ada | TCP-connect eksplisit berbatas |
| Inventaris sertifikat TLS | Belum ada; verifikasi sertifikat wajib | Ekstrak metadata tervalidasi |
| Validasi kerentanan/CVE | Tidak dilakukan | Pemeriksaan berbukti dengan acceptance criteria sendiri |
| HTML, histori/diff | Belum ada | Renderer model bersama, bukan inferensi di renderer |

[Panduan Nmap](https://nmap.org/book/man.html) mendokumentasikan discovery host,
scan port, deteksi layanan/versi dan OS, serta fungsi lain. M2B tidak menerapkan
engine tersebut. [Sublist3r](https://github.com/aboul3la/Sublist3r) adalah alat
enumerasi subdomain; M2B kini memiliki discovery berbatas sendiri, bukan klaim
kesetaraan cakupan atau kecepatan. Keduanya referensi, bukan
dependensi bawaan, integrasi terverifikasi atau alat yang sudah dikalahkan benchmark.

## Cakupan terimplementasi dan usulan milestone selanjutnya

1. **M2B — discovery domain/subdomain terimplementasi.** Lihat [panduan fungsional](discovery.md).
   Sumber file/wordlist/crt.sh eksplisit, disclosure provider, budget logis bersama,
   provenance/digest, pemeriksaan batas label serta A/AAAA/wildcard opt-in.
   Nama hasil discovery tetap kandidat, bukan target otomatis berizin; tanpa HTTP
   otomatis. Fixture memverifikasi perilaku, bukan ketersediaan provider publik.
2. **M2C — inventaris port/layanan.** Mulai dengan TCP-connect tanpa admin ke alamat/
   port yang diizinkan. Gunakan scope, pinning numerik, deadline, laju/concurrency/
   budget dan cleanup bersama. Timeout bukan otomatis port open/closed. Adaptor
   eksternal perlu review tersendiri, target numerik, argument array tetap, output/
   waktu berbatas, tanpa shell atau skrip NSE arbitrer.
3. **M2D — observasi web/TLS lebih dalam.** Metadata sertifikat terverifikasi,
   pemetaan endpoint berbatas dan aturan fingerprint transparan dengan confidence.
   Petunjuk metadata bukan bukti versi rentan; tanpa eksploitasi otomatis.
4. **M3 — alur kerja praktisi.** Korelasi aset lintas sumber, HTML portabel yang
   di-escape, perbandingan historis, prioritas dan pemeriksaan paparan tervalidasi
   secara independen. Semua tampilan memakai model bukti ternormalisasi.

Tiap milestone memerlukan kontrak yang disepakati dan tes sebelum implementasi.
Jangan diam-diam mengubah M2A menjadi scanner tanpa batas. Kontrol jaringan adalah
bagian dari ketepatan recon, bukan opsi yang dimatikan untuk mempercantik pengukuran.

## Syarat klaim pembanding

- Versikan fixture, inventaris ground truth, alat/konfigurasi/perintah, environment
  dan prosedur pengukuran. Bandingkan hanya fungsi yang tumpang tindih dan scope setara.
- Catat aset diketahui yang ditemukan/terlewat, false positive/negative dan cakupan
  parsial. Jangan menyimpulkan akurasi umum dari lab sintetis kecil.
- Ukur jumlah request, waktu, byte dan sumber daya nyata dengan batas yang dibuka.
  Jangan membandingkan policy HTTP satu request/detik dengan scan paket tanpa batas
  lalu mengklaim pemenang umum. Laporkan variasi pengulangan, bukan timing pilihan.
- Uji kegagalan, DNS wildcard, perubahan jawaban, layanan tidak responsif, redirect,
  kegagalan TLS, penyamaran dan pembatalan, bukan hanya hasil berhasil.
- Pakai lab milik sendiri/berizin. Deployment publik, akurasi target nyata dan
  platform native memerlukan bukti tersendiri. Screenshot/GIF wallpaper desktop
  atau output simulasi bukan validasi fitur.

Sebelum rilis open source: lisensi pilihan pemilik, kontak keamanan privat
terverifikasi, panduan kontribusi, review dependensi/build dan kebijakan dukungan.
Repositori publik bukan pemberian lisensi. Roadmap ini tidak mengizinkan atau
menyatakan sudah adanya release.
