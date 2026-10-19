# M2C: inventaris TCP-connect eksplisit

[English](../en/ports.md) · [Perintah](commands.md)

`ports` menguji pembentukan koneksi TCP ke pasangan host/port yang diizinkan
eksplisit. Tanpa hak admin, payload aplikasi atau pembacaan banner. Tidak
mengidentifikasi layanan, versi, sistem operasi atau kerentanan. Port 443 tidak
otomatis disebut HTTPS; open bukan bukti aplikasi berfungsi.

## Reproduksi lokal

Dari checkout yang sudah dipasang, jalankan fixture di terminal lain:

```text
python -m pasopati.lab --port 8765
```

Lalu:

```text
pasopati ports 127.0.0.1 --ports 8765 --config examples/lab.toml --json
pasopati --lang id ports --targets-file examples/tcp-lab-hosts.txt --ports 8765 --config examples/lab.toml --output reports/tcp-lab-001
```

Kontrak fixture: satu percobaan TCP, `tcp.state = "open"`, tanpa DNS target,
request HTTP atau identifikasi layanan. Ini ekspektasi fixture yang dapat diulang,
bukan hasil produksi rekaan. Config contoh hanya mengizinkan alamat/port loopback
tersebut, bukan template izin target nyata. Hentikan fixture dengan Ctrl+C.
Pakai direktori output baru setiap run.

## Otorisasi dan input eksplisit

Untuk sistem lain dapatkan izin sebenarnya, lalu set `authorized = true`, pilih
`profile = "safe"` serta allowlist domain/CIDR dan port tepat di TOML privat.
Default `init` tetap passive/tanpa otorisasi. Aturan domain tidak mengizinkan
target IP literal: IP perlu CIDR eksplisit. Alamat lab privat yang didukung juga
memerlukan CIDR dan `allow_private = true`; rentang khusus terlarang tetap ditolak.
Pengecualian menang. Lihat [konfigurasi](configuration.md).

```text
pasopati ports your-authorized-host.example --ports 22,80,443 --config pasopati.toml --output reports/tcp-001 --json
```

Ini sintaks, bukan target yang sudah dipindai atau izin untuk mengujinya. `--ports`
tidak memiliki daftar scan default: berikan angka desimal dipisah koma, tanpa
spasi, nol di depan, rentang, nama atau tanda. Tiap port 1–65535. Maksimal 64 entri
port sebelum deduplikasi. `--targets-file` menerima baris host/IP UTF-8 berbatas
(BOM opsional, baris kosong/komentar penuh `#` diabaikan), bukan daftar URL untuk
`scan`. Host posisi dan file dapat digabung. Tanpa URL, wildcard, CIDR, IP ambigu,
kredensial atau sintaks `host:port`. IPv6 berupa alamat polos saat input dan
ditampilkan memakai kurung siku pada endpoint. Tanpa ekspansi subnet/reverse DNS.

Seluruh input divalidasi sebelum jaringan: berkas maksimal 1 MiB, 64 entri host
sebelum deduplikasi, nama kanonis/IDNA, maksimal 256 pasangan host/port unik.
Entri invalid membatalkan batch. Host/port di luar scope menghasilkan denied
eksplisit, tanpa DNS jika seluruh port host ditolak. Subdomain hasil discovery
tidak otomatis diimpor, diizinkan atau diprobe.

## Kontrol koneksi dan batas

Kolektor memakai scope, resolver A/AAAA berscope dan `RequestBudget` yang sama
dengan discovery. Resolve sekali per host layak/run; wajib jawaban DNS sukses
lengkap, lalu periksa **seluruh** alamat sebelum koneksi mana pun. Jawaban campuran
publik/terlarang, family kedua gagal, jawaban inkonsisten atau lebih dari 16 alamat
ditolak tertutup; tidak memilih subset aman diam-diam. DNS negatif tetap menjadi
bukti tetapi tidak menyelesaikan cakupan TCP. Timestamp/jawaban DNS asli dipakai
ulang pada tiap aset port dengan ID bukti unik; bukan DNS berulang. TTL adalah
metadata teramati, bukan jaminan kesegaran untuk setiap endpoint berikutnya.

Tiap endpoint memakai IP numerik tervalidasi, bukan hostname socket. Snapshot
terpin mencegah check-then-re-resolve/rebinding saat koneksi. Tanpa refresh, retry,
resolver alternatif, proxy atau adaptor alat otomatis. Seluruh alamat teresolusi
berizin dipertimbangkan untuk setiap port yang diminta/diizinkan sampai budget
habis. Routing/NAT OS di luar kendali library.

Policy safe: 50 unit logis untuk seluruh run, agregat satu unit/detik, concurrency
maksimal dua (scheduler saat ini sekuensial). Tiap lookup A/AAAA dan tiap TCP connect
memakai satu unit, termasuk yang gagal. NXDOMAIN menghentikan query DNS tersisa
untuk nama itu. Retransmisi/percobaan nameserver dnspython dan retransmisi SYN OS
**bukan** penghitung paket atau penegakan laju paket. Batas input tidak menjamin
seluruh pasangan/alamat cukup dalam 50 unit.

Tiap nama lookup DNS memakai batas total 10 detik/query 3 detik yang sudah ada.
Tiap endpoint TCP memiliki deadline total 10 detik termasuk menunggu limiter dan
fase connect maksimal tiga detik atau sisa waktu. Hasil terlambat tidak diterima
sebagai open/refused. Socket ditutup saat sukses, gagal dan pembatalan. OS bukan
scheduler hard-real-time. Tanpa data aplikasi dikirim/dibaca, tetapi handshake/
close TCP biasa dan log di sisi server tetap dapat terjadi. Lihat
[kontrak socket Python](https://docs.python.org/3.12/library/socket.html#socket.socket.connect)
dan [simbol kesalahan OS](https://docs.python.org/3.12/library/errno.html).

## Tafsirkan bukti, bukan tebakan nomor port

| `tcp.state` | Makna |
| --- | --- |
| `open` | TCP connect sukses sebelum deadline fase |
| `refused` | OS eksplisit melaporkan koneksi ditolak; bisa dari host atau perantara |
| `timeout` / `deadline_exceeded` | Tidak ada hasil diterima dalam batas; bukan closed/filtered |
| `unreachable` | OS melaporkan jalur tidak terjangkau; bukan vonis keadaan layanan |
| `reset` | Reset/error saat koneksi; bukan vonis layanan/versi |
| `local_error` / `error` | Izin/resource/family lokal atau kegagalan OS lain; keadaan target belum diketahui |

DNS gagal, penolakan kebijakan dan budget habis **tidak membuat percobaan/keadaan
TCP rekaan**. Bukti mencatat host target, IP numerik yang dicoba, port, transport,
waktu UTC, metode, versi terpasang dan IP koneksi berhasil hanya jika teramati.
Observasi merujuk ID bukti, kode error OS numerik aman jika tersedia serta durasi
connect tanpa waktu menunggu rate gate. Durasi bukan RTT jaringan atau benchmark.
String exception mentah, banner, body dan rahasia tidak dilaporkan. Tanpa inferensi
layanan melalui `getservbyport`, TLS atau probe protokol.

JSON/TXT memakai `RunReport` yang sama; TCP menggunakan `schema_version = "3"`,
tetap `report_type = "pasopati.recon"`, menambah metadata `tcp` serta bukti `port`/
`transport`. Bentuk schema scan 1 dan discovery 2 tidak berubah.
`tcp.service_identification = "not_performed"`, `payloads_sent = false`, `findings = []`
dan `vulnerability_assessment = "not_performed"`. Inventaris domain/IP nyata tetap
sensitif; jangan commit. Lihat [laporan HTTP](recon.md) untuk privasi output.

`--json` satu dokumen tanpa ANSI. `--output DIREKTORI_BARU` menyimpan JSON/TXT UTF-8
secara eksplisit dan menolak output lama sebelum jaringan. Exit 0 berarti seluruh
percobaan endpoint teresolusi/berizin selesai diobservasi open/refused, bukan semua
port terbuka atau target aman. Exit 1 mencakup partial/denied/skipped/unknown/DNS/
output gagal. Exit 2 berarti input/konfigurasi invalid. Pembatalan melaporkan
`interrupted`, bukan inventaris selesai; berkas dapat belum lengkap.

Tes mencakup DNS lokal terbatas, TCP loopback IPv4 dan IPv6 jika tersedia, koneksi
berhasil/ditolak, tanpa payload, cleanup, scope/batas, klasifikasi error dan entry
point terpasang dari luar checkout. Integrasi IPv6 skip eksplisit jika OS tidak
dapat bind `::1`. Tidak diklaim ada scan target eksternal, SYN/raw/UDP, deteksi
layanan, kesetaraan Nmap atau validasi VirtualBox native.
