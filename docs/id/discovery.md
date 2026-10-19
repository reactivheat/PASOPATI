# M2B: kandidat subdomain dan validasi DNS berscope

[English](../en/discovery.md) · [Perintah](commands.md)

`discover subdomains` menggabungkan sumber yang dipilih eksplisit, mendeduplikasi
nama dan secara opsional mengumpulkan bukti A/AAAA. Perintah ini tidak otomatis
mengunjungi situs kandidat, mengenumerasi port, mengubah allowlist atau menyimpulkan
kerentanan.

## Run pertama tanpa jaringan

Dari checkout yang sudah dipasang:

```text
pasopati discover subdomains example.invalid --source file --candidates-file examples/discovery-candidates.txt --source wordlist --wordlist examples/discovery-wordlist.txt --config examples/discovery.toml --output reports/discovery-offline-001 --json
```

Input sintetis `.invalid` tidak membutuhkan server DNS atau akun pihak ketiga.
Konfigurasi contoh passive tanpa otorisasi. Tanpa `--resolve` atau sumber `crtsh`,
impor/pembuatan nama bersifat offline, termasuk jika profil safe dipilih.
Kandidat **belum diverifikasi**, termasuk yang cocok dengan scope konfigurasi.
`scope.allowed` mencatat kecocokan kebijakan offline, bukan konektivitas atau izin legal.
Kandidat yang dikecualikan dapat tetap dicatat sebagai data sumber offline; dengan
`--resolve` kandidat ditolak sebelum DNS. Wildcard sertifikat tetap menjadi pola,
bukan host konkret atau host apex hasil inferensi.

## Sumber dan batas input

Minimal satu `--source` wajib dipilih dan dapat diulang; tidak ada sumber implisit:

| Sumber | Input wajib | Perilaku |
| --- | --- | --- |
| `file` | `--candidates-file FILE` | Kandidat domain lengkap, termasuk pola wildcard |
| `wordlist` | `--wordlist FILE` | Prefix relatif seperti `www`, `api`, `dev.api`; tambahkan `.DOMAIN` |
| `crtsh` | `--allow-provider-queries` | Satu query Certificate Transparency berbatas ke crt.sh |

Berkas lokal UTF-8 (BOM opsional), maksimal 1 MiB per berkas, berisi 1–4.096 entri
nonkosong/nonkomentar. Baris kosong dan komentar satu baris penuh `#` diabaikan.
Maksimal 256 kandidat unik dipertahankan lintas sumber. Domain memakai batas label
strict dan normalisasi IDNA; `example.invalid.evil.invalid` bukan anak
`example.invalid`. URL, IP, nama invalid dan input lokal di luar domain membuat
seluruh batch ditolak sebelum trafik. Wordlist tidak menerima wildcard atau titik
di akhir. Tidak ada wordlist besar bawaan.

Nama duplikat mempertahankan setiap sumber penyumbang, referensi baris/sertifikat
pertamanya dan digest SHA-256 untuk setiap input lokal. Path berkas lokal dan body
mentah sumber/provider tidak diekspor. SAN provider yang tidak terkait domain
dibuang, bukan diikuti atau dicetak sebagai target.

## Opt-in DNS hanya pada scope berizin

Buat TOML privat untuk sistem yang memang boleh kamu periksa. Berikut sintaks,
bukan otorisasi atas domain nyata:

```toml
schema_version = 1
profile = "safe"
authorized = true

[scope]
allow_domains = ["your-authorized-domain.example", "*.your-authorized-domain.example"]
exclude_domains = ["excluded.your-authorized-domain.example"]
```

Domain dasar dan setiap kandidat/probe acak yang di-query wajib diizinkan.
`*.DOMAIN` tidak mengizinkan apex; tulis keduanya jika keduanya disetujui.
Jangan tambahkan wildcard jika izin engagement tidak mencakupnya. Alamat lab privat
yang didukung juga memerlukan CIDR eksplisit dan `allow_private = true`; pengecualian
menang. Link-local, metadata dan rentang khusus terlarang lainnya tetap ditolak.
Lihat [konfigurasi](configuration.md).

```text
pasopati discover subdomains your-authorized-domain.example --source wordlist --wordlist your-prefixes.txt --resolve --config pasopati.toml --output reports/discovery-dns-001 --json
```

`--resolve` membedakan `dns_resolved`, `dns_nxdomain`, `dns_no_address`, timeout,
kegagalan resolver, alamat terlarang dan cakupan belum lengkap. Respons mencatat
alamat aktual serta TTL jika tersedia. Jawaban A/AAAA bukan bukti port terbuka,
HTTP tersedia, kepemilikan atau host unik. DNS rekursif dapat mengikuti CNAME;
alamat hasil tetap diperiksa kebijakan. Tidak ada koneksi ke alamat kandidat,
dan tujuan CNAME tidak otomatis ditambahkan sebagai target kandidat.

Sebelum resolusi subdomain, periksa tiga label acak pada **parent langsung**,
hanya jika seluruh nama probe masuk scope. Hasil tiap parent di-cache; maksimal
empat parent diprobe per run. Probe positif mana pun menghasilkan `possible`,
termasuk bila IP berotasi. `clear` hanya berarti tiga probe ini negatif saat run,
bukan bukti wildcard DNS tidak pernah ada. Batas scope/panjang/budget/kegagalan
dicatat sebagai unchecked atau inconclusive. Kandidat teresolusi dengan kemungkinan
wildcard memiliki confidence hostname tentative; cakupan wildcard yang belum
diperiksa menghasilkan status parsial.

## Query CT pihak ketiga opsional

Pemilihan crt.sh mengirim domain dasar ke pihak ketiga dan mengungkap query kepada
resolver DNS yang dikonfigurasi. Rekaman sertifikat bisa usang, kurang lengkap atau
dipakai bersama; ini klaim kandidat, bukan bukti host hidup. Wajib profil safe,
`authorized = true`, domain dasar yang diizinkan dan persetujuan query provider:

```text
pasopati discover subdomains your-authorized-domain.example --source crtsh --allow-provider-queries --config pasopati.toml --json
```

Tambahkan `--resolve` terpisah untuk validasi DNS target berscope. Tanpa opsi itu,
crt.sh tetap memakai HTTPS/DNS provider keluar; "CT pasif" **bukan** offline.
Request tetap: `https://crt.sh/?q=%25.DOMAIN&output=json`. Kebijakan terpisah khusus
`crt.sh:443` memeriksa alamat publik provider, TLS dan setiap redirect, mempertahankan
pengecualian target serta tidak memperluas scope target. Tidak ada opsi URL provider,
auth, header atau kredensial arbitrer. Tanpa retry aplikasi atau provider alternatif.

Non-200, timeout, JSON invalid, nesting berlebihan atau respons di atas 64 KiB
merupakan kegagalan eksplisit. Maksimal 4.096 baris/entri nama diparse; pemotongan
atau baris cacat menghasilkan cakupan sumber parsial. Array JSON kosong yang valid
adalah query selesai dengan nol kandidat, berbeda dari kegagalan provider.
Ketersediaan/rate limit layanan publik tidak dijamin. Jalur provider diuji dengan
fixture; tidak diklaim ada query target crt.sh live untuk validasi pengembangan.

Referensi antarmuka: [gateway web crt.sh](https://github.com/crtsh/crtsh-web),
[implementasi API database resmi](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).
Parser berbatas ditulis mandiri; kode provider tidak dibundel.

## Budget, laporan dan hasil

Satu budget safe bersama mencakup hop HTTP provider serta lookup DNS A/AAAA target,
termasuk wildcard: 50 unit percobaan logis, agregat 1 unit/detik, concurrency
maksimal 2. Tiap hop provider memakai satu unit termasuk DNS internal provider;
tiap lookup RR target memakai satu unit. NXDOMAIN menghentikan lookup tersisa
untuk nama tersebut. Deadline total per nama 10 detik termasuk menunggu rate gate;
lifetime tiap DNS maksimal 3 detik. DNS memakai resolver numerik konfigurasi OS,
tanpa search suffix, hosts/mDNS/DoH atau fallback resolver publik. dnspython dapat
mengirim ulang atau mencoba nameserver terkonfigurasi selama lifetime: ini **batas
lookup logis, bukan penghitung paket atau penegakan laju paket DNS**.
Lihat [transport](transport.md) dan [kontrak lifetime dnspython](https://dnspython.readthedocs.io/en/stable/resolver-class.html).

JSON/TXT memakai `RunReport` yang sama dengan `scan`. Discovery menggunakan
`schema_version = "2"`; schema scan 1 tetap. Metadata tambahan `discovery` berisi
status/digest sumber, disclosure, jumlah DNS/provider serta bukti wildcard. Bukti
memakai `subject_name`, `query_name`, `query_type`, bukan URL palsu untuk DNS/impor;
observasi merujuk ID bukti, timestamp dan versi alat terpasang. Query URL provider
disamarkan; body mentah, header arbitrer atau nilai cookie tidak disimpan.
Nama domain/IP tetap data recon sensitif: jangan commit laporan nyata.

`--json` menghasilkan satu dokumen tanpa ANSI. `--output DIREKTORI_BARU` membuat
JSON/TXT eksplisit, menolak output yang sudah ada sebelum jaringan. Pakai direktori
baru tiap run. Exit 0 berarti seluruh koleksi yang diminta selesai, **bukan** semua
kandidat hidup atau unik: jawaban DNS negatif dan ambiguitas wildcard yang dijelaskan
adalah data valid. Exit 1 mencakup provider gagal, DNS ditolak/parsial/dilewati atau
output gagal; sumber lain yang dipilih tetap dapat menyumbang bukti. Exit 2 berarti
input/konfigurasi invalid. `findings` tetap kosong dan `vulnerability_assessment`
adalah `not_performed`. Tidak ada klaim kelengkapan, kecepatan atau keunggulan atas
Sublist3r/Nmap.
