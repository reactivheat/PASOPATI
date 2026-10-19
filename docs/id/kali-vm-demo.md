# Demo manual Kali VirtualBox

[English](../en/kali-vm-demo.md)

Demo native VM **belum terverifikasi**, berbeda dari tes Kali WSL yang sudah lulus.
Alur manual ini tidak memerlukan SSH atau berbagi password. Jalankan sendiri
langkah berikut pada terminal di VM. Jangan kirim password ke chat. Jangan ubah
pengaturan jaringan/keamanan VM. Semua target demo adalah loopback.

## 1. Siapkan instalasi terisolasi

Cek `python3 --version`: perlu Python 3.12+ dan dukungan venv. Jika PASOPATI
belum di-clone, jalankan dari direktori **induk** yang diinginkan:

```bash
git clone https://github.com/reactivheat/PASOPATI.git
cd PASOPATI
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m pasopati --version
.venv/bin/python -m pasopati scan --help
```

Jika repo sudah ada, gunakan repo itu; jangan buat PASOPATI bertingkat atau
membuang perubahan. Jika venv/pip belum tersedia, laporkan error, jangan memasang
global atau mengubah proteksi package manager OS. Instalasi dependensi dapat
mengakses indeks paket; demo recon tidak memerlukan target internet.

## 2. Jalankan fixture lokal nyata (terminal A)

Dari root repo:

```bash
.venv/bin/python -m pasopati.lab --port 8765
```

Biarkan berjalan. Server hanya mendengarkan 127.0.0.1. Jika port terpakai, berhenti
dan pilih port nonprivileged lain secara konsisten pada perintah serta salinan
privat konfigurasi lab; jangan menghentikan proses lain yang tidak terkait.

## 3. Kumpulkan bukti (terminal B)

Buka terminal lain di root repo yang sama:

```bash
.venv/bin/python -m pasopati --lang id scan http://127.0.0.1:8765/ --config examples/lab.toml --output reports/vm-demo-001 --include-titles
echo "exit=$?"
```

Ekspektasi fixture: satu seed selesai, satu percobaan request, HTTP 200 dan judul
opt-in `PASOPATI local lab`; JSON/TXT di `reports/vm-demo-001`. Exit 0 membuktikan
koleksi, bukan keamanan. Jika output sudah ada, pilih direktori baru; jangan timpa.
Untuk fixture tiga seed/empat request gunakan `--targets-file examples/lab-targets.txt`
menggantikan URL tunggal. Demonstrasikan juga `/outside` dan `/large` yang
menghasilkan parsial/exit 1 secara eksplisit seperti di [panduan recon](recon.md).

## 4. Rekam dokumentasi asli

Maksimalkan terminal guest agar perintah/hasil terbaca. Ambil bantuan/versi serta
hasil lab berhasil/parsial yang nyata; jangan membuat output terminal rekaan.
Catat commit sumber (`git rev-parse --short HEAD`), versi Python/alat/OS, ukuran
terminal, perintah persis, kode keluar dan apakah rekaman real-time/dipercepat.
Tinjau frame agar tidak membocorkan jalur pribadi, username, notifikasi atau
rahasia sebelum publikasi. Jangan mematikan pengaturan keamanan/privasi OS atau
verifikasi untuk merekam.

Kirim hasil/screenshot untuk diperiksa sebelum mengklaim validasi native VM.
Screenshot desktop saja bukan bukti PASOPATI berjalan. Hasil Windows, WSL dan CI
hosted tidak membuktikan VM ini lulus. Hentikan fixture di terminal A dengan
Ctrl+C setelah selesai; simpan hanya laporan demo sintetis untuk ditinjau.
