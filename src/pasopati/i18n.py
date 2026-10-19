"""Small, explicit EN/ID message catalog; machine identifiers stay stable."""

from enum import StrEnum


class Language(StrEnum):
    EN = "en"
    ID = "id"


MESSAGES: dict[Language, dict[str, str]] = {
    Language.EN: {
        "hint": "Start with: pasopati --help",
        "quick_start": "Quick start",
        "quick_help": "List commands and options",
        "quick_doctor": "Check local environment readiness",
        "quick_json": "Get machine-readable environment checks",
        "foundation": (
            "M2B: explicit-source discovery and authorized URL inventory; offline policy remains."
        ),
        "recon_title": "DNS/HTTP inventory",
        "discovery_title": "Subdomain candidates and DNS observations",
        "discovery_domain": "Domain context",
        "discovery_attempts": "Logical attempt units used (not DNS packets)",
        "discovery_counts": "DNS RR lookups: {dns}; provider HTTP attempts: {http}",
        "discovery_limitations": (
            "Candidates are not authorization or proof of live hosts. No target HTTP probing."
        ),
        "provider_disclosure": "The selected domain query was explicitly permitted for crt.sh.",
        "invalid_domain": "Provide a valid domain, not a URL, IP, credential or wildcard.",
        "invalid_discovery": "Select explicit sources and provide the matching input options.",
        "invalid_candidates": (
            "Invalid or oversized candidate input; names must remain within the domain."
        ),
        "candidates_io": "Cannot read bounded UTF-8 candidate input.",
        "provider_consent_required": (
            "crt.sh requires --allow-provider-queries; the domain is sent to a third party."
        ),
        "provider_invalid": (
            "The provider returned unsupported or malformed JSON; no candidates invented."
        ),
        "provider_unavailable": "The provider did not return HTTP 200; no automatic retry.",
        "provider_invalid_rows": "Some provider records were malformed; collection is partial.",
        "candidate_limit": "Candidate/input limit reached; collection is partial.",
        "source_complete": "Selected source processed within its declared limits.",
        "candidate_collected": "Unverified candidate collected; DNS/connectivity were not checked.",
        "wildcard_pattern": "Wildcard pattern retained; this is not a concrete hostname.",
        "dns_resolved": "Address records observed; not proof of service availability or ownership.",
        "dns_nxdomain": "The resolver returned NXDOMAIN at collection time.",
        "dns_no_address": "No A/AAAA address records observed; other record types may exist.",
        "dns_inconsistent": (
            "Address and NXDOMAIN answers were inconsistent; validation is partial."
        ),
        "dns_wildcard_possible": (
            "Wildcard DNS is possible; do not treat this as a confirmed unique host."
        ),
        "dns_wildcard_unchecked": "DNS answers observed but wildcard validation is incomplete.",
        "recon_status": "Run status",
        "recon_requests": "Request attempts used",
        "recon_limitations": (
            "Explicit URLs only. No crawling or subdomain discovery. Paths/queries withheld."
        ),
        "recon_no_findings_claim": (
            "Vulnerability assessment NOT performed. No findings does NOT mean secure."
        ),
        "scan_completed": "Completed",
        "scan_partial": "Partial",
        "scan_failed": "Failed",
        "scan_denied": "Denied",
        "scan_error": "Error",
        "scan_skipped": "Skipped",
        "observed": "HTTP response observed; this is not a vulnerability verdict.",
        "body_sampled": "Body sample reached its size limit; content coverage is partial.",
        "invalid_targets": (
            "Provide 1 to 256 explicit HTTP/HTTPS URLs within the input size limits."
        ),
        "targets_io": "Cannot read the target list as bounded UTF-8 input.",
        "not_authorized": (
            "Network access requires explicit target authorization in the configuration."
        ),
        "passive_profile": "The passive profile does not permit network access.",
        "report_io": (
            "Cannot create report output, or output already exists. "
            "Existing data is not overwritten."
        ),
        "interrupted": "Interrupted. A complete report was not produced.",
        "timeout": "The operation exceeded its deadline; coverage is incomplete.",
        "dns_failed": "DNS resolution failed; connectivity is not established.",
        "network_failed": "Connection, TLS verification or HTTP exchange failed.",
        "redirect_loop": "A redirect loop was detected.",
        "redirect_limit": "The redirect limit was reached.",
        "https_downgrade": "HTTPS to HTTP downgrade was refused.",
        "invalid_response": "The HTTP response is malformed or ambiguous.",
        "encoding_denied": "Encoded response bodies are not decompressed.",
        "body_too_large": "The response exceeded the body limit.",
        "method_denied": "The HTTP method is not permitted by the profile.",
        "budget_exhausted": (
            "The shared request budget is exhausted; remaining work is not completed."
        ),
        "config_created": "Passive configuration created; network authorization is disabled.",
        "config_valid": "Configuration is valid. This does not authorize network access.",
        "invalid_config": "Invalid configuration; check the schema and field types.",
        "config_io": (
            "Cannot access configuration, or output already exists. No overwrite performed."
        ),
        "invalid_target": "Invalid target. Credentials and ambiguous addresses are rejected.",
        "unknown_profile": "Unknown profile. Choose passive or safe.",
        "allowed": "Target matches the offline scope policy.",
        "excluded": "Target is excluded by policy.",
        "not_allowlisted": "Target is not allowlisted.",
        "address_forbidden": "Address category is forbidden by policy.",
        "port_denied": "Port is not allowed.",
        "profiles_info": "Built-in policies only; no scanning is performed.",
        "offline_scope": "Offline decision only: DNS and connectivity have NOT been checked.",
        "doctor_title": "Environment doctor",
        "ready": "Required checks passed. Optional tools are not needed for M1A.",
        "not_ready": "Required checks failed. Follow the recommendations below.",
        "required": "required",
        "optional": "optional",
        "pass": "PASS",
        "warn": "WARN",
        "fail": "FAIL",
        "recommendation": "Recommendation",
        "python": "Python compatibility",
        "platform": "Operating system",
        "package": "Installed package",
        "git": "Git",
        "pipx": "pipx",
        "nmap": "Nmap",
        "nuclei": "Nuclei",
        "subfinder": "Subfinder",
        "config_dir": "Configuration directory",
        "filesystem": "Filesystem write capability",
        "python_details": "Python {version}; requires Python 3.12 or newer.",
        "python_fix": "Install Python 3.12+ and recreate the isolated environment.",
        "platform_details": "{system} ({release}, {machine}).",
        "platform_fix": (
            "Linux and Windows are the target platforms; verify other systems manually."
        ),
        "package_details": "Installed pasopati-recon {version}.",
        "package_missing": "Installed pasopati-recon metadata was not found.",
        "package_fix": "Install this checkout using pipx install . or python -m pip install -e .",
        "tool_found": "Available on PATH: {path}",
        "tool_missing": "Not found on PATH; not required to run M1A.",
        "git_fix": "Install Git if you need to clone or contribute to the source repository.",
        "pipx_fix": (
            "Optionally install pipx for isolated CLI installation and run pipx ensurepath."
        ),
        "integration_fix": (
            "Install {tool} separately only for a future integration; M1A never runs it."
        ),
        "config_exists": "Directory exists: {path}",
        "config_pending": "Directory does not exist: {path}; existing ancestor: {parent}.",
        "config_invalid": "Configuration path or an ancestor is not a directory: {path}",
        "config_error": "Cannot inspect configuration path: {path} ({error}).",
        "config_fix": (
            "Choose a user-owned directory with doctor --config-dir PATH; check permissions."
        ),
        "write_ok": "Created, wrote, and removed a temporary probe in {path}.",
        "write_error": "Temporary write probe failed in {path} ({error}).",
        "write_blocked": "Write probe skipped because the configuration path is invalid.",
        "installation_error": (
            "Package metadata is unavailable. Install PASOPATI in an isolated environment."
        ),
    },
    Language.ID: {
        "hint": "Mulai dengan: pasopati --help",
        "quick_start": "Panduan singkat",
        "quick_help": "Tampilkan perintah dan opsi",
        "quick_doctor": "Periksa kesiapan lingkungan lokal",
        "quick_json": "Dapatkan pemeriksaan lingkungan dalam JSON",
        "foundation": (
            "M2B: discovery bersumber eksplisit dan inventaris URL berizin; "
            "kebijakan offline tetap ada."
        ),
        "recon_title": "Inventaris DNS/HTTP",
        "discovery_title": "Kandidat subdomain dan observasi DNS",
        "discovery_domain": "Konteks domain",
        "discovery_attempts": "Unit percobaan logis terpakai (bukan paket DNS)",
        "discovery_counts": "Lookup RR DNS: {dns}; percobaan HTTP provider: {http}",
        "discovery_limitations": (
            "Kandidat bukan otorisasi atau bukti host hidup. Tanpa probing HTTP target."
        ),
        "provider_disclosure": "Query domain ke crt.sh dipilih dan diizinkan secara eksplisit.",
        "invalid_domain": "Berikan domain valid, bukan URL, IP, kredensial atau wildcard.",
        "invalid_discovery": "Pilih sumber eksplisit dan opsi input yang sesuai.",
        "invalid_candidates": (
            "Input kandidat invalid/terlalu besar; nama harus dalam batas domain."
        ),
        "candidates_io": "Input kandidat UTF-8 berbatas tidak dapat dibaca.",
        "provider_consent_required": (
            "crt.sh memerlukan --allow-provider-queries; domain dikirim ke pihak ketiga."
        ),
        "provider_invalid": (
            "Provider mengembalikan JSON rusak/tidak didukung; kandidat tidak direka."
        ),
        "provider_unavailable": "Provider tidak mengembalikan HTTP 200; tanpa retry otomatis.",
        "provider_invalid_rows": "Sebagian record provider rusak; koleksi parsial.",
        "candidate_limit": "Batas kandidat/input tercapai; koleksi parsial.",
        "source_complete": "Sumber terpilih diproses dalam batas yang dinyatakan.",
        "candidate_collected": "Kandidat belum diverifikasi; DNS/konektivitas belum diperiksa.",
        "wildcard_pattern": "Pola wildcard disimpan; bukan hostname konkret.",
        "dns_resolved": "Record alamat diamati; bukan bukti layanan aktif atau kepemilikan.",
        "dns_nxdomain": "Resolver mengembalikan NXDOMAIN saat pengumpulan.",
        "dns_no_address": "Record alamat A/AAAA tidak ditemukan; tipe record lain mungkin ada.",
        "dns_inconsistent": "Jawaban alamat dan NXDOMAIN tidak konsisten; validasi parsial.",
        "dns_wildcard_possible": (
            "DNS wildcard mungkin aktif; jangan anggap ini host unik terkonfirmasi."
        ),
        "dns_wildcard_unchecked": "Jawaban DNS diamati, tetapi pemeriksaan wildcard belum lengkap.",
        "recon_status": "Status proses",
        "recon_requests": "Percobaan request terpakai",
        "recon_limitations": (
            "Hanya URL eksplisit. Tanpa crawling/discovery subdomain. Path/query disamarkan."
        ),
        "recon_no_findings_claim": (
            "Penilaian kerentanan TIDAK dilakukan. Tanpa temuan BUKAN berarti aman."
        ),
        "scan_completed": "Selesai",
        "scan_partial": "Parsial",
        "scan_failed": "Gagal",
        "scan_denied": "Ditolak",
        "scan_error": "Kesalahan",
        "scan_skipped": "Dilewati",
        "observed": "Respons HTTP diamati; bukan penetapan kerentanan.",
        "body_sampled": "Sampel body mencapai batas ukuran; cakupan konten parsial.",
        "invalid_targets": (
            "Berikan 1 hingga 256 URL HTTP/HTTPS eksplisit dalam batas ukuran input."
        ),
        "targets_io": "Daftar target tidak dapat dibaca sebagai UTF-8 dalam batas ukuran.",
        "not_authorized": "Akses jaringan memerlukan otorisasi target eksplisit dalam konfigurasi.",
        "passive_profile": "Profil passive tidak mengizinkan akses jaringan.",
        "report_io": "Output laporan tidak dapat dibuat atau sudah ada. Data lama tidak ditimpa.",
        "interrupted": "Dihentikan. Laporan lengkap tidak dihasilkan.",
        "timeout": "Operasi melewati deadline; cakupan belum lengkap.",
        "dns_failed": "Resolusi DNS gagal; konektivitas belum terbukti.",
        "network_failed": "Koneksi, verifikasi TLS, atau pertukaran HTTP gagal.",
        "redirect_loop": "Loop redirect terdeteksi.",
        "redirect_limit": "Batas redirect tercapai.",
        "https_downgrade": "Penurunan HTTPS ke HTTP ditolak.",
        "invalid_response": "Respons HTTP rusak atau ambigu.",
        "encoding_denied": "Body respons terenkode tidak didekompresi.",
        "body_too_large": "Respons melebihi batas ukuran body.",
        "method_denied": "Metode HTTP tidak diizinkan oleh profil.",
        "budget_exhausted": "Anggaran request bersama habis; pekerjaan tersisa belum selesai.",
        "config_created": "Konfigurasi pasif dibuat; otorisasi jaringan dinonaktifkan.",
        "config_valid": "Konfigurasi valid. Ini tidak memberikan otorisasi akses jaringan.",
        "invalid_config": "Konfigurasi tidak valid; periksa schema dan tipe field.",
        "config_io": "Konfigurasi tidak dapat diakses atau berkas sudah ada. Tidak ditimpa.",
        "invalid_target": "Target tidak valid. Kredensial dan alamat ambigu ditolak.",
        "unknown_profile": "Profil tidak dikenal. Pilih passive atau safe.",
        "allowed": "Target cocok dengan kebijakan scope offline.",
        "excluded": "Target dikecualikan oleh kebijakan.",
        "not_allowlisted": "Target tidak terdaftar dalam allowlist.",
        "address_forbidden": "Kategori alamat ditolak oleh kebijakan.",
        "port_denied": "Port tidak diizinkan.",
        "profiles_info": "Hanya kebijakan bawaan; tidak menjalankan pemindaian.",
        "offline_scope": "Keputusan offline: DNS dan konektivitas BELUM diperiksa.",
        "doctor_title": "Pemeriksaan lingkungan",
        "ready": "Pemeriksaan wajib lulus. Alat opsional tidak diperlukan untuk M1A.",
        "not_ready": "Pemeriksaan wajib gagal. Ikuti rekomendasi di bawah.",
        "required": "wajib",
        "optional": "opsional",
        "pass": "LULUS",
        "warn": "PERINGATAN",
        "fail": "GAGAL",
        "recommendation": "Rekomendasi",
        "python": "Kompatibilitas Python",
        "platform": "Sistem operasi",
        "package": "Paket terpasang",
        "git": "Git",
        "pipx": "pipx",
        "nmap": "Nmap",
        "nuclei": "Nuclei",
        "subfinder": "Subfinder",
        "config_dir": "Direktori konfigurasi",
        "filesystem": "Kemampuan menulis berkas",
        "python_details": "Python {version}; memerlukan Python 3.12 atau lebih baru.",
        "python_fix": "Pasang Python 3.12+ dan buat ulang lingkungan terisolasi.",
        "platform_details": "{system} ({release}, {machine}).",
        "platform_fix": (
            "Linux dan Windows adalah platform target; verifikasi sistem lain secara manual."
        ),
        "package_details": "pasopati-recon {version} terpasang.",
        "package_missing": "Metadata pasopati-recon terpasang tidak ditemukan.",
        "package_fix": "Pasang proyek ini dengan pipx install . atau python -m pip install -e .",
        "tool_found": "Tersedia di PATH: {path}",
        "tool_missing": "Tidak ditemukan di PATH; tidak wajib untuk menjalankan M1A.",
        "git_fix": "Pasang Git jika ingin mengklon atau berkontribusi ke repositori sumber.",
        "pipx_fix": (
            "Opsional: pasang pipx untuk instalasi CLI terisolasi, lalu jalankan pipx ensurepath."
        ),
        "integration_fix": (
            "Pasang {tool} secara terpisah untuk integrasi mendatang; M1A tidak menjalankannya."
        ),
        "config_exists": "Direktori tersedia: {path}",
        "config_pending": "Direktori belum tersedia: {path}; direktori induk tersedia: {parent}.",
        "config_invalid": "Jalur konfigurasi atau induknya bukan direktori: {path}",
        "config_error": "Tidak dapat memeriksa jalur konfigurasi: {path} ({error}).",
        "config_fix": (
            "Pilih direktori milik pengguna dengan doctor --config-dir PATH; periksa izin akses."
        ),
        "write_ok": "Berkas uji sementara berhasil dibuat, ditulis, dan dihapus di {path}.",
        "write_error": "Uji tulis sementara gagal di {path} ({error}).",
        "write_blocked": "Uji tulis dilewati karena jalur konfigurasi tidak valid.",
        "installation_error": (
            "Metadata paket tidak tersedia. Pasang PASOPATI dalam lingkungan terisolasi."
        ),
    },
}


def tr(language: Language, key: str, **values: object) -> str:
    """Fail loudly for missing developer message keys, instead of hiding catalog bugs."""
    return MESSAGES[language][key].format(**values)
