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
        "foundation": "M1A foundation: local diagnostics only. Scanning is planned.",
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
        "foundation": "Fondasi M1A: hanya diagnostik lokal. Pemindaian masih direncanakan.",
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
