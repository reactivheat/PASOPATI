"""ASCII-only branding with a compact layout for narrow terminals."""

from rich.console import Console

from pasopati.i18n import Language, tr

DESCRIPTION = "Reconnaissance & Exposure Analysis Framework"
BANNER = r"""
 ____   _    ____   ___  ____   _  _____ ___
|  _ \ / \  / ___| / _ \|  _ \ / \|_   _|_ _|
| |_) / _ \ \___ \| | | | |_) / _ \ | |  | |
|  __/ ___ \ ___) | |_| |  __/ ___ \| |  | |
|_| /_/   \_\____/ \___/|_| /_/   \_\_| |___|
""".strip("\n")


def render_banner(console: Console, version: str, language: Language) -> None:
    """Use ordinary ASCII and let Rich manage wrapping and terminal capabilities."""
    if console.width >= max(map(len, BANNER.splitlines())):
        console.print(BANNER, style="bold cyan", markup=False, highlight=False)
    console.print(f"--> PASOPATI  v{version}", style="cyan", markup=False, highlight=False)
    console.print(DESCRIPTION, style="dim", markup=False, highlight=False)
    console.print(tr(language, "hint"), style="dim", markup=False, highlight=False)
