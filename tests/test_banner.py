from io import StringIO

import pytest
from rich.console import Console

from pasopati.branding import BANNER, render_banner
from pasopati.i18n import Language


@pytest.mark.parametrize("width", [20, 40, 80, 120])
def test_banner_widths(width: int) -> None:
    output = StringIO()
    console = Console(file=output, width=width, force_terminal=False)
    render_banner(console, "0.1.0", Language.EN)
    text = output.getvalue()
    assert "PASOPATI" in text
    assert "0.1.0" in text
    assert text.isascii()
    assert "\x1b" not in text
    assert all(len(line) <= width for line in text.splitlines())
    assert (BANNER in text) == (width >= max(map(len, BANNER.splitlines())))


def test_color_on_interactive_terminal() -> None:
    output = StringIO()
    render_banner(
        Console(file=output, width=100, force_terminal=True, color_system="standard"),
        "0.1.0",
        Language.ID,
    )
    assert "\x1b[" in output.getvalue()
    assert "Mulai dengan" in output.getvalue()
