"""Conservative reporting boundaries. Never serialize raw URLs, headers or bodies."""

import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from pasopati.core.errors import PolicyError
from pasopati.targets import parse_target


def report_url(value: str) -> str:
    """Keep only a validated origin; every non-root path and query is withheld."""
    try:
        target = parse_target(value, require_url=True)
    except PolicyError:
        return "[invalid-url]"
    parts = urlsplit(target.url)
    path = "/" if parts.path == "/" else "/[path-redacted]"
    query = "?[redacted]" if parts.query else ""
    return f"{target.scheme}://{target.authority}{path}{query}"


def media_type(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.split(";", 1)[0].strip().lower()
    known = {
        "text/html",
        "application/xhtml+xml",
        "application/json",
        "application/xml",
        "text/xml",
        "text/plain",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/octet-stream",
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/svg+xml",
        "image/webp",
        "image/x-icon",
        "image/avif",
    }
    return candidate if candidate in known else None


def header_summary(name: str, value: str) -> str:
    """No arbitrary header values: fixed tokens, recognized product, or presence only."""
    lowered = value.strip().lower()
    if name == "content-type":
        return media_type(value) or "present"
    choices = {
        "x-content-type-options": {"nosniff"},
        "x-frame-options": {"deny", "sameorigin"},
        "referrer-policy": {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        },
    }
    if name in choices:
        return lowered if lowered in choices[name] else "present"
    if name in {"server", "x-powered-by"}:
        for product in (
            "nginx",
            "apache",
            "caddy",
            "microsoft-iis",
            "openresty",
            "gunicorn",
            "uvicorn",
            "express",
            "php",
            "asp.net",
        ):
            if re.match(re.escape(product) + r"(?:[/\s;]|$)", lowered):
                return product  # Candidate only; deliberately do not report a version/CVE.
    return "present"


class _Title(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inside = False
        self.finished = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title" and not self.finished:
            self.inside = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self.inside:
            self.inside, self.finished = False, True

    def handle_data(self, data: str) -> None:
        if self.inside:
            self.parts.append(data)


def page_title(body: bytes, content_type: str | None, urls: tuple[str, ...]) -> str | None:
    """Opt-in UTF-8 title sample; heuristic redaction is NOT a secrecy guarantee."""
    if media_type(content_type) not in {"text/html", "application/xhtml+xml"}:
        return None
    parser = _Title()
    parser.feed(body.decode("utf-8", errors="replace"))
    # Do not infer a title from an unclosed/truncated title element.
    if not parser.finished:
        return None
    title = " ".join("".join(parser.parts).split())
    title = "".join(c for c in title if not unicodedata.category(c).startswith("C"))
    # Bound pattern matching work too, not only network input/output sizes.
    title = title[:512]
    for url in urls:
        parts = urlsplit(url)
        # Withhold titles reflecting any request path/query fragment, even if mundane.
        for token in re.split(r"[/&=;?]", unquote(parts.path + "?" + parts.query)):
            if token and token.casefold() in title.casefold():
                return "[redacted]"
    if re.search(
        r"(?i)(?:token|secret|password|passwd|session|api.?key|bearer|authorization)"
        r"|[\w.+-]+@[\w.-]+\.[a-z]{2,}|https?://|[a-z0-9_+/=-]{24,}",
        title,
    ):
        return "[redacted]"
    return title[:200] or None
