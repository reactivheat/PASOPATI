"""Fixed, versioned header observations. No bodies, raw header values or vulnerability rules."""

import re
from dataclasses import dataclass

from pasopati.redaction import header_summary

RULESET = "header-prefix/1"
WEB_HEADERS = ("Allow",)
DIRECTIVES = frozenset(
    {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "font-src",
        "connect-src",
        "media-src",
        "object-src",
        "frame-src",
        "child-src",
        "worker-src",
        "manifest-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
        "sandbox",
        "upgrade-insecure-requests",
        "report-uri",
        "report-to",
        "script-src-attr",
        "script-src-elem",
        "style-src-attr",
        "style-src-elem",
    }
)
METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
)


@dataclass(frozen=True)
class WebValue:
    kind: str
    value: str | int | bool | tuple[str, ...]
    confidence: str = "observed"


def web_observations(headers: dict[str, str], *, https: bool) -> tuple[WebValue, ...]:
    result: list[WebValue] = []
    for name in ("server", "x-powered-by"):
        value = headers.get(name)
        if value is not None and len(value) <= 8192:
            product = header_summary(name, value)
            if product != "present":
                result.extend(
                    (
                        WebValue("fingerprint." + name, product, "tentative"),
                        WebValue(
                            "fingerprint." + name + ".rule", RULESET + ":" + name + ":" + product
                        ),
                    )
                )
    hsts = headers.get("strict-transport-security")
    if hsts is not None:
        result.append(WebValue("hsts.received_over_https", https))
        tokens = hsts.split(";") if len(hsts) <= 8192 else []
        seen: dict[str, str | None] = {}
        valid = 1 <= len(tokens) <= 16
        for token in tokens[:16]:
            match = re.fullmatch(r"\s*([A-Za-z-]+)(?:\s*=\s*([0-9]{1,10}))?\s*", token)
            if match is None or match[1].lower() in seen:
                valid = False
                break
            seen[match[1].lower()] = match[2]
        valid = (
            valid
            and seen.get("max-age") is not None
            and all(seen.get(key) is None for key in ("includesubdomains", "preload"))
        )
        result.append(WebValue("hsts.syntax_supported", valid))
        if valid:
            result.extend(
                (
                    WebValue("hsts.max_age_seconds", int(seen["max-age"] or "0")),
                    WebValue("hsts.include_subdomains", "includesubdomains" in seen),
                    WebValue("hsts.preload_token", "preload" in seen),
                )
            )
    csp = headers.get("content-security-policy")
    if csp is not None:
        # Directive names only. Sources/nonces/hashes/URLs/report endpoints remain private.
        tokens = csp.split(";") if len(csp) <= 8192 else []
        supported = bool(tokens) and len(tokens) <= 64 and "," not in csp
        names = tuple(dict.fromkeys(t.split()[0].lower() for t in tokens[:64] if t.split()))
        result.append(WebValue("csp.directive_names_supported", supported))
        if supported:
            result.append(
                WebValue("csp.recognized_directives", tuple(n for n in names if n in DIRECTIVES))
            )
    allow = headers.get("allow")
    if allow is not None:
        allow_tokens = tuple(t.strip() for t in allow.split(",")) if len(allow) <= 8192 else ()
        supported = 1 <= len(allow_tokens) <= 32 and all(t in METHODS for t in allow_tokens)
        result.append(WebValue("http.allow_tokens_supported", supported))
        if supported:
            result.append(WebValue("http.advertised_methods", tuple(dict.fromkeys(allow_tokens))))
    return tuple(result)
