"""Lightweight source identifiers, safe to import from the offline CLI root."""

from enum import StrEnum


class Source(StrEnum):
    FILE = "file"
    WORDLIST = "wordlist"
    CRTSH = "crtsh"
