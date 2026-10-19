"""Bounded metadata from an already verified TLS socket; no new connection or PEM export."""

import hashlib
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from pasopati.core.errors import PolicyError


@dataclass(frozen=True)
class TLSInfo:
    leaf_sha256: str
    not_before: str
    not_after: str
    protocol: str
    cipher: str
    cipher_bits: int
    san_dns_count: int
    san_ip_count: int
    san_other_count: int


def verified_metadata(connection: ssl.SSLSocket) -> TLSInfo:
    # A custom connector/context cannot turn an unverified handshake into verified evidence.
    if not connection.context.check_hostname or connection.context.verify_mode != ssl.CERT_REQUIRED:
        raise PolicyError("tls_metadata_unavailable")
    try:
        der = connection.getpeercert(binary_form=True)
        if not isinstance(der, bytes) or not 1 <= len(der) <= 65536:
            raise ValueError
        cert = connection.getpeercert()
        protocol, cipher = connection.version(), connection.cipher()
        if (
            not cert
            or protocol not in {"TLSv1.2", "TLSv1.3"}
            or cipher is None
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", cipher[0])
            or type(cipher[2]) is not int
            or not 1 <= cipher[2] <= 1024
        ):
            raise ValueError
        dates: list[str] = []
        for key in ("notBefore", "notAfter"):
            value = cert[key]
            if not isinstance(value, str) or len(value) > 64:
                raise ValueError
            dates.append(datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC).isoformat())
        names = cert.get("subjectAltName", ())
        if not isinstance(names, (tuple, list)) or len(names) > 4096:
            raise ValueError
        dns = ips = other = 0
        for entry in names:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise ValueError
            if entry[0] == "DNS":
                dns += 1
            elif entry[0] == "IP Address":
                ips += 1
            else:
                other += 1
        return TLSInfo(
            hashlib.sha256(der).hexdigest(),
            dates[0],
            dates[1],
            protocol,
            cipher[0],
            cipher[2],
            dns,
            ips,
            other,
        )
    except (ValueError, KeyError, TypeError, OverflowError, OSError) as exc:
        raise PolicyError("tls_metadata_unavailable") from exc
