"""Bounded OS-configured DNS. Negative answers are data, failures remain explicit."""

import ipaddress
import time
from dataclasses import dataclass
from typing import Literal

import dns.exception
import dns.resolver

from pasopati.core.errors import PolicyError
from pasopati.targets import Address, domain_rule

RecordType = Literal["A", "AAAA"]


@dataclass(frozen=True)
class DNSAnswer:
    status: Literal["answer", "nxdomain", "no_address"]
    addresses: tuple[Address, ...] = ()
    ttl: int | None = None


def configured_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    for server in resolver.nameservers:
        ipaddress.ip_address(str(server))
    if not resolver.nameservers:
        raise PolicyError("dns_failed")
    return resolver


class DNSResolver:
    """No hosts/search/mDNS/DoH/public fallback; absolute A/AAAA only."""

    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]:
        # Preserve the M1B interface and one shared A+AAAA lifetime for HTTP pinning.
        end = time.monotonic() + timeout
        try:
            resolver = configured_resolver()
            addresses: set[Address] = set()
            for kind in ("A", "AAAA"):
                left = end - time.monotonic()
                if left <= 0:
                    raise PolicyError("timeout")
                answer = resolver.resolve(
                    host + ".", kind, lifetime=left, search=False, raise_on_no_answer=False
                )
                addresses.update(ipaddress.ip_address(record.to_text()) for record in answer)
            if not addresses:
                raise PolicyError("dns_failed")
            return tuple(sorted(addresses, key=lambda a: (a.version, int(a))))
        except dns.exception.Timeout as exc:
            raise PolicyError("timeout") from exc
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            raise PolicyError("dns_failed") from exc

    def query(self, host: str, kind: RecordType, timeout: float) -> DNSAnswer:
        domain_rule(host)
        if kind not in {"A", "AAAA"} or timeout <= 0:
            raise PolicyError("invalid_target", 2)
        try:
            resolver = configured_resolver()
            answer = resolver.resolve(
                host + ".", kind, lifetime=timeout, search=False, raise_on_no_answer=False
            )
            addresses = tuple(
                sorted({ipaddress.ip_address(record.to_text()) for record in answer}, key=int)
            )
            if any(a.version != (4 if kind == "A" else 6) for a in addresses):
                raise PolicyError("dns_failed")
            ttl = answer.rrset.ttl if answer.rrset is not None else None
            return DNSAnswer("answer" if addresses else "no_address", addresses, ttl)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer("nxdomain")
        except dns.resolver.NoAnswer:
            return DNSAnswer("no_address")
        except dns.exception.Timeout as exc:
            raise PolicyError("timeout") from exc
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            raise PolicyError("dns_failed") from exc
