"""Scope-checked DNS validation and bounded per-parent wildcard observations."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.dns_client import DNSAnswer, DNSResolver, RecordType
from pasopati.limits import Deadline, RequestBudget
from pasopati.profiles import get_profile
from pasopati.recon import Evidence, Observation, WildcardCheck, require_network, utc_now
from pasopati.scope import Scope
from pasopati.targets import Address, hostname

MAX_WILDCARD_PARENTS = 4


class QueryResolver(Protocol):
    def query(self, host: str, kind: RecordType, timeout: float) -> DNSAnswer: ...


@dataclass(frozen=True)
class Lookup:
    status: str
    reason: str
    addresses: tuple[Address, ...]
    evidence: tuple[Evidence, ...]
    observations: tuple[Observation, ...]


class ScopedDNS:
    def __init__(
        self,
        config: Config,
        budget: RequestBudget,
        domain: str,
        version: str,
        *,
        resolver: QueryResolver | None = None,
        timestamp: Callable[[], str] = utc_now,
        token: Callable[[], str] = lambda: uuid4().hex,
    ) -> None:
        require_network(config)
        if budget.profile != get_profile(config.profile):
            raise PolicyError("invalid_config", 2)
        self.scope = Scope(config)
        self.budget = budget
        self.domain = domain
        self.version = version
        self.resolver = resolver or DNSResolver()
        self.timestamp = timestamp
        self.token = token
        self.queries_used = 0
        self.checks: dict[str, WildcardCheck] = {}
        self._parents_probed = 0

    def lookup(self, name: str, identifier: str) -> Lookup:
        decision = self.scope.check(name)
        if not decision.allowed:
            return Lookup("denied", decision.reason, (), (), ())
        profile, clock = self.budget.profile, self.budget.clock
        deadline = Deadline(clock.monotonic() + profile.total_timeout, clock)
        addresses: set[Address] = set()
        evidence: list[Evidence] = []
        observations: list[Observation] = []
        status, reason = "no_address", "dns_no_address"
        try:
            with self.budget.slot(deadline):
                for kind in ("A", "AAAA"):
                    self.budget.reserve(deadline)
                    self.queries_used += 1
                    eid = f"{identifier}-q{len(evidence) + 1:02d}"
                    collected = self.timestamp()
                    try:
                        answer = self.resolver.query(
                            name, kind, deadline.remaining(profile.connect_timeout)
                        )
                        deadline.remaining()
                    except (PolicyError, OSError) as exc:
                        code = exc.code if isinstance(exc, PolicyError) else "dns_failed"
                        if isinstance(exc, TimeoutError):
                            code = "timeout"
                        code = code if code in {"timeout", "dns_failed"} else "dns_failed"
                        evidence.append(
                            Evidence(
                                eid,
                                "dns_query_attempt",
                                self.domain,
                                None,
                                collected,
                                f"DNS {kind}",
                                "PASOPATI",
                                self.version,
                                query_name=name,
                                query_type=kind,
                            )
                        )
                        observations.append(Observation(f"dns.{kind.lower()}.outcome", code, eid))
                        return Lookup(
                            "error", code, tuple(addresses), tuple(evidence), tuple(observations)
                        )
                    evidence.append(
                        Evidence(
                            eid,
                            "dns_response",
                            self.domain,
                            None,
                            collected,
                            f"DNS {kind}",
                            "PASOPATI",
                            self.version,
                            addresses=tuple(str(a) for a in answer.addresses),
                            query_name=name,
                            query_type=kind,
                        )
                    )
                    observations.append(
                        Observation(f"dns.{kind.lower()}.outcome", answer.status, eid)
                    )
                    if answer.ttl is not None:
                        observations.append(Observation(f"dns.{kind.lower()}.ttl", answer.ttl, eid))
                    if answer.status == "nxdomain":
                        if addresses:
                            status, reason = "error", "dns_inconsistent"
                        else:
                            status, reason = "nxdomain", "dns_nxdomain"
                        break
                    addresses.update(answer.addresses)
                    for address in answer.addresses:
                        allowed = self.scope.address(address)
                        if not allowed.allowed:
                            return Lookup(
                                "denied",
                                allowed.reason,
                                tuple(addresses),
                                tuple(evidence),
                                tuple(observations),
                            )
                    if addresses:
                        status, reason = "resolved", "dns_resolved"
        except PolicyError as exc:
            reason = exc.code if exc.code in {"timeout", "budget_exhausted"} else "dns_failed"
            status = "error"
        return Lookup(
            status,
            reason,
            tuple(sorted(addresses, key=lambda a: (a.version, int(a)))),
            tuple(evidence),
            tuple(observations),
        )

    def wildcard(self, parent: str) -> WildcardCheck:
        if parent in self.checks:
            return self.checks[parent]
        if self._parents_probed >= MAX_WILDCARD_PARENTS:
            check = WildcardCheck(parent, "not_checked_limit")
            self.checks[parent] = check
            return check
        try:
            names = tuple(hostname(f"pasopati-{self.token()}.{parent}") for _ in range(3))
        except PolicyError:
            check = WildcardCheck(parent, "not_checked_length")
            self.checks[parent] = check
            return check
        if len(set(names)) != 3 or not all(self.scope.check(n).allowed for n in names):
            check = WildcardCheck(parent, "not_checked_scope")
            self.checks[parent] = check
            return check
        self._parents_probed += 1
        results = tuple(
            self.lookup(name, f"wildcard-{self._parents_probed:02d}-{n}")
            for n, name in enumerate(names, 1)
        )
        status = "clear"
        if any(r.status == "resolved" for r in results):
            status = "possible"
        elif any(r.status not in {"nxdomain", "no_address"} for r in results):
            status = "inconclusive"
        check = WildcardCheck(
            parent,
            status,
            tuple(e for r in results for e in r.evidence),
            tuple(o for r in results for o in r.observations),
        )
        self.checks[parent] = check
        return check
