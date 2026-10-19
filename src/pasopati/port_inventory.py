"""Bounded explicit host/port inventory using shared scope, DNS, and logical limits."""

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import replace
from uuid import uuid4

from pasopati import get_version
from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.limits import Deadline, RequestBudget
from pasopati.profiles import get_profile
from pasopati.recon import (
    Asset,
    Evidence,
    Observation,
    Outcome,
    RunReport,
    TCPDetails,
    require_network,
    utc_now,
)
from pasopati.scope import Scope
from pasopati.scoped_dns import QueryResolver, ScopedDNS
from pasopati.targets import Address, Target, hostname
from pasopati.tcp import NumericTCPConnector, TCPConnector, connect_outcome

MAX_HOSTS = 64
MAX_PORTS = 64
MAX_PAIRS = 256
MAX_ADDRESSES = 16


def parse_ports(value: str) -> tuple[int, ...]:
    if len(value) > 512:
        raise PolicyError("invalid_ports", 2)
    entries = value.split(",")
    if not 1 <= len(entries) <= MAX_PORTS or any(
        not re.fullmatch(r"[1-9][0-9]{0,4}", p) or int(p) > 65535 for p in entries
    ):
        raise PolicyError("invalid_ports", 2)
    return tuple(dict.fromkeys(int(p) for p in entries))


def normalize_hosts(values: Iterable[str]) -> tuple[str, ...]:
    hosts: dict[str, None] = {}
    for count, value in enumerate(values, 1):
        if count > MAX_HOSTS or len(value) > 253:
            raise PolicyError("invalid_hosts", 2)
        try:
            hosts[hostname(value)] = None
        except PolicyError as exc:
            raise PolicyError("invalid_hosts", 2) from exc
    if not hosts:
        raise PolicyError("invalid_hosts", 2)
    return tuple(hosts)


def validate_inventory(config: Config, hosts: tuple[str, ...], ports: tuple[int, ...]) -> None:
    if (
        normalize_hosts(hosts) != hosts
        or not 1 <= len(ports) <= MAX_PORTS
        or len(set(ports)) != len(ports)
        or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
        or len(hosts) * len(ports) > MAX_PAIRS
    ):
        raise PolicyError("invalid_ports", 2)
    require_network(config)


def run_port_inventory(
    config: Config,
    hosts: tuple[str, ...],
    ports: tuple[int, ...],
    *,
    budget: RequestBudget | None = None,
    resolver: QueryResolver | None = None,
    connector: TCPConnector | None = None,
    timestamp: Callable[[], str] = utc_now,
) -> RunReport:
    validate_inventory(config, hosts, ports)
    profile, scope = get_profile(config.profile), Scope(config)
    budget = budget or RequestBudget(profile)
    if budget.profile != profile:
        raise PolicyError("invalid_config", 2)
    connector = connector or NumericTCPConnector()
    version, started = get_version(), timestamp()
    assets: list[Asset] = []
    dns_used = tcp_used = 0
    for host_number, host in enumerate(hosts, 1):
        eligible = {p: scope.target(Target(host, port=p)) for p in ports}
        base_evidence: tuple[Evidence, ...] = ()
        base_observations: tuple[Observation, ...] = ()
        addresses: tuple[Address, ...] = ()
        host_reason = "dns_failed"
        host_state = "error"
        if any(d.allowed for d in eligible.values()):
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                dns = ScopedDNS(
                    config, budget, host, version, resolver=resolver, timestamp=timestamp
                )
                lookup = dns.lookup(host, f"host-{host_number:03d}")
                dns_used += dns.queries_used
                base_evidence, base_observations = lookup.evidence, lookup.observations
                addresses, host_reason, host_state = lookup.addresses, lookup.reason, lookup.status
                if host_state != "resolved":
                    addresses = ()  # Fail closed on incomplete/mixed-family/denied answers.
            else:
                addresses, host_state = (address,), "resolved"
                base_evidence = (
                    Evidence(
                        f"host-{host_number:03d}-literal",
                        "ip_literal",
                        host,
                        None,
                        timestamp(),
                        "literal",
                        "PASOPATI",
                        version,
                        addresses=(str(address),),
                        subject_name=host,
                    ),
                )
            if len(addresses) > MAX_ADDRESSES:
                addresses, host_state, host_reason = (), "error", "tcp_address_limit"
        for port in ports:
            identifier = f"asset-{len(assets) + 1:04d}"
            # Clone only IDs: collection times/answers remain the actual shared DNS snapshot.
            ids = {e.id: f"{identifier}-dns-{n:02d}" for n, e in enumerate(base_evidence, 1)}
            evidence = [replace(e, id=ids[e.id]) for e in base_evidence]
            observations = [replace(o, evidence_id=ids[o.evidence_id]) for o in base_observations]
            outcome: Outcome = "completed"
            reason = "tcp_complete"
            decision = eligible[port]
            if not decision.allowed:
                # Do not attach DNS answers from other allowed ports to an unqueried endpoint.
                evidence, observations = [], []
                outcome, reason = "denied", decision.reason
            elif not addresses:
                outcome = "denied" if host_state == "denied" else "error"
                if host_reason == "budget_exhausted":
                    outcome = "skipped"
                reason = host_reason
            else:
                for address in addresses:
                    deadline = Deadline(
                        budget.clock.monotonic() + profile.total_timeout, budget.clock
                    )
                    try:
                        # Recheck before the numeric connection; never re-resolve here.
                        checked = scope.address(address)
                        if not checked.allowed:
                            raise PolicyError(checked.reason)
                        with budget.slot(deadline):
                            budget.reserve(deadline)
                            deadline.remaining(profile.connect_timeout)
                            eid = f"{identifier}-tcp-{len(evidence) + 1:03d}"
                            collected, before = timestamp(), budget.clock.monotonic()
                            tcp_used += 1
                            state, code = "open", None
                            phase = Deadline(
                                min(deadline.end, before + profile.connect_timeout), budget.clock
                            )
                            try:
                                connector.connect(address, port, phase, profile.connect_timeout)
                                phase.remaining()
                            except OSError as exc:
                                state, code = connect_outcome(exc)
                                if budget.clock.monotonic() >= phase.end:
                                    state = "deadline_exceeded"
                            except PolicyError as exc:
                                if exc.code != "timeout":
                                    raise
                                state = "deadline_exceeded"
                            evidence.append(
                                Evidence(
                                    eid,
                                    "tcp_connect",
                                    host,
                                    None,
                                    collected,
                                    "TCP connect",
                                    "PASOPATI",
                                    version,
                                    addresses=(str(address),),
                                    connected_address=str(address) if state == "open" else None,
                                    subject_name=host,
                                    port=port,
                                    transport="tcp",
                                )
                            )
                            observations.extend(
                                (
                                    Observation("tcp.state", state, eid),
                                    Observation(
                                        "tcp.duration_ms",
                                        max(0, round((budget.clock.monotonic() - before) * 1000)),
                                        eid,
                                    ),
                                )
                            )
                            if code is not None:
                                observations.append(Observation("tcp.os_error", code, eid))
                            if state not in {"open", "refused"}:
                                outcome, reason = "partial", "tcp_" + state
                    except PolicyError as exc:
                        reason = (
                            exc.code
                            if exc.code
                            in {"budget_exhausted", "timeout", "excluded", "address_forbidden"}
                            else "network_failed"
                        )
                        outcome = (
                            "partial"
                            if any(e.source == "tcp_connect" for e in evidence)
                            else "skipped"
                        )
                        break
            endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            assets.append(
                Asset(identifier, endpoint, outcome, reason, tuple(evidence), tuple(observations))
            )
    return RunReport(
        str(uuid4()),
        version,
        started,
        timestamp(),
        config.profile,
        budget.used,
        False,
        tuple(assets),
        tcp=TCPDetails(hosts, ports, dns_used, tcp_used, MAX_ADDRESSES),
    )
