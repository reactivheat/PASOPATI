"""Explicit-source candidate discovery; never upgrades candidates to HTTP targets."""

from collections.abc import Callable
from dataclasses import replace
from urllib.parse import urlencode
from uuid import uuid4

from pasopati import get_version
from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.discovery_sources import (
    MAX_CANDIDATES,
    Candidate,
    DiscoveryPlan,
    Source,
    base_domain,
    candidate_name,
    parse_crtsh,
)
from pasopati.limits import RequestBudget
from pasopati.profiles import get_profile
from pasopati.recon import (
    REASONS,
    Asset,
    DiscoveryDetails,
    Evidence,
    Observation,
    Outcome,
    RunReport,
    SourceStatus,
    require_network,
    utc_now,
)
from pasopati.redaction import report_url
from pasopati.scope import Scope
from pasopati.scoped_dns import QueryResolver, ScopedDNS
from pasopati.transport import Hop, Resolution, Session

CRTSH_ENDPOINT = "https://crt.sh/"


def validate_discovery(config: Config, plan: DiscoveryPlan) -> None:
    if (
        base_domain(plan.domain) != plan.domain
        or not plan.sources
        or len(set(plan.sources)) != len(plan.sources)
        or not all(isinstance(s, Source) for s in plan.sources)
        or type(plan.resolve) is not bool
        or type(plan.allow_provider_queries) is not bool
        or len(plan.candidates) > MAX_CANDIDATES * len(plan.sources)
        or len({c.name for c in plan.candidates}) > MAX_CANDIDATES
    ):
        raise PolicyError("invalid_discovery", 2)
    for candidate in plan.candidates:
        if candidate_name(candidate.name, plan.domain) != candidate.name:
            raise PolicyError("invalid_candidates", 2)
    if Source.CRTSH in plan.sources and not plan.allow_provider_queries:
        raise PolicyError("provider_consent_required", 2)
    if plan.resolve or Source.CRTSH in plan.sources:
        require_network(config)
        decision = Scope(config).check(plan.domain)
        if not decision.allowed:
            raise PolicyError(decision.reason)


def provider_config(config: Config) -> Config:
    """Narrow, separate provider destination policy; never widen the target allowlist."""
    return Config(
        profile=config.profile,
        authorized=config.authorized,
        scope=ScopeConfig(
            allow_domains=("crt.sh",),
            ports=(443,),
            exclude_domains=config.scope.exclude_domains,
            exclude_cidrs=config.scope.exclude_cidrs,
        ),
    )


def run_discovery(
    config: Config,
    plan: DiscoveryPlan,
    *,
    budget: RequestBudget | None = None,
    resolver: QueryResolver | None = None,
    provider_session: Session | None = None,
    timestamp: Callable[[], str] = utc_now,
    token: Callable[[], str] = lambda: uuid4().hex,
) -> RunReport:
    validate_discovery(config, plan)
    version, started = get_version(), timestamp()
    budget = budget or RequestBudget(get_profile(config.profile))
    if budget.profile != get_profile(config.profile):
        raise PolicyError("invalid_config", 2)
    candidates = list(plan.candidates)
    sources = list(plan.source_status)
    provider_evidence: list[Evidence] = []
    provider_attempts = 0
    if Source.CRTSH in plan.sources:
        expected = provider_config(config)
        session = provider_session or Session(expected, budget=budget)
        if session.config != expected or session.budget is not budget:
            raise PolicyError("invalid_config", 2)

        def provider_event(event: Resolution | Hop) -> None:
            item = Evidence(
                f"provider-{len(provider_evidence) + 1:03d}",
                "provider_dns",
                plan.domain,
                report_url(event.url),
                timestamp(),
                "DNS A+AAAA",
                "PASOPATI",
                version,
            )
            if isinstance(event, Resolution):
                item = replace(
                    item,
                    addresses=event.addresses,
                    source="provider_dns" if event.dns_performed else "provider_literal",
                    method="DNS A+AAAA" if event.dns_performed else "literal",
                )
            else:
                item = replace(
                    item,
                    source="provider_http",
                    method="GET",
                    addresses=event.resolved_addresses,
                    connected_address=event.connected_address,
                    http_status=event.status,
                )
            provider_evidence.append(item)

        before = budget.used
        try:
            query = urlencode({"q": f"%.{plan.domain}", "output": "json"})
            response = session.fetch(f"{CRTSH_ENDPOINT}?{query}", observe=provider_event)
            if response.status != 200:
                raise PolicyError("provider_unavailable")
            fetched, status = parse_crtsh(response.body, plan.domain)
            existing = {c.name for c in candidates}
            retained: list[Candidate] = []
            for candidate in fetched:
                if candidate.name not in existing and len(existing) >= MAX_CANDIDATES:
                    status = replace(status, status="partial", reason="candidate_limit")
                    continue
                existing.add(candidate.name)
                retained.append(candidate)
            candidates.extend(retained)
            sources.append(replace(status, candidates=len({c.name for c in retained})))
        except PolicyError as exc:
            code = (
                exc.code
                if exc.code in REASONS | {"provider_invalid", "provider_unavailable"}
                else "provider_invalid"
            )
            sources.append(SourceStatus(Source.CRTSH.value, "error", code))
        provider_attempts = budget.used - before
    grouped: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.name, []).append(candidate)
    dns_client = (
        ScopedDNS(
            config,
            budget,
            plan.domain,
            version,
            resolver=resolver,
            timestamp=timestamp,
            token=token,
        )
        if plan.resolve
        else None
    )
    scope = Scope(config)
    assets: list[Asset] = []
    for index, (name, origins) in enumerate(grouped.items(), 1):
        identifier = f"asset-{index:04d}"
        evidence: list[Evidence] = []
        observations: list[Observation] = []
        for number, origin in enumerate(origins, 1):
            eid = f"{identifier}-s{number:02d}"
            evidence.append(
                Evidence(
                    eid,
                    origin.source,
                    plan.domain,
                    None,
                    timestamp(),
                    "CT import" if origin.source == Source.CRTSH else "local import",
                    "PASOPATI",
                    version,
                    confidence="tentative",
                    subject_name=name,
                )
            )
            observations.append(Observation("discovery.source_reference", origin.reference, eid))
        pattern = name.startswith("*.")
        allowed = None if pattern else scope.check(name).allowed
        observations.extend(
            [
                Observation("discovery.candidate", True, evidence[0].id, "tentative"),
                Observation("discovery.wildcard_pattern", pattern, evidence[0].id),
                Observation("scope.allowed", allowed, evidence[0].id),
            ]
        )
        state: Outcome = "completed"
        reason = "wildcard_pattern" if pattern else "candidate_collected"
        if dns_client is not None and not pattern:
            if not allowed:
                state, reason = "denied", scope.check(name).reason
            else:
                wildcard = (
                    dns_client.wildcard(name.split(".", 1)[1]) if name != plan.domain else None
                )
                lookup = dns_client.lookup(name, identifier)
                evidence.extend(lookup.evidence)
                observations.extend(lookup.observations)
                reason = lookup.reason
                eid = lookup.evidence[-1].id if lookup.evidence else evidence[0].id
                observations.append(Observation("dns.validation", lookup.status, eid))
                observations.append(
                    Observation("dns.addresses", tuple(str(a) for a in lookup.addresses), eid)
                )
                if lookup.status == "resolved" and wildcard is not None:
                    observations.append(Observation("dns.wildcard_check", wildcard.status, eid))
                    if wildcard.status != "clear":
                        reason = (
                            "dns_wildcard_possible"
                            if wildcard.status == "possible"
                            else "dns_wildcard_unchecked"
                        )
                        observations.append(
                            Observation("dns.hostname_confidence", "tentative", eid, "tentative")
                        )
                        if wildcard.status != "possible":
                            state = "partial"
                if lookup.status == "denied":
                    state = "denied"
                elif lookup.status == "error":
                    state = (
                        "skipped"
                        if reason == "budget_exhausted" and not lookup.evidence
                        else "partial"
                    )
        else:
            observations.append(Observation("dns.validation", "not_checked", evidence[0].id))
        assets.append(Asset(identifier, name, state, reason, tuple(evidence), tuple(observations)))
    details = DiscoveryDetails(
        plan.domain,
        tuple(sources),
        plan.resolve,
        Source.CRTSH in plan.sources and plan.allow_provider_queries,
        dns_client.queries_used if dns_client else 0,
        provider_attempts,
        tuple(provider_evidence),
        tuple(dns_client.checks.values()) if dns_client else (),
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
        details,
    )
