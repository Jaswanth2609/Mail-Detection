"""Scoring engine and pipeline evaluation for PhishScan (FR-S1, FR-S2, FR-S3, FR-M5)."""
from __future__ import annotations

from typing import Any

from phishscan.checks.attachments import check_attachments
from phishscan.checks.body import check_body
from phishscan.checks.headers import check_headers
from phishscan.checks.links import check_links
from phishscan.intel import ThreatIntelCache, enrich_threat_intel
from phishscan.llm import blend_scores, query_llm_review, should_request_llm_review
from phishscan.models import AnalysisResult, Finding, IOCs, LLMResult, ParsedEmail


def calculate_severity(score: int, bands: dict[str, Any]) -> str:
    """FR-S2: Map numerical score (0-100) to severity category using config bands."""
    low_max = bands.get("low_max", 24)
    med_max = bands.get("medium_max", 49)
    high_max = bands.get("high_max", 74)

    if score <= low_max:
        return "Low"
    elif score <= med_max:
        return "Medium"
    elif score <= high_max:
        return "High"
    return "Critical"


def extract_iocs(parsed: ParsedEmail) -> IOCs:
    """FR-R3: Extract all unique IOCs (URLs, domains, and attachment hashes)."""
    urls: list[str] = []
    domains: set[str] = set()
    hashes: list[str] = []

    # Sender domains
    for d in (parsed.from_domain, parsed.reply_to_domain, parsed.return_path_domain):
        if d:
            domains.add(d.lower())

    # Links
    for link in parsed.links:
        if link.url and link.url not in urls:
            urls.append(link.url)
        if link.href_domain:
            domains.add(link.href_domain.lower())
        if link.anchor_domain:
            domains.add(link.anchor_domain.lower())

    # Attachment hashes
    for att in parsed.attachments:
        if att.sha256 and att.sha256 not in hashes:
            hashes.append(att.sha256)

    return IOCs(urls=urls, domains=sorted(domains), hashes=hashes)


def evaluate_email(
    parsed_email: ParsedEmail,
    config: dict[str, Any],
    no_llm: bool = False,
    offline: bool = False,
    cache: ThreatIntelCache | None = None,
) -> AnalysisResult:
    """
    Execute check modules, threat intel, and optional LLM review to generate AnalysisResult.
    """
    all_findings: list[Finding] = []
    skipped_checks: list[str] = []

    check_modules = [
        ("Header checks", check_headers),
        ("Body checks", check_body),
        ("Link checks", check_links),
        ("Attachment checks", check_attachments),
    ]

    for check_name, check_fn in check_modules:
        try:
            findings = check_fn(parsed_email, config)
            all_findings.extend(findings)
        except Exception as err:
            skipped_checks.append(f"{check_name}: {err}")

    # Threat intelligence lookups
    try:
        ti_findings, ti_skipped = enrich_threat_intel(
            parsed_email, config, offline=offline, cache=cache
        )
        all_findings.extend(ti_findings)
        skipped_checks.extend(ti_skipped)
    except Exception as err:
        skipped_checks.append(f"Threat intelligence lookup: {err}")

    # FR-S1: Sum weights capped at 100 with auth failure cap
    weights_cfg = config.get("weights", {})
    auth_max = weights_cfg.get("auth_failure_max", 30)

    auth_rules = {"HDR_AUTH_MISSING", "HDR_SPF_FAIL", "HDR_DKIM_FAIL", "HDR_DMARC_FAIL"}
    auth_score = 0
    other_score = 0

    for f in all_findings:
        if f.rule_id in auth_rules:
            auth_score += f.weight
        else:
            other_score += f.weight

    capped_auth = min(auth_score, auth_max)
    total_rule_score = capped_auth + other_score
    rule_score = min(max(total_rule_score, 0), 100)

    severity_bands = config.get("severity_bands", {})
    is_rule_critical = (
        calculate_severity(rule_score, severity_bands) == "Critical" or rule_score >= 75
    )

    # FR-M1 to FR-M6: LLM Review
    llm_result: LLMResult | None = None
    should_call_llm, llm_skip_reason = should_request_llm_review(
        rule_score, config, no_llm=no_llm, offline=offline
    )

    if should_call_llm:
        try:
            llm_result = query_llm_review(parsed_email, all_findings)
            if llm_result is None:
                skipped_checks.append("LLM review (provider API error, invalid JSON, or timeout)")
        except Exception as err:
            skipped_checks.append(f"LLM review: {err}")
    elif llm_skip_reason and not (
        "outside gray zone" in llm_skip_reason
    ):
        skipped_checks.append(llm_skip_reason)

    # Score blending
    final_score = blend_scores(rule_score, llm_result, is_rule_critical=is_rule_critical)
    severity = calculate_severity(final_score, severity_bands)
    iocs = extract_iocs(parsed_email)

    return AnalysisResult(
        file=parsed_email.file_path,
        rule_score=rule_score,
        llm=llm_result,
        final_score=final_score,
        severity=severity,
        findings=all_findings,
        iocs=iocs,
        skipped=skipped_checks,
    )
