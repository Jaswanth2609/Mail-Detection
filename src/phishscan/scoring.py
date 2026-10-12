"""Scoring and evaluation engine for PhishScan (FR-S1, FR-S2, FR-S3, NFR-2, NFR-8)."""

from __future__ import annotations

from typing import Any

from phishscan.checks.attachments import check_attachments
from phishscan.checks.body import check_body
from phishscan.checks.headers import check_headers
from phishscan.checks.links import check_links
from phishscan.models import AnalysisResult, Finding, ParsedEmail


def calculate_severity(score: int, bands: dict[str, Any]) -> str:
    """Map numerical score (0-100) to severity category using config bands."""
    low_max = bands.get("low_max", 24)
    med_max = bands.get("medium_max", 49)
    high_max = bands.get("high_max", 74)

    if score <= low_max:
        return "Low"
    elif score <= med_max:
        return "Medium"
    elif score <= high_max:
        return "High"
    else:
        return "Critical"


def evaluate_email(parsed_email: ParsedEmail, config: dict[str, Any]) -> AnalysisResult:
    """
    Executes all check modules and aggregates findings into a final score and severity.
    
    FR-S1: Assign weights defined in config.
    FR-S2: Sum weights capped at 100, respecting auth fail cap (max 30).
    FR-S3: Map final score to severity band.
    NFR-2: Fault isolation - failed checks are recorded in skipped_checks without halting.
    NFR-8: Deterministic evaluation.
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

    # Calculate weighted score
    weights_cfg = config.get("weights", {})
    auth_max = weights_cfg.get("auth_failure_max", 30)

    auth_rules = {"HDR_AUTH_MISSING", "HDR_SPF_FAIL", "HDR_DKIM_FAIL", "HDR_DMARC_FAIL"}
    auth_score = 0
    other_score = 0

    for finding in all_findings:
        if finding.rule_id in auth_rules:
            auth_score += finding.weight
        else:
            other_score += finding.weight

    # Cap authentication failures at auth_failure_max
    capped_auth_score = min(auth_score, auth_max)
    total_raw_score = capped_auth_score + other_score

    # FR-S2: Rule score capped at 100
    final_score = min(max(total_raw_score, 0), 100)

    # FR-S3: Map to severity
    severity_bands = config.get("severity_bands", {})
    severity = calculate_severity(final_score, severity_bands)

    # Create summary metadata
    summary = {
        "subject": parsed_email.subject,
        "from": parsed_email.from_header,
        "sender_address": parsed_email.from_address,
        "sender_domain": parsed_email.from_domain,
        "reply_to": parsed_email.reply_to_address,
        "date": parsed_email.date,
        "message_id": parsed_email.message_id,
        "total_links": len(parsed_email.links),
        "total_attachments": len(parsed_email.attachments),
        "total_findings": len(all_findings),
    }

    return AnalysisResult(
        file_path=parsed_email.file_path,
        score=final_score,
        severity=severity,
        findings=all_findings,
        skipped_checks=skipped_checks,
        summary=summary,
    )
