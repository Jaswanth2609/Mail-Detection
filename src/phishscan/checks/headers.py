"""Header checks — FR-H1, FR-H2, FR-H3, FR-H4."""
from __future__ import annotations

import email.utils
import re
from typing import Any

from phishscan.models import Finding, ParsedEmail

_FAIL_STATUSES = {"fail", "softfail", "permerror", "temperror"}
_FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "proton.me", "protonmail.com", "zoho.com", "gmx.com",
}


def _auth_statuses(headers: dict[str, list[str]]) -> dict[str, str]:
    statuses = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    auth_lines = headers.get("authentication-results", []) + headers.get("received-spf", [])
    text = " ; ".join(auth_lines).lower()
    if not text.strip():
        return statuses

    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{proto}=([a-z]+)", text)
        if m:
            statuses[proto] = m.group(1)

    if statuses["spf"] == "missing" and headers.get("received-spf"):
        first_token = headers["received-spf"][0].strip().lower().split()[0].rstrip(";:()")
        if first_token in {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}:
            statuses["spf"] = first_token
    return statuses


def _check_received_chain(received: list[str]) -> list[str]:
    """FR-H4: Detect anomalies in the Received header chain."""
    anomalies: list[str] = []
    if not received:
        return anomalies

    timestamps: list[float] = []
    for line in received:
        if ";" in line:
            date_str = line.rsplit(";", 1)[-1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(date_str)
                timestamps.append(dt.timestamp())
            except Exception:
                continue

    # In RFC 5322, Received headers are prepended, so the first header is the most recent hop.
    # Therefore, timestamps should be non-increasing from top to bottom.
    for i in range(len(timestamps) - 1):
        # Allow small clock skew (up to 300 seconds)
        if timestamps[i] < timestamps[i + 1] - 300:
            anomalies.append("Out-of-order timestamps in Received chain (possible header tampering)")
            break
    return anomalies


def check_headers(parsed: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """Execute header checks against parsed email."""
    findings: list[Finding] = []
    weights = config.get("weights", {})
    auth_w = weights.get("auth_failure", 15)
    mismatch_w = weights.get("domain_mismatch", 15)
    spoof_w = weights.get("display_name_spoofing", 20)
    received_w = weights.get("received_anomaly", 10)

    # FR-H1: SPF, DKIM, DMARC authentication
    auth = _auth_statuses(parsed.headers)
    if all(v == "missing" for v in auth.values()):
        findings.append(
            Finding(
                rule_id="HDR_AUTH_MISSING",
                category="Header",
                title="Missing email authentication",
                description="No SPF, DKIM, or DMARC authentication results found in headers.",
                weight=auth_w,
            )
        )
    else:
        for proto, rule_id, label in [
            ("spf", "HDR_SPF_FAIL", "SPF"),
            ("dkim", "HDR_DKIM_FAIL", "DKIM"),
            ("dmarc", "HDR_DMARC_FAIL", "DMARC"),
        ]:
            if auth[proto] in _FAIL_STATUSES:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="Header",
                        title=f"{label} authentication failed",
                        description=f"{label} verification returned '{auth[proto]}'.",
                        weight=auth_w,
                    )
                )

    # FR-H2: Sender domain mismatch
    fd = parsed.from_domain.lower()
    mismatches: list[str] = []
    if fd:
        if parsed.reply_to_domain and parsed.reply_to_domain.lower() != fd:
            mismatches.append(f"Reply-To '{parsed.reply_to_domain}' != From '{fd}'")
        if parsed.return_path_domain and parsed.return_path_domain.lower() != fd:
            mismatches.append(f"Return-Path '{parsed.return_path_domain}' != From '{fd}'")
    if mismatches:
        findings.append(
            Finding(
                rule_id="HDR_DOMAIN_MISMATCH",
                category="Header",
                title="Sender domain mismatch",
                description="; ".join(mismatches),
                weight=mismatch_w,
            )
        )

    # FR-H3: Display-name spoofing
    dn = parsed.from_display_name.strip()
    if dn and fd:
        dn_lower = dn.lower()
        matched_brand = False
        for brand in config.get("brands", {}).get("popular", []):
            brand_name = brand.get("name", "").lower()
            allowed = [d.lower() for d in brand.get("domains", [])]
            if re.search(rf"\b{re.escape(brand_name)}\b", dn_lower):
                if not any(fd == d or fd.endswith("." + d) for d in allowed):
                    findings.append(
                        Finding(
                            rule_id="HDR_DISPLAY_SPOOF_BRAND",
                            category="Header",
                            title="Display-name brand spoofing",
                            description=f"Display name '{dn}' claims brand '{brand.get('name')}' but domain is '{fd}'.",
                            weight=spoof_w,
                        )
                    )
                matched_brand = True
                break

        if not matched_brand:
            for role in config.get("brands", {}).get("roles", []):
                if re.search(rf"\b{re.escape(role.lower())}\b", dn_lower):
                    if fd in _FREE_MAIL_PROVIDERS:
                        findings.append(
                            Finding(
                                rule_id="HDR_DISPLAY_SPOOF_ROLE",
                                category="Header",
                                title="Display-name role spoofing",
                                description=f"Display name '{dn}' uses organizational role '{role}' from free webmail '{fd}'.",
                                weight=spoof_w,
                            )
                        )
                    break

    # FR-H4: Received chain anomalies
    # Only flag if there are anomalies and headers exist
    if parsed.headers:
        received_anomalies = _check_received_chain(parsed.received_chain)
        if received_anomalies:
            findings.append(
                Finding(
                    rule_id="HDR_RECEIVED_ANOMALY",
                    category="Header",
                    title="Received chain anomaly",
                    description="; ".join(received_anomalies),
                    weight=received_w,
                )
            )

    return findings
