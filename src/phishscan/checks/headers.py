"""Header check module for PhishScan (FR-H1, FR-H2, FR-H3)."""

from __future__ import annotations

import re
from typing import Any

from phishscan.models import Finding, ParsedEmail


def _parse_auth_results(headers: dict[str, list[str]]) -> dict[str, str]:
    """Extract SPF, DKIM, DMARC statuses from Authentication-Results and Received-SPF."""
    results: dict[str, str] = {
        "spf": "missing",
        "dkim": "missing",
        "dmarc": "missing",
    }

    auth_headers = headers.get("authentication-results", [])
    spf_headers = headers.get("received-spf", [])

    full_text = " ; ".join(auth_headers + spf_headers).lower()

    if not full_text.strip():
        return results

    # Search for spf=(pass|fail|softfail|neutral|none|permerror|temperror)
    spf_match = re.search(r'\bspf=([a-z]+)', full_text)
    if spf_match:
        results["spf"] = spf_match.group(1)
    elif spf_headers:
        # Received-SPF header often starts with "pass", "fail", "softfail", "none"
        recv_spf = spf_headers[0].strip().lower()
        first_token = recv_spf.split()[0].rstrip(";:()").lower()
        if first_token in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
            results["spf"] = first_token

    # Search for dkim=(pass|fail|none|neutral|permerror|temperror)
    dkim_match = re.search(r'\bdkim=([a-z]+)', full_text)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # Search for dmarc=(pass|fail|none|permerror|temperror)
    dmarc_match = re.search(r'\bdmarc=([a-z]+)', full_text)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def check_headers(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """
    Executes header checks on the parsed email.
    
    FR-H1: SPF, DKIM, DMARC status evaluation.
    FR-H2: Domain mismatch between From, Reply-To, Return-Path.
    FR-H3: Display-name spoofing.
    """
    findings: list[Finding] = []
    weights = config.get("weights", {})
    auth_weight = weights.get("auth_failure", 15)
    domain_mismatch_weight = weights.get("domain_mismatch", 15)
    display_spoof_weight = weights.get("display_name_spoofing", 20)

    # --- FR-H1: SPF, DKIM, DMARC ---
    auth_statuses = _parse_auth_results(parsed_email.headers)

    # Check for complete lack of authentication
    if all(status == "missing" for status in auth_statuses.values()):
        findings.append(
            Finding(
                rule_id="HDR_AUTH_MISSING",
                category="Header",
                title="Missing email authentication results",
                description="No SPF, DKIM, or DMARC authentication results found in email headers.",
                weight=auth_weight,
            )
        )
    else:
        # Check SPF
        spf_status = auth_statuses["spf"]
        if spf_status in ("fail", "softfail", "permerror", "temperror"):
            findings.append(
                Finding(
                    rule_id="HDR_SPF_FAIL",
                    category="Header",
                    title="SPF authentication failed or softfailed",
                    description=f"SPF verification returned status '{spf_status}', indicating the sending IP may not be authorized.",
                    weight=auth_weight,
                )
            )

        # Check DKIM
        dkim_status = auth_statuses["dkim"]
        if dkim_status in ("fail", "permerror", "temperror"):
            findings.append(
                Finding(
                    rule_id="HDR_DKIM_FAIL",
                    category="Header",
                    title="DKIM authentication failed",
                    description=f"DKIM verification returned status '{dkim_status}', indicating possible message alteration or invalid signature.",
                    weight=auth_weight,
                )
            )

        # Check DMARC
        dmarc_status = auth_statuses["dmarc"]
        if dmarc_status in ("fail", "permerror", "temperror"):
            findings.append(
                Finding(
                    rule_id="HDR_DMARC_FAIL",
                    category="Header",
                    title="DMARC policy failed",
                    description=f"DMARC verification returned status '{dmarc_status}', failing alignment or sender domain policy.",
                    weight=auth_weight,
                )
            )

    # --- FR-H2: Domain mismatch between From, Reply-To, and Return-Path ---
    from_dom = parsed_email.from_domain
    mismatches: list[str] = []

    if from_dom:
        if parsed_email.reply_to_domain and parsed_email.reply_to_domain != from_dom:
            mismatches.append(f"Reply-To domain '{parsed_email.reply_to_domain}' != From domain '{from_dom}'")

        if parsed_email.return_path_domain and parsed_email.return_path_domain != from_dom:
            # Note: ignore empty or generic return-paths if not present
            mismatches.append(f"Return-Path domain '{parsed_email.return_path_domain}' != From domain '{from_dom}'")

    if mismatches:
        findings.append(
            Finding(
                rule_id="HDR_DOMAIN_MISMATCH",
                category="Header",
                title="Domain mismatch between From, Reply-To, or Return-Path",
                description="; ".join(mismatches),
                weight=domain_mismatch_weight,
            )
        )

    # --- FR-H3: Display-name spoofing ---
    display_name = parsed_email.from_display_name.strip()
    from_domain = parsed_email.from_domain.lower()

    if display_name and from_domain:
        display_lower = display_name.lower()
        spoof_found = False

        # 1. Check well-known brand spoofing
        popular_brands = config.get("brands", {}).get("popular", [])
        for brand_item in popular_brands:
            brand_name = brand_item.get("name", "").lower()
            allowed_domains = [d.lower() for d in brand_item.get("domains", [])]

            # If brand name is in display name (e.g. "PayPal Security" or "Microsoft Account")
            # Ensure word boundary check so "amazon" matches but not arbitrary subwords
            pattern = rf"\b{re.escape(brand_name)}\b"
            if re.search(pattern, display_lower):
                # Check if from_domain matches any of the brand's domains (or subdomain)
                is_legit = any(
                    from_domain == d or from_domain.endswith("." + d)
                    for d in allowed_domains
                )
                if not is_legit:
                    findings.append(
                        Finding(
                            rule_id="HDR_DISPLAY_SPOOF_BRAND",
                            category="Header",
                            title="Display-name brand spoofing detected",
                            description=(
                                f"Sender display name '{display_name}' claims to be '{brand_item.get('name')}', "
                                f"but sender email domain is '{from_domain}'."
                            ),
                            weight=display_spoof_weight,
                        )
                    )
                    spoof_found = True
                    break

        # 2. Check role-based spoofing (e.g., "CEO", "IT Support", "Help Desk")
        if not spoof_found:
            role_keywords = config.get("brands", {}).get("roles", [])
            for role in role_keywords:
                pattern = rf"\b{re.escape(role.lower())}\b"
                if re.search(pattern, display_lower):
                    # Flag if paired with public free email providers or unrelated generic domain
                    free_mail_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "proton.me", "protonmail.com"}
                    if from_domain in free_mail_providers or "support" in display_lower or "security" in display_lower:
                        findings.append(
                            Finding(
                                rule_id="HDR_DISPLAY_SPOOF_ROLE",
                                category="Header",
                                title="Display-name role spoofing detected",
                                description=(
                                    f"Sender display name '{display_name}' uses organizational role '{role}', "
                                    f"sent from external/untrusted domain '{from_domain}'."
                                ),
                                weight=display_spoof_weight,
                            )
                        )
                        break

    return findings
