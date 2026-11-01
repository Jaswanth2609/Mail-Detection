"""Link check module for PhishScan (FR-L1, FR-L2, FR-L3)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from phishscan.models import Finding, ParsedEmail


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)

    previous = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous[j + 1] + 1
            deletions = current[j] + 1
            substitutions = previous[j] + (c1 != c2)
            current.append(min(insertions, deletions, substitutions))
        previous = current
    return previous[-1]


def _is_ip_address(host: str) -> bool:
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _get_base_domain(host: str) -> tuple[str, str, int]:
    """Returns (second_level_label, registered_domain, subdomain_count)."""
    parts = host.lower().split(".")
    if len(parts) >= 2:
        if (
            len(parts) >= 3
            and parts[-2] in {"co", "com", "org", "net", "gov", "edu"}
            and len(parts[-1]) == 2
        ):
            base_label = parts[-3]
            registered = ".".join(parts[-3:])
            subdomain_count = len(parts) - 3
        else:
            base_label = parts[-2]
            registered = ".".join(parts[-2:])
            subdomain_count = len(parts) - 2
        return base_label, registered, max(0, subdomain_count)
    return host, host, 0


def check_links(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """Execute rule-based link checks."""
    findings: list[Finding] = []
    weights = config.get("weights", {})
    mismatch_w = weights.get("link_text_href_mismatch", 25)
    suspicious_w = weights.get("suspicious_url_structure", 15)
    lookalike_w = weights.get("lookalike_domain", 25)

    shorteners = {d.lower() for d in config.get("url_shorteners", {}).get("domains", [])}
    popular_brands = config.get("brands", {}).get("popular", [])

    mismatch_details: list[str] = []
    suspicious_details: list[str] = []
    lookalike_details: list[str] = []

    seen_mismatches: set[tuple[str, str]] = set()
    seen_suspicious: set[str] = set()
    seen_lookalikes: set[str] = set()

    for link in parsed_email.links:
        href_domain = link.href_domain.lower()
        if not href_domain:
            continue

        # FR-L1: Link text domain vs href domain mismatch
        if link.anchor_domain:
            anchor_dom = link.anchor_domain.lower()
            if anchor_dom != href_domain and not href_domain.endswith("." + anchor_dom):
                pair = (anchor_dom, href_domain)
                if pair not in seen_mismatches:
                    seen_mismatches.add(pair)
                    mismatch_details.append(
                        f"Visible text shows '{link.anchor_text}' ({anchor_dom}) but href points to '{href_domain}'"
                    )

        # FR-L2: Raw IP, known shortener, punycode, or deep subdomain chain
        if _is_ip_address(href_domain):
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_details.append(f"Raw IP address used as host: {href_domain}")

        if href_domain in shorteners or any(href_domain.endswith("." + s) for s in shorteners):
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_details.append(f"Known URL shortener hiding target: {href_domain}")

        if "xn--" in href_domain:
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_details.append(f"Punycode (internationalized domain) used: {href_domain}")

        base_label, reg_domain, subdomain_count = _get_base_domain(href_domain)
        if subdomain_count >= 3:
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_details.append(f"Unusually deep subdomain chain ({subdomain_count} levels): {href_domain}")

        # FR-L3: Lookalike / Typosquatting domains
        for brand in popular_brands:
            brand_name = brand.get("name", "").lower()
            allowed = [d.lower() for d in brand.get("domains", [])]
            if any(href_domain == d or href_domain.endswith("." + d) for d in allowed):
                continue

            clean_label = re.sub(r"[^a-z0-9]", "", base_label)
            clean_brand = re.sub(r"[^a-z0-9]", "", brand_name)

            dist = _levenshtein_distance(clean_label, clean_brand)
            is_typosquat = dist in (1, 2) and len(clean_brand) >= 4
            embeds_brand = bool(
                re.search(rf"(?:^|[-_.])({re.escape(clean_brand)})(?:[-_.]|$)", base_label)
                or (clean_brand in base_label and len(base_label) > len(clean_brand))
            )

            if (is_typosquat or embeds_brand) and reg_domain not in seen_lookalikes:
                seen_lookalikes.add(reg_domain)
                reason = "edit distance typosquat" if is_typosquat else "suspicious brand impersonation"
                lookalike_details.append(
                    f"Domain '{href_domain}' mimics '{brand.get('name')}' ({reason})"
                )

    if mismatch_details:
        findings.append(
            Finding(
                rule_id="LINK_DOMAIN_MISMATCH",
                category="Link",
                title="Link text domain differs from href destination",
                description="; ".join(mismatch_details),
                weight=mismatch_w,
            )
        )

    if suspicious_details:
        findings.append(
            Finding(
                rule_id="LINK_SUSPICIOUS_STRUCTURE",
                category="Link",
                title="Suspicious URL structure detected",
                description="; ".join(suspicious_details),
                weight=suspicious_w,
            )
        )

    if lookalike_details:
        findings.append(
            Finding(
                rule_id="LINK_LOOKALIKE_DOMAIN",
                category="Link",
                title="Lookalike or typosquatting domain detected",
                description="; ".join(lookalike_details),
                weight=lookalike_w,
            )
        )

    return findings
