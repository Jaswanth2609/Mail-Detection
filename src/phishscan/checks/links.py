"""Link check module for PhishScan (FR-L1, FR-L2, FR-L3)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from phishscan.models import ExtractedLink, Finding, ParsedEmail


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _is_ip_address(host: str) -> bool:
    """Checks if hostname is an IPv4 or IPv6 address."""
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _get_base_domain(host: str) -> tuple[str, str]:
    """
    Returns (second_level_label, registered_domain).
    For example: 'sub.login.paypal-security.com' -> ('paypal-security', 'paypal-security.com')
    """
    parts = host.lower().split(".")
    if len(parts) >= 2:
        # Simple heuristic for common ccTLDs like .co.uk, .com.au
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu") and len(parts[-1]) == 2:
            base_label = parts[-3]
            registered = ".".join(parts[-3:])
        else:
            base_label = parts[-2]
            registered = ".".join(parts[-2:])
        return base_label, registered
    return host, host


def check_links(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """
    Executes link checks on all extracted URLs.
    
    FR-L1: Link text vs href domain mismatch.
    FR-L2: Raw IP, URL shortener, or punycode.
    FR-L3: Lookalike / typosquat domains against brand list.
    """
    findings: list[Finding] = []
    weights = config.get("weights", {})
    mismatch_weight = weights.get("link_text_href_mismatch", 25)
    suspicious_url_weight = weights.get("suspicious_url_structure", 15)
    lookalike_weight = weights.get("lookalike_domain", 25)

    shortener_domains = {d.lower() for d in config.get("url_shorteners", {}).get("domains", [])}
    popular_brands = config.get("brands", {}).get("popular", [])

    mismatch_details: list[str] = []
    suspicious_urls: list[str] = []
    lookalike_details: list[str] = []

    seen_mismatches: set[tuple[str, str]] = set()
    seen_suspicious: set[str] = set()
    seen_lookalikes: set[str] = set()

    for link in parsed_email.links:
        href_domain = link.href_domain.lower()
        if not href_domain:
            continue

        # --- FR-L1: Link text vs href domain mismatch ---
        if link.anchor_domain:
            anchor_domain = link.anchor_domain.lower()
            # If anchor domain is clearly different from href domain
            if anchor_domain != href_domain and not href_domain.endswith("." + anchor_domain):
                pair = (anchor_domain, href_domain)
                if pair not in seen_mismatches:
                    seen_mismatches.add(pair)
                    mismatch_details.append(
                        f"Visible text displays '{link.anchor_text}' (domain: {anchor_domain}), "
                        f"but destination points to '{href_domain}'"
                    )

        # --- FR-L2: Raw IP, known shortener, or punycode ---
        if _is_ip_address(href_domain):
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_urls.append(f"Raw IP address used as hostname: {href_domain}")

        if href_domain in shortener_domains or any(href_domain.endswith("." + s) for s in shortener_domains):
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_urls.append(f"Known URL shortener hiding destination: {href_domain}")

        if "xn--" in href_domain:
            if href_domain not in seen_suspicious:
                seen_suspicious.add(href_domain)
                suspicious_urls.append(f"Punycode (internationalized domain) used: {href_domain}")

        # --- FR-L3: Lookalike / Typosquat domains ---
        base_label, reg_domain = _get_base_domain(href_domain)
        for brand in popular_brands:
            brand_name = brand.get("name", "").lower()
            allowed_domains = [d.lower() for d in brand.get("domains", [])]

            # If already an official domain of the brand, skip
            if any(href_domain == d or href_domain.endswith("." + d) for d in allowed_domains):
                continue

            # Check edit distance (typosquatting) e.g., paypa1 vs paypal
            clean_label = re.sub(r'[^a-z0-9]', '', base_label)
            clean_brand = re.sub(r'[^a-z0-9]', '', brand_name)

            dist = _levenshtein_distance(clean_label, clean_brand)
            is_typosquat = (dist in (1, 2) and len(clean_brand) >= 4)

            # Check if domain embeds brand with hyphen or prefix/suffix (e.g., paypal-security, login-microsoft)
            embeds_brand = bool(
                re.search(rf'(?:^|[-_.])({re.escape(clean_brand)})(?:[-_.]|$)', base_label)
                or (clean_brand in base_label and len(base_label) > len(clean_brand))
            )

            if (is_typosquat or embeds_brand) and reg_domain not in seen_lookalikes:
                seen_lookalikes.add(reg_domain)
                reason = "edit distance typosquat" if is_typosquat else "suspicious brand impersonation"
                lookalike_details.append(
                    f"Domain '{href_domain}' mimics brand '{brand.get('name')}' ({reason})"
                )

    # Compile findings
    if mismatch_details:
        findings.append(
            Finding(
                rule_id="LINK_DOMAIN_MISMATCH",
                category="Link",
                title="Link text domain differs from href destination",
                description="; ".join(mismatch_details),
                weight=mismatch_weight,
            )
        )

    if suspicious_urls:
        findings.append(
            Finding(
                rule_id="LINK_SUSPICIOUS_STRUCTURE",
                category="Link",
                title="Suspicious URL structure detected",
                description="; ".join(suspicious_urls),
                weight=suspicious_url_weight,
            )
        )

    if lookalike_details:
        findings.append(
            Finding(
                rule_id="LINK_LOOKALIKE_DOMAIN",
                category="Link",
                title="Lookalike or typosquatting domain detected",
                description="; ".join(lookalike_details),
                weight=lookalike_weight,
            )
        )

    return findings
