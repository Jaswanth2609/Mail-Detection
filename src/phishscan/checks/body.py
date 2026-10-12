"""Body check module for PhishScan (FR-B1, FR-B2, FR-B3)."""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from phishscan.models import Finding, ParsedEmail

# Invisible and zero-width Unicode characters
INVISIBLE_UNICODE_CHARS = {
    "\u200b": "Zero-Width Space (U+200B)",
    "\u200c": "Zero-Width Non-Joiner (U+200C)",
    "\u200d": "Zero-Width Joiner (U+200D)",
    "\ufeff": "Zero-Width No-Break Space / BOM (U+FEFF)",
    "\u200e": "Left-to-Right Mark (U+200E)",
    "\u200f": "Right-to-Left Mark (U+200F)",
    "\u2060": "Word Joiner (U+2060)",
    "\u202a": "Left-to-Right Embedding (U+202A)",
    "\u202b": "Right-to-Left Embedding (U+202B)",
    "\u202c": "Pop Directional Formatting (U+202C)",
    "\u202d": "Left-to-Right Override (U+202D)",
    "\u202e": "Right-to-Left Override (U+202E)",
    "\u180e": "Mongolian Vowel Separator (U+180E)",
}

WHITE_COLOR_VALUES = {
    "white",
    "#fff",
    "#ffffff",
    "rgb(255,255,255)",
    "rgb(255, 255, 255)",
    "rgba(255,255,255,1)",
    "rgba(255, 255, 255, 1)",
}


def _check_hidden_html(html_body: str) -> list[str]:
    """Detect hidden text techniques in HTML body."""
    techniques: list[str] = []
    if not html_body:
        return techniques

    # 1. Regex check on raw HTML for inline styles or attributes
    if re.search(r'display\s*:\s*none', html_body, re.IGNORECASE):
        techniques.append("CSS 'display:none'")

    if re.search(r'visibility\s*:\s*hidden', html_body, re.IGNORECASE):
        techniques.append("CSS 'visibility:hidden'")

    if re.search(r'font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?', html_body, re.IGNORECASE):
        techniques.append("CSS 'font-size:0'")

    if re.search(r'opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)', html_body, re.IGNORECASE):
        techniques.append("CSS 'opacity:0'")

    if re.search(r'<\s*[a-zA-Z0-9]+\s+[^>]*\bhidden\b', html_body, re.IGNORECASE):
        techniques.append("HTML 'hidden' attribute")

    # 2. Check for white-on-white text (color matching background)
    try:
        soup = BeautifulSoup(html_body, "html.parser")
        for tag in soup.find_all(True):
            style = tag.get("style", "")
            if not style or not isinstance(style, str):
                continue

            style_clean = style.lower().replace(" ", "")
            color_match = re.search(r'color:([^;]+)', style_clean)
            bg_match = re.search(r'background(?:-color)?:([^;]+)', style_clean)

            if color_match and bg_match:
                fg = color_match.group(1).strip()
                bg = bg_match.group(1).strip()
                if (fg in WHITE_COLOR_VALUES and bg in WHITE_COLOR_VALUES) or (fg == bg):
                    techniques.append("White-on-white or same-color hidden text")
                    break
            elif color_match:
                fg = color_match.group(1).strip()
                # Check if tag background attribute or parent background is white
                if fg in WHITE_COLOR_VALUES and tag.get("bgcolor", "").lower() in ("#fff", "#ffffff", "white"):
                    techniques.append("White text on white bgcolor")
                    break
    except Exception:
        pass

    return list(dict.fromkeys(techniques))


def _check_invisible_unicode(texts: list[str]) -> list[str]:
    """Detect zero-width and invisible Unicode characters."""
    detected: list[str] = []
    combined = "\n".join(texts)
    for char, name in INVISIBLE_UNICODE_CHARS.items():
        if char in combined:
            detected.append(name)
    return detected


def _check_urgency_keywords(texts: list[str], keywords: list[str]) -> list[str]:
    """Detect urgency, threat, or credential-request phrases."""
    matches: list[str] = []
    combined = " ".join(texts).lower()
    for kw in keywords:
        clean_kw = kw.strip().lower()
        if not clean_kw:
            continue
        # Use regex to find phrase in text
        if re.search(rf'\b{re.escape(clean_kw)}\b', combined):
            matches.append(kw)
    return matches


def check_body(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """
    Executes body checks on the parsed email.
    
    FR-B1: Hidden text techniques (display:none, visibility:hidden, white-on-white, font-size:0).
    FR-B2: Zero-width and other invisible Unicode characters.
    FR-B3: Urgency, threat, and credential-request phrases.
    """
    findings: list[Finding] = []
    weights = config.get("weights", {})
    hidden_weight = weights.get("hidden_text", 15)
    invisible_weight = weights.get("invisible_characters", 10)
    urgency_weight = weights.get("urgency_credential_language", 10)

    # All text contents for character and keyword scanning
    all_texts = [
        parsed_email.subject,
        parsed_email.text_body,
        parsed_email.html_body,
    ]

    # --- FR-B1: Hidden Text Techniques ---
    hidden_techniques = _check_hidden_html(parsed_email.html_body)
    if hidden_techniques:
        findings.append(
            Finding(
                rule_id="BODY_HIDDEN_TEXT",
                category="Body",
                title="Hidden text techniques detected",
                description=f"Detected CSS/HTML text concealment methods: {', '.join(hidden_techniques)}.",
                weight=hidden_weight,
            )
        )

    # --- FR-B2: Zero-Width and Invisible Characters ---
    invisible_chars = _check_invisible_unicode(all_texts)
    if invisible_chars:
        findings.append(
            Finding(
                rule_id="BODY_INVISIBLE_CHARS",
                category="Body",
                title="Zero-width or invisible characters detected",
                description=f"Found invisible Unicode characters often used for evasion: {', '.join(invisible_chars)}.",
                weight=invisible_weight,
            )
        )

    # --- FR-B3: Urgency, Threat, and Credential-Request Phrases ---
    configured_keywords = config.get("keywords", {}).get("urgency", [])
    matched_keywords = _check_urgency_keywords(all_texts, configured_keywords)
    if matched_keywords:
        findings.append(
            Finding(
                rule_id="BODY_URGENCY_LANGUAGE",
                category="Body",
                title="Urgency or credential-request language detected",
                description=f"Identified high-pressure or credential-harvesting phrases: {', '.join(matched_keywords[:5])}{' (and more)' if len(matched_keywords) > 5 else ''}.",
                weight=urgency_weight,
            )
        )

    return findings
