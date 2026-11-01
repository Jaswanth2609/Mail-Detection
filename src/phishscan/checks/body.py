"""Body and whitespace checks — FR-B1, FR-B2, FR-B3, FR-B4."""
from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from phishscan.models import Finding, ParsedEmail

_INVISIBLE_UNICODE = {
    "\u200b": "ZWSP", "\u200c": "ZWNJ", "\u200d": "ZWJ", "\ufeff": "BOM",
    "\u200e": "LRM", "\u200f": "RLM", "\u2060": "WJ",
    "\u202a": "LRE", "\u202b": "RLE", "\u202c": "PDF",
    "\u202d": "LRO", "\u202e": "RLO", "\u180e": "MVS",
}

_WHITE_COLORS = {"white", "#fff", "#ffffff", "rgb(255,255,255)", "rgba(255,255,255,1)"}


def _detect_hidden_html(html: str) -> list[str]:
    """FR-B1: Detect CSS and HTML text hiding techniques."""
    if not html:
        return []
    methods: list[str] = []

    css_patterns = [
        (r"display\s*:\s*none", "display:none"),
        (r"visibility\s*:\s*hidden", "visibility:hidden"),
        (r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?", "font-size:0"),
        (r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)", "opacity:0"),
    ]
    for pattern, label in css_patterns:
        if re.search(pattern, html, re.I):
            methods.append(label)

    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(True):
            style = (tag.get("style") or "").lower().replace(" ", "")
            cm = re.search(r"color:([^;]+)", style)
            bm = re.search(r"background(?:-color)?:([^;]+)", style)
            if cm and bm:
                fg, bg = cm.group(1).strip(), bm.group(1).strip()
                if (fg in _WHITE_COLORS and bg in _WHITE_COLORS) or fg == bg:
                    methods.append("white-on-white text")
                    break
    except Exception:
        pass
    return list(dict.fromkeys(methods))


def _detect_abnormal_whitespace(text: str) -> bool:
    """FR-B2: Detect abnormal whitespace runs (padding to push content off-screen)."""
    return bool(re.search(r"[ \t]{30,}", text) or re.search(r"\n{10,}", text))


def _detect_low_text_image_ratio(parsed: ParsedEmail) -> bool:
    """FR-B4: Flag HTML-only emails with no plain-text part and low text-to-image ratio."""
    if parsed.text_body.strip():
        return False
    if not parsed.html_body.strip():
        return False

    try:
        soup = BeautifulSoup(parsed.html_body, "html.parser")
        images = soup.find_all("img")
        text_len = len(soup.get_text(strip=True))
        if images and text_len < 40:
            return True
    except Exception:
        pass
    return False


def check_body(parsed: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """Execute body checks against parsed email."""
    findings: list[Finding] = []
    weights = config.get("weights", {})
    hidden_w = weights.get("hidden_text", 15)
    invisible_w = weights.get("invisible_characters", 10)
    urgency_w = weights.get("urgency_credential_language", 10)
    ratio_w = weights.get("low_text_image_ratio", 10)

    # FR-B1: Hidden text in HTML
    hidden_methods = _detect_hidden_html(parsed.html_body)
    if hidden_methods:
        findings.append(
            Finding(
                rule_id="BODY_HIDDEN_TEXT",
                category="Body",
                title="Hidden text detected",
                description=f"HTML concealment methods detected: {', '.join(hidden_methods)}.",
                weight=hidden_w,
            )
        )

    # FR-B2: Invisible Unicode chars and abnormal whitespace
    all_text = f"{parsed.subject}\n{parsed.text_body}\n{parsed.html_body}"
    chars_found = [name for ch, name in _INVISIBLE_UNICODE.items() if ch in all_text]
    has_abnormal_ws = _detect_abnormal_whitespace(all_text)
    if chars_found or has_abnormal_ws:
        details: list[str] = []
        if chars_found:
            details.append(f"invisible Unicode: {', '.join(chars_found)}")
        if has_abnormal_ws:
            details.append("abnormal whitespace padding")
        findings.append(
            Finding(
                rule_id="BODY_INVISIBLE_CHARS",
                category="Body",
                title="Zero-width or abnormal whitespace detected",
                description=f"Evasion indicators: {'; '.join(details)}.",
                weight=invisible_w,
            )
        )

    # FR-B3: Urgency and credential-request phrases
    keywords = config.get("keywords", {}).get("urgency", [])
    lower_text = all_text.lower()
    matched = [
        kw for kw in keywords
        if kw.strip() and re.search(rf"\b{re.escape(kw.strip().lower())}\b", lower_text)
    ]
    if matched:
        display_matched = ", ".join(matched[:5])
        if len(matched) > 5:
            display_matched += f" (+{len(matched) - 5} more)"
        findings.append(
            Finding(
                rule_id="BODY_URGENCY_LANGUAGE",
                category="Body",
                title="Urgency or credential-request language",
                description=f"Phrases detected: {display_matched}.",
                weight=urgency_w,
            )
        )

    # FR-B4: HTML-only email with low text-to-image ratio
    if _detect_low_text_image_ratio(parsed):
        findings.append(
            Finding(
                rule_id="BODY_LOW_TEXT_IMAGE_RATIO",
                category="Body",
                title="Image-only email with low text content",
                description="Email has HTML image structure but almost no readable plain text.",
                weight=ratio_w,
            )
        )

    return findings
