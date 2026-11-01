"""RFC 5322 email parser — FR-P1 through FR-P5."""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from phishscan.models import AttachmentInfo, ExtractedLink, ParsedEmail


class ParserError(Exception):
    """Raised when parsing fails or input is invalid."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


_URL_RE = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.I)
_DOMAIN_RE = re.compile(
    r"^(?:https?://)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)(?:[/:?#].*)?$",
    re.I,
)


def extract_domain(addr_or_url: str | None) -> str:
    """Extract domain portion from email address or URL host."""
    if not addr_or_url:
        return ""
    text = addr_or_url.strip().lower()
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    if "://" in text or text.startswith("//"):
        if text.startswith("//"):
            text = "http:" + text
        try:
            return (urlsplit(text).hostname or "").strip(".")
        except Exception:
            pass
    if ":" in text and not text.startswith("http"):
        text = text.split(":")[0]
    return text.strip("<>[](),; \t\r\n").rstrip(".")


def parse_address_header(val: str | None) -> tuple[str, str, str]:
    """Parse address header returning (display_name, email_address, domain)."""
    if not val:
        return "", "", ""
    try:
        name, addr = email.utils.parseaddr(val)
        addr = addr.strip().lower()
        return name.strip(), addr, extract_domain(addr)
    except Exception:
        match = re.search(r"[\w.\-]+@[\w.\-]+", val)
        addr = match.group(0).lower() if match else ""
        return "", addr, extract_domain(addr)


def extract_links(html: str, text: str) -> list[ExtractedLink]:
    """FR-P3: Extract URLs from href attributes and visible text."""
    links: list[ExtractedLink] = []
    seen: set[tuple[str, str]] = set()

    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a"):
                href = (a.get("href") or "").strip()
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                anchor = a.get_text(separator=" ", strip=True)
                pair = (href, anchor)
                if pair in seen:
                    continue
                seen.add(pair)

                dm = _DOMAIN_RE.match(anchor)
                anchor_dom = dm.group(1).lower().rstrip(".") if dm else None
                links.append(
                    ExtractedLink(
                        url=href,
                        anchor_text=anchor,
                        href_domain=extract_domain(href),
                        anchor_domain=anchor_dom,
                    )
                )
        except Exception:
            pass

    # Extract raw text URLs
    for m in _URL_RE.finditer(f"{text}\n{html}"):
        url = m.group(0).rstrip(".,;:!?)>]}\"'")
        pair = (url, "")
        if pair not in seen:
            seen.add(pair)
            links.append(ExtractedLink(url=url, href_domain=extract_domain(url)))

    return links


def decode_payload(part: Any) -> str:
    """FR-P2: Decode quoted-printable and base64 text payload safely."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
    except Exception:
        pass

    try:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        if isinstance(payload, str):
            return payload
    except Exception:
        pass
    return ""


def parse_eml(file_path: str | Path) -> ParsedEmail:
    """FR-P1 through FR-P5: Parse an RFC 5322 .eml file."""
    path = Path(file_path)
    if not path.exists():
        raise ParserError(f"File not found: {path}", exit_code=2)
    if not path.is_file():
        raise ParserError(f"Target is not a regular file: {path}", exit_code=2)

    try:
        raw_bytes = path.read_bytes()
    except Exception as exc:
        raise ParserError(f"Failed to read {path}: {exc}", exit_code=2)

    if not raw_bytes.strip():
        raise ParserError(f"Email file is empty: {path}", exit_code=2)

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as exc:
            raise ParserError(f"Failed to parse email message: {exc}", exit_code=2)

    # FR-P1: Extract headers, tolerating repeated headers like Received
    headers: dict[str, list[str]] = {}
    try:
        for k, v in msg.items():
            headers.setdefault(k.lower(), []).append(str(v))
    except Exception:
        pass

    from_raw = str(msg.get("From", ""))
    from_name, from_addr, from_dom = parse_address_header(from_raw)

    reply_to_raw = msg.get("Reply-To")
    _, reply_to_addr, reply_to_dom = (
        parse_address_header(str(reply_to_raw)) if reply_to_raw else ("", None, None)
    )

    return_path_raw = msg.get("Return-Path")
    _, return_path_addr, return_path_dom = (
        parse_address_header(str(return_path_raw)) if return_path_raw else ("", None, None)
    )

    received_chain = headers.get("received", [])

    # FR-P2 & FR-P4: Extract body parts and static attachments
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    try:
        for part in msg.walk():
            try:
                ct = (part.get_content_type() or "").lower()
                disp = str(part.get_content_disposition() or "").lower()
                filename = part.get_filename()

                is_attachment = disp == "attachment" or filename is not None or (
                    ct not in (
                        "text/plain",
                        "text/html",
                        "multipart/alternative",
                        "multipart/mixed",
                        "multipart/related",
                    )
                    and not part.is_multipart()
                )

                if is_attachment:
                    data = part.get_payload(decode=True) or b""
                    att_name = filename or f"attachment_{len(attachments)+1}"
                    attachments.append(
                        AttachmentInfo(
                            filename=att_name,
                            content_type=ct or "application/octet-stream",
                            size=len(data),
                            data=data,
                            sha256=hashlib.sha256(data).hexdigest(),
                        )
                    )
                elif ct == "text/plain":
                    text_parts.append(decode_payload(part))
                elif ct == "text/html":
                    html_parts.append(decode_payload(part))
            except Exception:
                continue
    except Exception:
        pass

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)
    links = extract_links(html_body, text_body)

    return ParsedEmail(
        file_path=str(path),
        headers=headers,
        from_header=from_raw,
        from_address=from_addr,
        from_display_name=from_name,
        from_domain=from_dom,
        reply_to_address=reply_to_addr,
        reply_to_domain=reply_to_dom,
        return_path_address=return_path_addr,
        return_path_domain=return_path_dom,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        received_chain=received_chain,
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
    )


def redact_sensitive_text(text: str, max_length: int = 2000) -> str:
    """NFR-9 / FR-M2: Redact email addresses and phone numbers before sending to LLM."""
    if not text:
        return ""
    # Redact email addresses
    redacted = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[EMAIL_REDACTED]", text)
    # Redact phone numbers
    redacted = re.sub(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        "[PHONE_REDACTED]",
        redacted,
    )
    # Truncate to maximum characters
    if len(redacted) > max_length:
        redacted = redacted[:max_length] + "\n...[truncated for privacy & token limit]"
    return redacted
