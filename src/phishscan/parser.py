"""Email parser module for PhishScan."""

from __future__ import annotations

import email
import email.policy
import email.utils
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from phishscan.models import AttachmentInfo, ExtractedLink, ParsedEmail


class ParserError(Exception):
    """Raised when an email file cannot be read, parsed, or is empty."""
    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


URL_REGEX = re.compile(
    r"""https?://[^\s<>"'{}|\\^`\[\]]+""",
    re.IGNORECASE,
)

DOMAIN_IN_TEXT_REGEX = re.compile(
    r"""^(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)(?:[/:?#].*)?$""",
    re.IGNORECASE,
)


def extract_domain(email_or_url: str | None) -> str:
    """Safely extracts domain name from email address or host."""
    if not email_or_url:
        return ""
    text = email_or_url.strip().lower()
    if "@" in text:
        text = text.split("@")[-1]
    if ":" in text and not text.startswith("http"):
        text = text.split(":")[0]
    return text.strip("<>[](),; \t\r\n").rstrip(".")


def extract_host(url: str) -> str:
    """Extract host/domain from a URL."""
    if not url:
        return ""
    cleaned = url.strip()
    if cleaned.startswith("//"):
        cleaned = "http:" + cleaned
    elif not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = "http://" + cleaned
    try:
        parts = urlsplit(cleaned)
        host = parts.hostname or ""
        return host.lower().strip(".")
    except Exception:
        return ""


def parse_address_field(header_val: str | None) -> tuple[str, str, str]:
    """
    Parse an address header into (display_name, email_address, domain).
    Tolerates malformed values without failing.
    """
    if not header_val:
        return "", "", ""
    try:
        display_name, addr = email.utils.parseaddr(header_val)
        display_name = display_name.strip()
        addr = addr.strip().lower()
        domain = extract_domain(addr)
        return display_name, addr, domain
    except Exception:
        # Fallback for malformed address
        addr_match = re.search(r'[\w\.-]+@[\w\.-]+', header_val)
        addr = addr_match.group(0).lower() if addr_match else ""
        domain = extract_domain(addr)
        return "", addr, domain


def extract_links(html_body: str, text_body: str) -> list[ExtractedLink]:
    """
    Extracts all URLs from HTML href attributes and visible text,
    preserving anchor text and target URL.
    """
    links: list[ExtractedLink] = []
    seen: set[tuple[str, str]] = set()

    # 1. Parse HTML links if HTML body exists
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a_tag in soup.find_all("a"):
                href = a_tag.get("href")
                if not href:
                    continue
                href = str(href).strip()
                if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                    continue

                anchor_text = a_tag.get_text(separator=" ", strip=True)
                href_domain = extract_host(href)

                anchor_domain: str | None = None
                dom_match = DOMAIN_IN_TEXT_REGEX.match(anchor_text)
                if dom_match:
                    anchor_domain = dom_match.group(1).lower().rstrip(".")

                pair = (href, anchor_text)
                if pair not in seen:
                    seen.add(pair)
                    links.append(
                        ExtractedLink(
                            url=href,
                            anchor_text=anchor_text,
                            href_domain=href_domain,
                            anchor_domain=anchor_domain,
                        )
                    )
        except Exception:
            pass

    # 2. Extract plain text URLs from text_body and html_body
    combined_text = f"{text_body}\n{html_body}"
    for match in URL_REGEX.finditer(combined_text):
        url = match.group(0).rstrip(".,;:!?)>]}")
        href_domain = extract_host(url)
        pair = (url, "")
        if pair not in seen:
            seen.add(pair)
            links.append(
                ExtractedLink(
                    url=url,
                    anchor_text="",
                    href_domain=href_domain,
                    anchor_domain=None,
                )
            )

    return links


def parse_eml(file_path: str | Path) -> ParsedEmail:
    """
    Parses a single .eml file.
    
    FR-P1: Read single .eml file and extract all headers.
    FR-P2: Extract plain-text and HTML body (decode quoted-printable and base64).
    FR-P3: Extract all URLs preserving anchor text and target.
    FR-P4: Extract attachment metadata and content bytes safely (never executed).
    FR-P5: On missing, empty, or unreadable file, raise ParserError with exit code 2.
    FR-P6: Tolerate malformed headers without crashing.
    """
    path = Path(file_path)

    if not path.exists():
        raise ParserError(f"File not found: {path}", exit_code=2)
    if not path.is_file():
        raise ParserError(f"Path is not a regular file: {path}", exit_code=2)

    try:
        raw_bytes = path.read_bytes()
    except Exception as e:
        raise ParserError(f"Unable to read file {path}: {e}", exit_code=2)

    if len(raw_bytes.strip()) == 0:
        raise ParserError(f"File is empty: {path}", exit_code=2)

    try:
        # Use default policy for RFC 5322 parsing with defect recovery
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        # Fallback to compat32 if standard parser trips on unusual malformation
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as e:
            raise ParserError(f"Failed to parse email message: {e}", exit_code=2)

    # FR-P1 & FR-P6: Extract all headers case-insensitively
    headers_dict: dict[str, list[str]] = {}
    try:
        for key, val in msg.items():
            k = key.lower()
            headers_dict.setdefault(k, []).append(str(val))
    except Exception:
        pass

    # Extract From, Reply-To, Return-Path
    from_raw = str(msg.get("From", ""))
    from_display, from_addr, from_dom = parse_address_field(from_raw)

    reply_to_raw = msg.get("Reply-To")
    reply_to_display, reply_to_addr, reply_to_dom = (
        parse_address_field(str(reply_to_raw)) if reply_to_raw else ("", None, None)
    )

    return_path_raw = msg.get("Return-Path")
    return_path_display, return_path_addr, return_path_dom = (
        parse_address_field(str(return_path_raw)) if return_path_raw else ("", None, None)
    )

    subject = str(msg.get("Subject", ""))
    date_val = str(msg.get("Date", ""))
    message_id = str(msg.get("Message-ID", ""))

    # FR-P2: Extract plain-text and HTML body
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    def decode_payload_safe(part: Any) -> str:
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
            elif isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
        except Exception:
            pass

        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
            elif isinstance(payload, str):
                return payload
        except Exception:
            pass
        return ""

    # FR-P4: Extract attachment filename, declared Content-Type, and size
    try:
        for part in msg.walk():
            try:
                content_disposition = part.get_content_disposition()
                filename = part.get_filename()
                content_type = part.get_content_type()

                is_attachment = (
                    content_disposition == "attachment"
                    or filename is not None
                    or (
                        content_type not in ("text/plain", "text/html", "multipart/alternative", "multipart/mixed", "multipart/related")
                        and not part.is_multipart()
                    )
                )

                if is_attachment:
                    raw_data = part.get_payload(decode=True) or b""
                    att_filename = filename or f"attachment_{len(attachments) + 1}"
                    attachments.append(
                        AttachmentInfo(
                            filename=att_filename,
                            content_type=content_type,
                            size=len(raw_data),
                            data=raw_data,
                        )
                    )
                else:
                    if content_type == "text/plain":
                        text_parts.append(decode_payload_safe(part))
                    elif content_type == "text/html":
                        html_parts.append(decode_payload_safe(part))
            except Exception:
                continue
    except Exception:
        pass

    text_body = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    # FR-P3: Extract all URLs
    links = extract_links(html_body=html_body, text_body=text_body)

    return ParsedEmail(
        file_path=str(path),
        headers=headers_dict,
        from_header=from_raw,
        from_address=from_addr,
        from_display_name=from_display,
        from_domain=from_dom,
        reply_to_header=str(reply_to_raw) if reply_to_raw else None,
        reply_to_address=reply_to_addr,
        reply_to_domain=reply_to_dom,
        return_path_header=str(return_path_raw) if return_path_raw else None,
        return_path_address=return_path_addr,
        return_path_domain=return_path_dom,
        subject=subject,
        date=date_val,
        message_id=message_id,
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
    )
