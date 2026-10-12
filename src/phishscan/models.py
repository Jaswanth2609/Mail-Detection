"""Data models for PhishScan."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ExtractedLink:
    """Represents a URL found inside an email."""
    url: str
    anchor_text: str = ""
    href_domain: str = ""
    anchor_domain: str | None = None


@dataclass
class AttachmentInfo:
    """Represents an attachment extracted from an email."""
    filename: str
    content_type: str
    size: int
    data: bytes = field(repr=False)
    magic_type: str | None = None


@dataclass
class ParsedEmail:
    """Represents a parsed RFC 5322 email message."""
    file_path: str
    headers: dict[str, list[str]] = field(default_factory=dict)
    from_header: str = ""
    from_address: str = ""
    from_display_name: str = ""
    from_domain: str = ""
    reply_to_header: str | None = None
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path_header: str | None = None
    return_path_address: str | None = None
    return_path_domain: str | None = None
    subject: str = ""
    date: str = ""
    message_id: str = ""
    text_body: str = ""
    html_body: str = ""
    links: list[ExtractedLink] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)

    def get_header(self, name: str) -> str | None:
        """Get first occurrence of a header, case-insensitively."""
        vals = self.headers.get(name.lower())
        if vals:
            return vals[0]
        return None

    def get_headers(self, name: str) -> list[str]:
        """Get all occurrences of a header, case-insensitively."""
        return self.headers.get(name.lower(), [])


@dataclass
class Finding:
    """Represents a single detected indicator with weight and explanation."""
    rule_id: str
    category: str
    title: str
    description: str
    weight: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Complete analysis report for an email file."""
    file_path: str
    score: int
    severity: str
    findings: list[Finding] = field(default_factory=list)
    skipped_checks: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "score": self.score,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "skipped_checks": self.skipped_checks,
            "summary": self.summary,
        }
