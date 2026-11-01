"""Data models for PhishScan."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ExtractedLink:
    url: str
    anchor_text: str = ""
    href_domain: str = ""
    anchor_domain: str | None = None


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    data: bytes = field(repr=False, default=b"")
    sha256: str = ""
    magic_type: str | None = None


@dataclass
class ParsedEmail:
    file_path: str
    headers: dict[str, list[str]] = field(default_factory=dict)
    from_header: str = ""
    from_address: str = ""
    from_display_name: str = ""
    from_domain: str = ""
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path_address: str | None = None
    return_path_domain: str | None = None
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_chain: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: list[ExtractedLink] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    description: str
    weight: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "module": self.category,
            "weight": self.weight,
            "detail": f"{self.title}: {self.description}" if self.title else self.description,
            "title": self.title,
            "description": self.description,
        }


@dataclass
class LLMResult:
    verdict: str = ""  # "phishing" or "legitimate"
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    raw_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "reasons": self.reasons,
            "tactics": self.tactics,
        }


@dataclass
class IOCs:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return {"urls": self.urls, "domains": self.domains, "hashes": self.hashes}


@dataclass
class AnalysisResult:
    file: str
    analysed_at: str = ""
    rule_score: int = 0
    llm: LLMResult | None = None
    final_score: int = 0
    severity: str = "Low"
    findings: list[Finding] = field(default_factory=list)
    iocs: IOCs = field(default_factory=IOCs)
    skipped: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.analysed_at:
            self.analysed_at = datetime.now(timezone.utc).isoformat()

    @property
    def file_path(self) -> str:
        return self.file

    @property
    def score(self) -> int:
        return self.final_score

    @property
    def skipped_checks(self) -> list[str]:
        return self.skipped

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "final_score": self.final_score,
            "rule_score": self.rule_score,
            "severity": self.severity,
            "findings_count": len(self.findings),
            "iocs_count": len(self.iocs.urls) + len(self.iocs.domains) + len(self.iocs.hashes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "analysed_at": self.analysed_at,
            "rule_score": self.rule_score,
            "llm": self.llm.to_dict() if self.llm else None,
            "final_score": self.final_score,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "iocs": self.iocs.to_dict(),
            "skipped": self.skipped,
        }


@dataclass
class BenchmarkResult:
    total_samples: int = 0
    phishing_samples: int = 0
    legit_samples: int = 0
    true_positives: int = 0  # phishing >= Medium
    false_negatives: int = 0  # phishing < Medium
    true_negatives: int = 0  # legit < High
    false_positives: int = 0  # legit >= High
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "phishing_samples": self.phishing_samples,
            "legit_samples": self.legit_samples,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "details": self.details,
        }
