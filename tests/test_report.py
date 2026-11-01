"""Tests for report formatters (FR-R1, FR-R2, FR-R3, Appendix A)."""
from __future__ import annotations

import json
from pathlib import Path

from phishscan.models import AnalysisResult, Finding, IOCs, LLMResult
from phishscan.report import (
    format_csv_report,
    format_html_report,
    format_json_report,
    format_terminal_report,
)


def _sample_result() -> AnalysisResult:
    return AnalysisResult(
        file="invoice.eml",
        rule_score=70,
        final_score=72,
        severity="High",
        llm=LLMResult(
            verdict="phishing",
            confidence=0.85,
            reasons=["Creates urgency and asks for login on a non-official domain."],
            tactics=["T1566.002 Spearphishing Link"],
        ),
        findings=[
            Finding("LINK_DOMAIN_MISMATCH", "Link", "Domain mismatch", "Link text shows paypal.com but href goes to paypa1-secure.xyz", 25),
            Finding("LINK_LOOKALIKE_DOMAIN", "Link", "Lookalike domain", "Lookalike domain: paypa1-secure.xyz resembles paypal.com", 25),
            Finding("HDR_SPF_FAIL", "Header", "SPF fail", "SPF fail for sender domain", 15),
            Finding("BODY_URGENCY_LANGUAGE", "Body", "Urgency language", 'Urgency language: "verify within 24 hours"', 10),
        ],
        iocs=IOCs(
            urls=["https://paypa1-secure.xyz/login"],
            domains=["paypa1-secure.xyz", "paypal.com"],
            hashes=["a1b2c3d4e5f6"],
        ),
        skipped=["VirusTotal lookup (VT_API_KEY not set)"],
    )


def test_report_terminal_appendix_a_layout():
    """FR-R1: Terminal report matches layout in SRS Appendix A."""
    res = _sample_result()
    term = format_terminal_report(res, use_color=False)

    assert "File: invoice.eml" in term
    assert "Severity: HIGH" in term
    assert "Final score: 72/100" in term
    assert "Rule score: 70" in term
    assert "LLM review: yes (confidence 0.85" in term
    assert "Findings" in term
    assert "+25  Link text shows paypal.com but href goes to paypa1-secure.xyz  (LINK_DOMAIN_MISMATCH)" in term
    assert "+15  SPF fail for sender domain  (HDR_SPF_FAIL)" in term
    assert "LLM explanation" in term
    assert "Creates urgency and asks for login on a non-official domain." in term
    assert "Skipped: VirusTotal lookup (VT_API_KEY not set)" in term


def test_report_json_section_7_5_schema():
    """FR-R2, Section 7.5: JSON export contains all mandatory schema fields."""
    res = _sample_result()
    json_str = format_json_report(res)
    data = json.loads(json_str)

    assert data["file"] == "invoice.eml"
    assert "analysed_at" in data
    assert data["rule_score"] == 70
    assert data["final_score"] == 72
    assert data["severity"] == "High"
    assert data["llm"]["verdict"] == "phishing"
    assert data["llm"]["confidence"] == 0.85
    assert len(data["findings"]) == 4
    for f in data["findings"]:
        assert "id" in f
        assert "module" in f
        assert "weight" in f
        assert "detail" in f
    assert data["iocs"]["urls"] == ["https://paypa1-secure.xyz/login"]
    assert "paypa1-secure.xyz" in data["iocs"]["domains"]
    assert data["skipped"] == ["VirusTotal lookup (VT_API_KEY not set)"]


def test_report_csv_batch():
    """FR-R2: CSV batch export format."""
    res = _sample_result()
    csv_str = format_csv_report([res])
    lines = csv_str.strip().splitlines()

    assert len(lines) == 2
    header = lines[0]
    row = lines[1]
    assert "file,final_score,severity,rule_score,llm_verdict" in header
    assert "invoice.eml,72,High,70,phishing,0.85,4,1,2,1,1" in row


def test_report_html_self_contained():
    """FR-R2: Self-contained HTML report generation."""
    res = _sample_result()
    html_doc = format_html_report([res])

    assert "<!DOCTYPE html>" in html_doc
    assert "<style>" in html_doc
    assert "PhishScan Email Security Report" in html_doc
    assert "invoice.eml" in html_doc
    assert "72/100" in html_doc
    assert "HIGH" in html_doc
    assert "paypa1-secure.xyz" in html_doc
    assert "LINK_DOMAIN_MISMATCH" in html_doc
