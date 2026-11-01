"""Tests for threat intelligence and SQLite caching (FR-T1, FR-T2, FR-T3, FR-L4, FR-L5, FR-A4)."""
from __future__ import annotations

import os
from pathlib import Path
import time
import pytest

from phishscan.intel import (
    ThreatIntelCache,
    enrich_threat_intel,
    query_domain_age,
    query_virustotal_hash,
    query_virustotal_url,
)
from phishscan.models import AttachmentInfo, ExtractedLink, ParsedEmail


def test_intel_sqlite_cache_set_and_get(tmp_path):
    """FR-T2: Verify SQLite cache stores and retrieves entries before expiry."""
    db_file = tmp_path / "test_cache.db"
    cache = ThreatIntelCache(db_path=db_file)

    # Store entry with 60 second TTL
    cache.set("https://evil.com/phish", "url", "virustotal", {"malicious": 12}, ttl_seconds=60)
    cached = cache.get("https://evil.com/phish", "virustotal")
    assert cached is not None
    assert cached["malicious"] == 12

    # Verify cache misses on non-existent keys
    assert cache.get("https://unknown.com", "virustotal") is None


def test_intel_sqlite_cache_expiration(tmp_path):
    """FR-T2: Verify expired cache entries are not returned."""
    db_file = tmp_path / "test_cache.db"
    cache = ThreatIntelCache(db_path=db_file)

    # Store entry with -1 second TTL (already expired)
    cache.set("test_hash_123", "hash", "virustotal", {"malicious": 5}, ttl_seconds=-1)
    assert cache.get("test_hash_123", "virustotal") is None


def test_intel_offline_skips_network_calls(config):
    """AC-4: Running with offline=True performs zero network lookups and notes skip."""
    parsed = ParsedEmail(
        file_path="test.eml",
        links=[ExtractedLink(url="https://suspicious-site.com", href_domain="suspicious-site.com")],
        attachments=[AttachmentInfo(filename="bad.exe", content_type="application/octet-stream", size=10, sha256="abc123hash")],
    )

    findings, skipped = enrich_threat_intel(parsed, config, offline=True)
    assert len(findings) == 0
    assert any("offline mode" in s.lower() for s in skipped)


def test_intel_missing_api_key_skips_virustotal(config, monkeypatch):
    """FR-T3: Missing VT_API_KEY notes skip reason in report without failing."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    parsed = ParsedEmail(
        file_path="test.eml",
        links=[ExtractedLink(url="https://suspicious-site.com", href_domain="suspicious-site.com")],
    )

    findings, skipped = enrich_threat_intel(parsed, config, offline=False)
    assert any("VT_API_KEY" in s for s in skipped)


def test_intel_cached_virustotal_url_flagged(config, tmp_path, monkeypatch):
    """FR-L5: Flag URL when VirusTotal returns malicious verdict."""
    monkeypatch.setenv("VT_API_KEY", "dummy_vt_key")
    cache = ThreatIntelCache(db_path=tmp_path / "cache.db")
    url = "https://known-phish-domain.xyz/login"
    cache.set(url, "url", "virustotal", {"malicious": 8, "suspicious": 2})

    parsed = ParsedEmail(
        file_path="test.eml",
        links=[ExtractedLink(url=url, href_domain="known-phish-domain.xyz")],
    )

    findings, skipped = enrich_threat_intel(parsed, config, offline=False, cache=cache)
    threat_findings = [f for f in findings if f.rule_id == "LINK_THREAT_INTEL"]
    assert len(threat_findings) == 1
    assert "VirusTotal detected 8" in threat_findings[0].description
    assert threat_findings[0].weight == 30


def test_intel_cached_attachment_hash_flagged(config, tmp_path, monkeypatch):
    """FR-A4: Flag attachment when VirusTotal returns malicious verdict."""
    monkeypatch.setenv("VT_API_KEY", "dummy_vt_key")
    cache = ThreatIntelCache(db_path=tmp_path / "cache.db")
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    cache.set(sha256, "hash", "virustotal", {"malicious": 14})

    parsed = ParsedEmail(
        file_path="test.eml",
        attachments=[AttachmentInfo(filename="trojan.exe", content_type="application/octet-stream", size=1024, sha256=sha256)],
    )

    findings, skipped = enrich_threat_intel(parsed, config, offline=False, cache=cache)
    att_threats = [f for f in findings if f.rule_id == "ATT_THREAT_INTEL"]
    assert len(att_threats) == 1
    assert "VirusTotal detected 14" in att_threats[0].description
    assert att_threats[0].weight == 40


def test_intel_recent_domain_age_flagged(config, tmp_path, monkeypatch):
    """FR-L4: Flag domain registered under 30 days ago."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    cache = ThreatIntelCache(db_path=tmp_path / "cache.db")
    domain = "newly-registered-evil.com"
    cache.set(domain, "domain", "whois", {"age_days": 5, "registered_at": "2026-10-27T00:00:00Z"})

    parsed = ParsedEmail(
        file_path="test.eml",
        links=[ExtractedLink(url=f"https://{domain}/signin", href_domain=domain)],
    )

    findings, skipped = enrich_threat_intel(parsed, config, offline=False, cache=cache)
    age_findings = [f for f in findings if f.rule_id == "LINK_RECENT_DOMAIN"]
    assert len(age_findings) == 1
    assert "registered only 5 days ago" in age_findings[0].description
    assert age_findings[0].weight == 15
