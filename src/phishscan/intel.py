"""Threat intelligence lookups and SQLite caching (FR-T1, FR-T2, FR-T3, FR-L4, FR-L5, FR-A4)."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from phishscan.models import Finding, ParsedEmail

DEFAULT_CACHE_DIR = Path.home() / ".phishscan"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "cache.db"
DEFAULT_TTL_SECONDS = 86400  # 24 hours


class ThreatIntelCache:
    """FR-T2: SQLite-backed cache for threat intelligence lookups."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = self._resolve_db_path(db_path)
        self._init_db()

    def _resolve_db_path(self, db_path: str | Path | None) -> str:
        if db_path:
            return str(db_path)
        try:
            DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            return str(DEFAULT_CACHE_FILE)
        except Exception:
            try:
                tmp_dir = Path("/tmp/phishscan")
                tmp_dir.mkdir(parents=True, exist_ok=True)
                return str(tmp_dir / "cache.db")
            except Exception:
                return ":memory:"

    def _init_db(self) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        kind TEXT,
                        source TEXT,
                        result TEXT,
                        fetched_at INTEGER,
                        expires_at INTEGER
                    )
                    """
                )
                conn.commit()
        except Exception:
            pass

    def get(self, key: str, source: str) -> dict[str, Any] | None:
        """Retrieve unexpired cached result."""
        try:
            now = int(time.time())
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT result, expires_at FROM cache WHERE key = ? AND source = ?",
                    (key, source),
                )
                row = cur.fetchone()
                if row:
                    result_json, expires_at = row
                    if expires_at > now:
                        return json.loads(result_json)
        except Exception:
            pass
        return None

    def set(
        self,
        key: str,
        kind: str,
        source: str,
        result: dict[str, Any],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """Store lookup result with expiration timestamp."""
        try:
            now = int(time.time())
            expires_at = now + ttl_seconds
            result_json = json.dumps(result)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO cache (key, kind, source, result, fetched_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        result = excluded.result,
                        fetched_at = excluded.fetched_at,
                        expires_at = excluded.expires_at
                    """,
                    (key, kind, source, result_json, now, expires_at),
                )
                conn.commit()
        except Exception:
            pass


def _url_to_vt_id(url: str) -> str:
    """Encode URL to VirusTotal v3 identifier (base64url without padding)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def query_virustotal_url(
    url: str, api_key: str, cache: ThreatIntelCache, timeout: float = 15.0
) -> dict[str, Any] | None:
    """FR-T1, FR-L5: Query VirusTotal v3 for URL reputation."""
    cached = cache.get(url, "virustotal")
    if cached is not None:
        return cached

    url_id = _url_to_vt_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    import httpx

    for attempt in range(2):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": data.get("reputation", 0),
                    }
                    cache.set(url, "url", "virustotal", result)
                    return result
                elif resp.status_code == 429:
                    # Rate limit hit, wait briefly before retrying
                    time.sleep(1.0)
                    continue
                elif resp.status_code == 404:
                    return {"malicious": 0, "not_found": True}
        except Exception:
            pass
    return None


def query_virustotal_hash(
    file_hash: str, api_key: str, cache: ThreatIntelCache, timeout: float = 15.0
) -> dict[str, Any] | None:
    """FR-T1, FR-A4: Query VirusTotal v3 for SHA-256 hash reputation."""
    cached = cache.get(file_hash, "virustotal")
    if cached is not None:
        return cached

    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    import httpx

    for attempt in range(2):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    result = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                    }
                    cache.set(file_hash, "hash", "virustotal", result)
                    return result
                elif resp.status_code == 429:
                    time.sleep(1.0)
                    continue
                elif resp.status_code == 404:
                    return {"malicious": 0, "not_found": True}
        except Exception:
            pass
    return None


def query_domain_age(
    domain: str, cache: ThreatIntelCache, timeout: float = 10.0
) -> dict[str, Any] | None:
    """FR-L4: Query domain registration age via RDAP protocol."""
    cached = cache.get(domain, "whois")
    if cached is not None:
        return cached

    endpoint = f"https://rdap.org/domain/{domain}"

    import httpx

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(endpoint)
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                reg_date_str = None
                for ev in events:
                    if ev.get("eventAction") in ("registration", "created"):
                        reg_date_str = ev.get("eventDate")
                        break

                if reg_date_str:
                    # Parse ISO 8601 date
                    clean_date = reg_date_str.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_date)
                    now = datetime.now(timezone.utc)
                    age_days = (now - dt).days
                    result = {"registered_at": reg_date_str, "age_days": max(0, age_days)}
                    cache.set(domain, "domain", "whois", result)
                    return result
    except Exception:
        pass
    return None


def enrich_threat_intel(
    parsed: ParsedEmail,
    config: dict[str, Any],
    offline: bool = False,
    cache: ThreatIntelCache | None = None,
) -> tuple[list[Finding], list[str]]:
    """Enrich findings using threat intelligence lookups (VirusTotal & WHOIS)."""
    findings: list[Finding] = []
    skipped: list[str] = []

    if offline:
        skipped.append("Threat intelligence lookups (offline mode requested)")
        return findings, skipped

    vt_key = os.getenv("VT_API_KEY", "").strip()
    if not vt_key:
        skipped.append("VirusTotal lookup (VT_API_KEY environment variable not set)")

    cache = cache or ThreatIntelCache()
    weights = config.get("weights", {})
    url_threat_w = weights.get("threat_intel_url", 30)
    att_threat_w = weights.get("threat_intel_attachment", 40)
    domain_age_w = weights.get("recent_domain", 15)

    # 1. Check unique URLs with VirusTotal
    if vt_key:
        seen_urls: set[str] = set()
        for link in parsed.links:
            url = link.url
            if url in seen_urls or not url.startswith(("http://", "https://")):
                continue
            seen_urls.add(url)
            vt_res = query_virustotal_url(url, vt_key, cache)
            if vt_res and vt_res.get("malicious", 0) > 0:
                findings.append(
                    Finding(
                        rule_id="LINK_THREAT_INTEL",
                        category="ThreatIntel",
                        title="URL flagged by threat intelligence",
                        description=f"VirusTotal detected {vt_res['malicious']} security vendors flagging '{url}'.",
                        weight=url_threat_w,
                    )
                )

    # 2. Check attachment SHA-256 hashes with VirusTotal
    if vt_key:
        for att in parsed.attachments:
            if att.sha256:
                vt_res = query_virustotal_hash(att.sha256, vt_key, cache)
                if vt_res and vt_res.get("malicious", 0) > 0:
                    findings.append(
                        Finding(
                            rule_id="ATT_THREAT_INTEL",
                            category="ThreatIntel",
                            title="Attachment hash flagged by threat intelligence",
                            description=f"VirusTotal detected {vt_res['malicious']} security vendors flagging hash {att.sha256[:16]}... ({att.filename}).",
                            weight=att_threat_w,
                        )
                    )

    # 3. FR-L4: WHOIS / RDAP domain registration age for unique domains
    seen_domains: set[str] = set()
    for link in parsed.links:
        dom = link.href_domain.lower()
        if not dom or dom in seen_domains:
            continue
        seen_domains.add(dom)
        age_info = query_domain_age(dom, cache)
        if age_info:
            age_days = age_info.get("age_days", 999)
            if age_days < 30:
                findings.append(
                    Finding(
                        rule_id="LINK_RECENT_DOMAIN",
                        category="ThreatIntel",
                        title="Recently registered domain",
                        description=f"Domain '{dom}' was registered only {age_days} days ago (< 30 days threshold).",
                        weight=domain_age_w,
                    )
                )

    return findings, skipped
