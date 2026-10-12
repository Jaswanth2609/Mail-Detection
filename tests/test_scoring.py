"""Tests for scoring engine (FR-S1, FR-S2, FR-S3, NFR-2, NFR-8)."""

from phishscan.models import Finding, ParsedEmail
from phishscan.scoring import calculate_severity, evaluate_email


def test_calculate_severity_bands(config):
    """FR-S3: Severity bands correctly map scores."""
    bands = config["severity_bands"]
    assert calculate_severity(0, bands) == "Low"
    assert calculate_severity(24, bands) == "Low"
    assert calculate_severity(25, bands) == "Medium"
    assert calculate_severity(49, bands) == "Medium"
    assert calculate_severity(50, bands) == "High"
    assert calculate_severity(74, bands) == "High"
    assert calculate_severity(75, bands) == "Critical"
    assert calculate_severity(100, bands) == "Critical"


def test_scoring_cap_at_100(config, monkeypatch):
    """FR-S2: Final score capped at 100 regardless of excessive finding weights."""
    email_data = ParsedEmail(file_path="huge_threat.eml")

    # Mock all checks to return multiple heavy findings
    heavy_findings = [
        Finding(rule_id=f"TEST_{i}", category="Custom", title=f"Risk {i}", description="", weight=40)
        for i in range(5)
    ]
    monkeypatch.setattr("phishscan.scoring.check_headers", lambda p, c: heavy_findings[:2])
    monkeypatch.setattr("phishscan.scoring.check_body", lambda p, c: heavy_findings[2:])
    monkeypatch.setattr("phishscan.scoring.check_links", lambda p, c: [])
    monkeypatch.setattr("phishscan.scoring.check_attachments", lambda p, c: [])

    result = evaluate_email(email_data, config)
    assert result.score == 100
    assert result.severity == "Critical"


def test_scoring_auth_failure_capped_at_30(config, monkeypatch):
    """Auth failures (SPF, DKIM, DMARC, missing) capped at auth_failure_max (30)."""
    email_data = ParsedEmail(file_path="auth_fails.eml")

    auth_findings = [
        Finding(rule_id="HDR_SPF_FAIL", category="Header", title="SPF Fail", description="", weight=15),
        Finding(rule_id="HDR_DKIM_FAIL", category="Header", title="DKIM Fail", description="", weight=15),
        Finding(rule_id="HDR_DMARC_FAIL", category="Header", title="DMARC Fail", description="", weight=15),
    ]
    monkeypatch.setattr("phishscan.scoring.check_headers", lambda p, c: auth_findings)
    monkeypatch.setattr("phishscan.scoring.check_body", lambda p, c: [])
    monkeypatch.setattr("phishscan.scoring.check_links", lambda p, c: [])
    monkeypatch.setattr("phishscan.scoring.check_attachments", lambda p, c: [])

    result = evaluate_email(email_data, config)
    # Sum is 45, but auth failure max is 30
    assert result.score == 30
    assert result.severity == "Medium"


def test_scoring_fault_isolation_nfr2(config, monkeypatch):
    """NFR-2: An unexpected check failure is caught and recorded in skipped_checks."""
    email_data = ParsedEmail(file_path="safe.eml")

    def broken_check(p, c):
        raise RuntimeError("Simulated crash in third-party engine")

    monkeypatch.setattr("phishscan.scoring.check_body", broken_check)

    result = evaluate_email(email_data, config)
    assert len(result.skipped_checks) == 1
    assert "Simulated crash" in result.skipped_checks[0]
    # Execution completed without unhandled exception
    assert result.score >= 0


def test_scoring_determinism_nfr8(config):
    """NFR-8: Same input + same config produces identical score and severity."""
    email_data = ParsedEmail(
        file_path="test.eml",
        from_display_name="PayPal",
        from_domain="evil.com",
        subject="Action Required",
        text_body="verify your account immediately",
    )

    res1 = evaluate_email(email_data, config)
    res2 = evaluate_email(email_data, config)

    assert res1.score == res2.score
    assert res1.severity == res2.severity
    assert len(res1.findings) == len(res2.findings)
