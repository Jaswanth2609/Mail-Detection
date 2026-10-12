"""Tests for header checks (FR-H1, FR-H2, FR-H3)."""

from phishscan.checks.headers import check_headers
from phishscan.models import ParsedEmail


def test_headers_auth_fail(config):
    """FR-H1: Flag SPF, DKIM, DMARC failures."""
    email_data = ParsedEmail(
        file_path="test.eml",
        headers={
            "authentication-results": [
                "mx.test.com; spf=fail smtp.mailfrom=attacker.com; dkim=fail; dmarc=fail"
            ]
        },
        from_header="Test <test@attacker.com>",
        from_address="test@attacker.com",
        from_domain="attacker.com",
    )

    findings = check_headers(email_data, config)
    rule_ids = [f.rule_id for f in findings]
    assert "HDR_SPF_FAIL" in rule_ids
    assert "HDR_DKIM_FAIL" in rule_ids
    assert "HDR_DMARC_FAIL" in rule_ids


def test_headers_auth_missing(config):
    """FR-H1: Flag missing authentication headers."""
    email_data = ParsedEmail(
        file_path="test.eml",
        headers={},
        from_header="Test <test@attacker.com>",
        from_address="test@attacker.com",
        from_domain="attacker.com",
    )

    findings = check_headers(email_data, config)
    assert any(f.rule_id == "HDR_AUTH_MISSING" for f in findings)


def test_headers_auth_pass_no_findings(config):
    """FR-H1: Pass statuses do not trigger findings."""
    email_data = ParsedEmail(
        file_path="test.eml",
        headers={
            "authentication-results": [
                "mx.google.com; spf=pass; dkim=pass header.d=google.com; dmarc=pass"
            ]
        },
        from_header="Google <support@google.com>",
        from_address="support@google.com",
        from_domain="google.com",
    )

    findings = check_headers(email_data, config)
    auth_findings = [f for f in findings if f.category == "Header" and "AUTH" in f.rule_id or "SPF" in f.rule_id]
    assert len(auth_findings) == 0


def test_headers_domain_mismatch(config):
    """FR-H2: Flag domain mismatch between From, Reply-To, and Return-Path."""
    email_data = ParsedEmail(
        file_path="test.eml",
        from_header="Acme Corp <info@acme.com>",
        from_address="info@acme.com",
        from_domain="acme.com",
        reply_to_address="stealth@shadowmail.org",
        reply_to_domain="shadowmail.org",
        return_path_address="bounce@unrelated.net",
        return_path_domain="unrelated.net",
    )

    findings = check_headers(email_data, config)
    mismatch_findings = [f for f in findings if f.rule_id == "HDR_DOMAIN_MISMATCH"]
    assert len(mismatch_findings) == 1
    assert "shadowmail.org" in mismatch_findings[0].description
    assert "unrelated.net" in mismatch_findings[0].description


def test_headers_display_name_spoof_brand(config):
    """FR-H3: Flag well-known brand display-name spoofing with unrelated sender domain."""
    email_data = ParsedEmail(
        file_path="test.eml",
        from_header="Microsoft Security Support <service@hacker-host.com>",
        from_display_name="Microsoft Security Support",
        from_address="service@hacker-host.com",
        from_domain="hacker-host.com",
    )

    findings = check_headers(email_data, config)
    spoof_findings = [f for f in findings if f.rule_id == "HDR_DISPLAY_SPOOF_BRAND"]
    assert len(spoof_findings) == 1
    assert "Microsoft" in spoof_findings[0].description


def test_headers_display_name_spoof_role(config):
    """FR-H3: Flag organizational role display-name spoofing from public webmail."""
    email_data = ParsedEmail(
        file_path="test.eml",
        from_header="Corporate CEO Office <ceo.urgent.tasks@gmail.com>",
        from_display_name="Corporate CEO Office",
        from_address="ceo.urgent.tasks@gmail.com",
        from_domain="gmail.com",
    )

    findings = check_headers(email_data, config)
    role_findings = [f for f in findings if f.rule_id == "HDR_DISPLAY_SPOOF_ROLE"]
    assert len(role_findings) == 1
    assert "ceo" in role_findings[0].description.lower()
