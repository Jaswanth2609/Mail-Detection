"""Tests for link checks (FR-L1, FR-L2, FR-L3)."""

from phishscan.checks.links import check_links
from phishscan.models import ExtractedLink, ParsedEmail


def test_links_text_vs_href_mismatch(config):
    """FR-L1: Flag links where visible text domain differs from href domain."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="https://evil-credential-harvester.com/login",
                anchor_text="https://www.paypal.com/signin",
                href_domain="evil-credential-harvester.com",
                anchor_domain="www.paypal.com",
            )
        ],
    )
    findings = check_links(email_data, config)
    mismatch_findings = [f for f in findings if f.rule_id == "LINK_DOMAIN_MISMATCH"]
    assert len(mismatch_findings) == 1
    assert "evil-credential-harvester.com" in mismatch_findings[0].description
    assert "www.paypal.com" in mismatch_findings[0].description


def test_links_raw_ip_address(config):
    """FR-L2: Flag raw IP address URLs."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="http://192.168.1.100/phish",
                href_domain="192.168.1.100",
            )
        ],
    )
    findings = check_links(email_data, config)
    assert any(f.rule_id == "LINK_SUSPICIOUS_STRUCTURE" and "192.168.1.100" in f.description for f in findings)


def test_links_url_shortener(config):
    """FR-L2: Flag known URL shorteners."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="https://bit.ly/3xyzSecret",
                href_domain="bit.ly",
            )
        ],
    )
    findings = check_links(email_data, config)
    assert any(f.rule_id == "LINK_SUSPICIOUS_STRUCTURE" and "bit.ly" in f.description for f in findings)


def test_links_punycode_url(config):
    """FR-L2: Flag punycode URLs."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="https://xn--pypal-4ve.com/auth",
                href_domain="xn--pypal-4ve.com",
            )
        ],
    )
    findings = check_links(email_data, config)
    assert any(f.rule_id == "LINK_SUSPICIOUS_STRUCTURE" and "xn--" in f.description for f in findings)


def test_links_lookalike_typosquat_domain(config):
    """FR-L3: Flag lookalike / typosquat domains mimicking brands."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="https://paypa1.com/login",
                href_domain="paypa1.com",
            ),
            ExtractedLink(
                url="https://microsoft-login-support.com/auth",
                href_domain="microsoft-login-support.com",
            ),
        ],
    )
    findings = check_links(email_data, config)
    lookalike_findings = [f for f in findings if f.rule_id == "LINK_LOOKALIKE_DOMAIN"]
    assert len(lookalike_findings) == 1
    assert "paypa1.com" in lookalike_findings[0].description
    assert "microsoft-login-support.com" in lookalike_findings[0].description


def test_links_legitimate_url_no_findings(config):
    """Legitimate links do not trigger false positives."""
    email_data = ParsedEmail(
        file_path="test.eml",
        links=[
            ExtractedLink(
                url="https://paypal.com/signin",
                anchor_text="https://paypal.com/signin",
                href_domain="paypal.com",
                anchor_domain="paypal.com",
            ),
            ExtractedLink(
                url="https://www.google.com/search",
                anchor_text="Search Google",
                href_domain="www.google.com",
                anchor_domain=None,
            ),
        ],
    )
    findings = check_links(email_data, config)
    assert len(findings) == 0
