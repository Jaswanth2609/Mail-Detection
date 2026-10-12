"""Tests for body checks (FR-B1, FR-B2, FR-B3)."""

from phishscan.checks.body import check_body
from phishscan.models import ParsedEmail


def test_body_hidden_text_css_display_none(config):
    """FR-B1: Flag display:none in HTML body."""
    email_data = ParsedEmail(
        file_path="test.eml",
        html_body="<div>Visible message <span style='display: none;'>hidden keywords</span></div>",
    )
    findings = check_body(email_data, config)
    assert any(f.rule_id == "BODY_HIDDEN_TEXT" for f in findings)


def test_body_hidden_text_font_size_zero(config):
    """FR-B1: Flag font-size:0 in HTML body."""
    email_data = ParsedEmail(
        file_path="test.eml",
        html_body="<p style='font-size: 0px;'>hidden anti-spam filler</p>",
    )
    findings = check_body(email_data, config)
    assert any(f.rule_id == "BODY_HIDDEN_TEXT" for f in findings)


def test_body_hidden_text_white_on_white(config):
    """FR-B1: Flag white text on white background."""
    email_data = ParsedEmail(
        file_path="test.eml",
        html_body="<div style='color: #ffffff; background-color: #ffffff;'>evasion text</div>",
    )
    findings = check_body(email_data, config)
    assert any(f.rule_id == "BODY_HIDDEN_TEXT" for f in findings)


def test_body_invisible_unicode(config):
    """FR-B2: Flag zero-width spaces and invisible formatting chars."""
    email_data = ParsedEmail(
        file_path="test.eml",
        text_body="P\u200ba\u200by\u200bP\u200ba\u200bl account security verification",
    )
    findings = check_body(email_data, config)
    assert any(f.rule_id == "BODY_INVISIBLE_CHARS" for f in findings)


def test_body_urgency_and_credential_phrases(config):
    """FR-B3: Flag urgency and threat language from configurable keyword list."""
    email_data = ParsedEmail(
        file_path="test.eml",
        subject="URGENT ACTION REQUIRED",
        text_body="Your account will be suspended within 24 hours if you fail to verify your account.",
    )
    findings = check_body(email_data, config)
    urgency_findings = [f for f in findings if f.rule_id == "BODY_URGENCY_LANGUAGE"]
    assert len(urgency_findings) == 1
    assert "urgent action required" in urgency_findings[0].description.lower()
    assert "within 24 hours" in urgency_findings[0].description.lower()


def test_body_clean_message_no_findings(config):
    """Clean body does not trigger findings."""
    email_data = ParsedEmail(
        file_path="test.eml",
        subject="Project meeting scheduled",
        text_body="Hi team, our sprint retrospective is set for Wednesday at 10 AM.",
        html_body="<p>Hi team, our sprint retrospective is set for Wednesday at 10 AM.</p>",
    )
    findings = check_body(email_data, config)
    assert len(findings) == 0
