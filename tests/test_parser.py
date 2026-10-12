"""Tests for email parser (FR-P1 to FR-P6)."""

from pathlib import Path
import pytest

from phishscan.parser import ParserError, parse_eml


def test_parser_missing_file():
    """FR-P5: Missing file raises ParserError with exit_code 2."""
    with pytest.raises(ParserError) as exc_info:
        parse_eml("tests/fixtures/non_existent_file.eml")
    assert exc_info.value.exit_code == 2
    assert "not found" in str(exc_info.value).lower()


def test_parser_empty_file(tmp_path):
    """FR-P5: Empty file raises ParserError with exit_code 2."""
    empty_file = tmp_path / "empty.eml"
    empty_file.write_text("")
    with pytest.raises(ParserError) as exc_info:
        parse_eml(empty_file)
    assert exc_info.value.exit_code == 2
    assert "empty" in str(exc_info.value).lower()


def test_parser_extract_headers_and_body(tmp_path):
    """FR-P1 & FR-P2: Extract headers, plain-text, and base64/quoted-printable bodies."""
    eml_file = tmp_path / "sample.eml"
    eml_file.write_text(
        "From: Alice <alice@example.com>\n"
        "To: Bob <bob@example.com>\n"
        "Subject: Meeting Notes\n"
        "Date: Mon, 12 Oct 2026 12:00:00 +0000\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "Content-Transfer-Encoding: quoted-printable\n\n"
        "Hello Bob, this is a plain text test=20with quoted printable.\n"
    )

    parsed = parse_eml(eml_file)
    assert parsed.from_address == "alice@example.com"
    assert parsed.from_display_name == "Alice"
    assert parsed.from_domain == "example.com"
    assert parsed.subject == "Meeting Notes"
    assert "quoted printable" in parsed.text_body


def test_parser_extract_urls_html_and_text(tmp_path):
    """FR-P3: Extract all URLs preserving anchor text and target."""
    eml_file = tmp_path / "links.eml"
    eml_file.write_text(
        "From: Sender <sender@example.com>\n"
        "Content-Type: text/html; charset=\"utf-8\"\n\n"
        "<html><body>\n"
        "<a href=\"https://target.com/page\">https://anchor-display.com</a>\n"
        "<p>Also check out https://raw-link.org/test in plain text</p>\n"
        "</body></html>\n"
    )

    parsed = parse_eml(eml_file)
    assert len(parsed.links) >= 2
    html_link = next(l for l in parsed.links if "target.com" in l.url)
    assert html_link.url == "https://target.com/page"
    assert html_link.anchor_text == "https://anchor-display.com"
    assert html_link.anchor_domain == "anchor-display.com"
    assert html_link.href_domain == "target.com"


def test_parser_extract_attachment_metadata(tmp_path):
    """FR-P4: Extract attachment filename, Content-Type, and size safely."""
    eml_file = tmp_path / "attachment.eml"
    eml_file.write_text(
        "From: Sender <sender@example.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"====BOUNDARY====\"\n\n"
        "--====BOUNDARY====\n"
        "Content-Type: text/plain\n\n"
        "Body content here\n"
        "--====BOUNDARY====\n"
        "Content-Type: application/pdf; name=\"report.pdf\"\n"
        "Content-Disposition: attachment; filename=\"report.pdf\"\n"
        "Content-Transfer-Encoding: base64\n\n"
        "JVBERi0xLjQKMSAwIG9iajw8Pj5lbmRvYmoKc3RhcnR4cmVmCjI1CiUlRU9G\n"
        "--====BOUNDARY====--\n"
    )

    parsed = parse_eml(eml_file)
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "report.pdf"
    assert att.content_type == "application/pdf"
    assert att.size > 0
    assert att.data.startswith(b"%PDF-")


def test_parser_tolerate_malformed_headers(tmp_path):
    """FR-P6: Tolerate malformed headers without crashing."""
    eml_file = tmp_path / "malformed.eml"
    eml_file.write_text(
        "From: ??? Unknown <malformed@@@domain..com>\n"
        "Subject: \x00\xff Invalid-Byte-Header\n"
        "Malformed-Header: missing colon or weird format\n"
        "Authentication-Results: ;;; broken;;;\n\n"
        "Message body with content.\n"
    )

    parsed = parse_eml(eml_file)
    assert parsed is not None
    assert "Message body with content" in parsed.text_body
