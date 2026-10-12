"""Tests for attachment checks (FR-A1, FR-A2, FR-A3)."""

from phishscan.checks.attachments import check_attachments
from phishscan.models import AttachmentInfo, ParsedEmail


def test_attachments_high_risk_extension(config):
    """FR-A1: Flag high-risk executable or script extensions."""
    email_data = ParsedEmail(
        file_path="test.eml",
        attachments=[
            AttachmentInfo(
                filename="setup.exe",
                content_type="application/octet-stream",
                size=1024,
                data=b"dummy",
            ),
            AttachmentInfo(
                filename="script.vbs",
                content_type="text/plain",
                size=512,
                data=b"dummy",
            ),
        ],
    )
    findings = check_attachments(email_data, config)
    assert any(f.rule_id == "ATT_HIGH_RISK_EXT" for f in findings)


def test_attachments_double_extension(config):
    """FR-A2: Flag double file extensions disguise technique."""
    email_data = ParsedEmail(
        file_path="test.eml",
        attachments=[
            AttachmentInfo(
                filename="invoice_march.pdf.exe",
                content_type="application/pdf",
                size=2048,
                data=b"dummy",
            )
        ],
    )
    findings = check_attachments(email_data, config)
    assert any(f.rule_id == "ATT_DOUBLE_EXT" for f in findings)


def test_attachments_content_type_mismatch(config):
    """FR-A3: Flag mismatch between declared extension and actual content magic."""
    # Disguised Windows PE executable with MZ header declared as innocent PDF
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    email_data = ParsedEmail(
        file_path="test.eml",
        attachments=[
            AttachmentInfo(
                filename="official_receipt.pdf",
                content_type="application/pdf",
                size=len(pe_bytes),
                data=pe_bytes,
            )
        ],
    )
    findings = check_attachments(email_data, config)
    assert any(f.rule_id == "ATT_TYPE_MISMATCH" for f in findings)


def test_attachments_clean_pdf(config):
    """Valid PDF attachment does not trigger findings."""
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    email_data = ParsedEmail(
        file_path="test.eml",
        attachments=[
            AttachmentInfo(
                filename="monthly_report.pdf",
                content_type="application/pdf",
                size=len(pdf_bytes),
                data=pdf_bytes,
            )
        ],
    )
    findings = check_attachments(email_data, config)
    assert len(findings) == 0
