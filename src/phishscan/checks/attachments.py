"""Attachment check module for PhishScan (FR-A1, FR-A2, FR-A3)."""
from __future__ import annotations

import os
from typing import Any

from phishscan.models import Finding, ParsedEmail

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "Windows PE Executable (EXE/DLL)", "application/x-dosexec"),
    (b"\x7fELF", "Linux ELF Executable", "application/x-executable"),
    (b"%PDF-", "PDF Document", "application/pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Compound Binary", "application/x-ole-storage"),
    (b"PK\x03\x04", "Zip Archive / Office XML", "application/zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", "image/png"),
    (b"\xff\xd8\xff", "JPEG Image", "image/jpeg"),
    (b"GIF87a", "GIF Image", "image/gif"),
    (b"GIF89a", "GIF Image", "image/gif"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "RAR Archive", "application/x-rar"),
]

INNOCUOUS_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3",
}


def _detect_file_type(data: bytes) -> tuple[str | None, str | None]:
    """Statically inspects byte header to identify real file type. Attachments are never executed."""
    if not data:
        return None, None

    # Try file-magic or python-magic if available
    try:
        import magic
        if hasattr(magic, "detect_from_content"):
            res = magic.detect_from_content(data[:4096])
            if res:
                mime = getattr(res, "mime_type", None) or str(res)
                desc = getattr(res, "name", None) or str(res)
                return desc, mime
        elif hasattr(magic, "Magic"):
            mime = magic.Magic(mime=True).from_buffer(data[:4096])
            desc = magic.Magic().from_buffer(data[:4096])
            return desc, mime
    except Exception:
        pass

    for prefix, desc, mime in MAGIC_SIGNATURES:
        if data.startswith(prefix):
            return desc, mime

    sample = data[:256].strip()
    if sample.startswith(b"#!/") or sample.startswith(b"<script"):
        return "Script File", "text/plain"

    return None, None


def _check_double_extension(filename: str, high_risk_exts: set[str]) -> bool:
    parts = filename.strip().lower().split(".")
    if len(parts) >= 3:
        penultimate = "." + parts[-2]
        final = "." + parts[-1]
        if penultimate in INNOCUOUS_EXTENSIONS and (
            final in high_risk_exts
            or final in {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1"}
        ):
            return True
    return False


def check_attachments(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """Execute attachment checks on all extracted attachments."""
    findings: list[Finding] = []
    weights = config.get("weights", {})
    high_risk_w = weights.get("high_risk_attachment", 25)
    double_or_mismatch_w = weights.get("attachment_type_or_double_extension", 25)

    high_risk_exts = {
        ext.lower()
        for ext in config.get("attachments", {}).get("high_risk_extensions", [])
    }

    high_risk_found: list[str] = []
    double_ext_found: list[str] = []
    mismatch_found: list[str] = []

    for att in parsed_email.attachments:
        filename = att.filename
        ext = os.path.splitext(filename)[1].lower()

        # FR-A1: High-risk extensions
        if ext in high_risk_exts:
            high_risk_found.append(f"'{filename}' has dangerous extension ({ext})")

        # FR-A2: Double extension
        if _check_double_extension(filename, high_risk_exts):
            double_ext_found.append(f"'{filename}' disguises payload with double extension")

        # FR-A3: Content type vs declared extension mismatch
        desc, mime = _detect_file_type(att.data)
        att.magic_type = mime or desc

        if att.data:
            is_pe_executable = att.data.startswith(b"MZ") or (mime and "dosexec" in mime)
            if is_pe_executable and ext in {
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"
            }:
                mismatch_found.append(
                    f"'{filename}' declared as '{ext}', but content is Windows Executable (MZ/PE)"
                )
            elif ext == ".pdf" and not att.data.startswith(b"%PDF-") and len(att.data) > 10:
                mismatch_found.append(
                    f"'{filename}' declared as PDF, but content magic does not match PDF format"
                )

    if high_risk_found:
        findings.append(
            Finding(
                rule_id="ATT_HIGH_RISK_EXT",
                category="Attachment",
                title="High-risk attachment extension detected",
                description="; ".join(high_risk_found),
                weight=high_risk_w,
            )
        )

    if double_ext_found:
        findings.append(
            Finding(
                rule_id="ATT_DOUBLE_EXT",
                category="Attachment",
                title="Double file extension detected",
                description="; ".join(double_ext_found),
                weight=double_or_mismatch_w,
            )
        )

    if mismatch_found:
        findings.append(
            Finding(
                rule_id="ATT_TYPE_MISMATCH",
                category="Attachment",
                title="Attachment type mismatch between declared extension and actual content",
                description="; ".join(mismatch_found),
                weight=double_or_mismatch_w,
            )
        )

    return findings
