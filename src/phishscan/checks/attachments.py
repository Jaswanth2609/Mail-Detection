"""Attachment check module for PhishScan (FR-A1, FR-A2, FR-A3)."""

from __future__ import annotations

import os
from pathlib import PurePath
import re
from typing import Any

from phishscan.models import AttachmentInfo, Finding, ParsedEmail

# Well-known signatures for static magic byte identification
MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "Windows PE Executable (EXE/DLL)", "application/x-dosexec"),
    (b"\x7fELF", "Linux ELF Executable", "application/x-executable"),
    (b"%PDF-", "PDF Document", "application/pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Compound Binary (Doc/XLS/PPT)", "application/x-ole-storage"),
    (b"PK\x03\x04", "Zip Archive / Office OpenXML", "application/zip"),
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
    """
    Statically inspects byte header to identify real file type.
    Uses system magic if available, with built-in magic-bytes fallback.
    Attachments are NEVER executed.
    """
    if not data:
        return None, None

    # 1. Try file-magic or python-magic if available
    try:
        import magic
        # Try detect_from_content (file-magic)
        if hasattr(magic, "detect_from_content"):
            res = magic.detect_from_content(data[:4096])
            if res:
                mime = getattr(res, "mime_type", None) or str(res)
                desc = getattr(res, "name", None) or str(res)
                return desc, mime
        # Try Magic().from_buffer (python-magic)
        elif hasattr(magic, "Magic"):
            m = magic.Magic(mime=True)
            mime = m.from_buffer(data[:4096])
            desc_m = magic.Magic()
            desc = desc_m.from_buffer(data[:4096])
            return desc, mime
    except Exception:
        pass

    # 2. Pure Python magic bytes inspection fallback
    for magic_prefix, desc, mime in MAGIC_SIGNATURES:
        if data.startswith(magic_prefix):
            return desc, mime

    # Check for shell script or text script
    sample = data[:256].strip()
    if sample.startswith(b"#!/") or sample.startswith(b"<script"):
        return "Script File", "text/plain"

    return None, None


def _check_double_extension(filename: str, high_risk_exts: set[str]) -> bool:
    """
    Detects double extensions like 'invoice.pdf.exe' or 'statement.docx.scr'.
    """
    clean_name = filename.strip().lower()
    parts = clean_name.split(".")
    if len(parts) >= 3:
        penultimate = "." + parts[-2]
        final = "." + parts[-1]
        if penultimate in INNOCUOUS_EXTENSIONS and (final in high_risk_exts or final in {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1"}):
            return True
    return False


def check_attachments(parsed_email: ParsedEmail, config: dict[str, Any]) -> list[Finding]:
    """
    Executes attachment checks.
    
    FR-A1: Flag high-risk extensions.
    FR-A2: Flag double extensions.
    FR-A3: Detect real file type from content and flag mismatch with declared extension/MIME.
    """
    findings: list[Finding] = []
    weights = config.get("weights", {})
    high_risk_weight = weights.get("high_risk_attachment", 25)
    double_or_mismatch_weight = weights.get("attachment_type_or_double_extension", 25)

    high_risk_exts = {
        ext.lower() for ext in config.get("attachments", {}).get("high_risk_extensions", [])
    }

    flagged_high_risk: list[str] = []
    flagged_double_ext: list[str] = []
    flagged_mismatch: list[str] = []

    for att in parsed_email.attachments:
        filename = att.filename
        ext = os.path.splitext(filename)[1].lower()

        # --- FR-A1: High-risk extensions ---
        if ext in high_risk_exts:
            flagged_high_risk.append(f"'{filename}' has dangerous extension ({ext})")

        # --- FR-A2: Double extensions ---
        if _check_double_extension(filename, high_risk_exts):
            flagged_double_ext.append(f"'{filename}' disguises executable payload with double extension")

        # --- FR-A3: Static content inspection & mismatch detection ---
        desc, mime = _detect_file_type(att.data)
        att.magic_type = mime or desc

        if att.data and len(att.data) > 0:
            # Check for executable disguised as document/image
            is_executable = False
            if att.data.startswith(b"MZ") or (mime and "dosexec" in mime) or (desc and "PE32" in desc):
                is_executable = True

            if is_executable and ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"):
                flagged_mismatch.append(
                    f"'{filename}' declared as '{ext}' / '{att.content_type}', but actual content is Windows Executable (PE/MZ)"
                )
            elif ext == ".pdf" and not att.data.startswith(b"%PDF-") and len(att.data) > 10:
                # Declared as PDF but missing PDF signature and not empty
                if is_executable:
                    flagged_mismatch.append(
                        f"'{filename}' declared as PDF, but content is Windows Executable"
                    )
                elif att.data.startswith(b"PK\x03\x04") or att.data.startswith(b"\x7fELF"):
                    flagged_mismatch.append(
                        f"'{filename}' declared as PDF, but content magic does not match PDF"
                    )

    if flagged_high_risk:
        findings.append(
            Finding(
                rule_id="ATT_HIGH_RISK_EXT",
                category="Attachment",
                title="High-risk attachment extension detected",
                description="; ".join(flagged_high_risk),
                weight=high_risk_weight,
            )
        )

    if flagged_double_ext:
        findings.append(
            Finding(
                rule_id="ATT_DOUBLE_EXT",
                category="Attachment",
                title="Double file extension detected",
                description="; ".join(flagged_double_ext),
                weight=double_or_mismatch_weight,
            )
        )

    if flagged_mismatch:
        findings.append(
            Finding(
                rule_id="ATT_TYPE_MISMATCH",
                category="Attachment",
                title="Attachment type mismatch between declared extension and actual content",
                description="; ".join(flagged_mismatch),
                weight=double_or_mismatch_weight,
            )
        )

    return findings
