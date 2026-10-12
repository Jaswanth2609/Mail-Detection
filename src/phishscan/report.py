"""Reporting module for PhishScan (FR-R1, FR-R2, FR-R3)."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import TextIO

from phishscan.models import AnalysisResult

# ANSI Color codes for terminal styling
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"


def _supports_color(stream: TextIO) -> bool:
    """Check if stream supports ANSI colors."""
    return hasattr(stream, "isatty") and stream.isatty()


def format_terminal_report(result: AnalysisResult, verbose: bool = False, use_color: bool = True) -> str:
    """
    FR-R1: Formats an analysis report for human-readable terminal display.
    """
    # Color mapping for severity
    sev_upper = result.severity.upper()
    sev_color = COLOR_GREEN
    if sev_upper == "CRITICAL":
        sev_color = COLOR_RED
    elif sev_upper == "HIGH":
        sev_color = COLOR_MAGENTA
    elif sev_upper == "MEDIUM":
        sev_color = COLOR_YELLOW

    c_b = COLOR_BOLD if use_color else ""
    c_d = COLOR_DIM if use_color else ""
    c_s = sev_color if use_color else ""
    c_r = COLOR_RESET if use_color else ""
    c_c = COLOR_CYAN if use_color else ""

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"{c_b}PHISHSCAN EMAIL THREAT REPORT{c_r}")
    lines.append("=" * 70)
    lines.append(f"{c_b}File:{c_r}      {result.file_path}")
    lines.append(f"{c_b}Subject:{c_r}   {result.summary.get('subject', 'N/A')}")
    lines.append(f"{c_b}Sender:{c_r}    {result.summary.get('from', 'N/A')}")
    if result.summary.get("reply_to"):
        lines.append(f"{c_b}Reply-To:{c_r}  {result.summary.get('reply_to')}")
    lines.append(f"{c_b}Date:{c_r}      {result.summary.get('date', 'N/A')}")
    lines.append("-" * 70)
    lines.append(
        f"{c_b}Score:{c_r}     {c_s}{result.score}/100{c_r}   "
        f"{c_b}Severity:{c_r} {c_s}{result.severity.upper()}{c_r}"
    )
    lines.append("-" * 70)

    if result.findings:
        lines.append(f"{c_b}FINDINGS ({len(result.findings)} detected):{c_r}")
        for idx, finding in enumerate(result.findings, 1):
            lines.append(
                f"  {idx}. [{c_c}{finding.category.upper()}{c_r}] "
                f"{c_b}{finding.title}{c_r} (Weight: {finding.weight})"
            )
            lines.append(f"     {c_d}{finding.description}{c_r}")
    else:
        lines.append(f"{c_s}No suspicious indicators or security anomalies detected.{c_r}")

    if result.skipped_checks:
        lines.append("-" * 70)
        lines.append(f"{c_b}SKIPPED CHECKS / WARNINGS:{c_r}")
        for skip in result.skipped_checks:
            lines.append(f"  - {skip}")

    if verbose:
        lines.append("-" * 70)
        lines.append(f"{c_b}VERBOSE SUMMARY METADATA:{c_r}")
        for k, v in result.summary.items():
            lines.append(f"  • {k}: {v}")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_json_report(result: AnalysisResult | list[AnalysisResult]) -> str:
    """
    FR-R2: Formats analysis result as machine-readable JSON.
    """
    if isinstance(result, list):
        data = [r.to_dict() for r in result]
    else:
        data = result.to_dict()
    return json.dumps(data, indent=2)


def write_report(content: str, out_path: str | Path | None = None) -> None:
    """
    FR-R3: Prints to stdout or writes to a designated file.
    """
    if out_path:
        dest = Path(out_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    else:
        print(content)
