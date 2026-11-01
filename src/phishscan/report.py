"""Reporting module for PhishScan (FR-R1, FR-R2, FR-R3, Appendix A)."""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from phishscan.models import AnalysisResult, BenchmarkResult

# ANSI styling
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
CYAN = "\033[96m"


def _severity_color(sev: str) -> str:
    s = sev.upper()
    if s == "CRITICAL":
        return RED
    elif s == "HIGH":
        return MAGENTA
    elif s == "MEDIUM":
        return YELLOW
    return GREEN


def format_terminal_report(
    result: AnalysisResult, verbose: bool = False, use_color: bool = True
) -> str:
    """FR-R1: Formats analysis result as human-readable terminal output matching Appendix A."""
    c_b = BOLD if use_color else ""
    c_d = DIM if use_color else ""
    c_r = RESET if use_color else ""
    c_s = _severity_color(result.severity) if use_color else ""

    llm_info = "no"
    if result.llm:
        llm_info = f"yes (confidence {result.llm.confidence:.2f}, verdict: {result.llm.verdict})"

    lines: list[str] = []
    lines.append(
        f"File: {result.file:<24} Severity: {c_s}{result.severity.upper():<8}{c_r} "
        f"Final score: {c_s}{result.final_score}/100{c_r}"
    )
    lines.append(f"Rule score: {result.rule_score:<18} LLM review: {llm_info}")
    lines.append("")

    lines.append(f"{c_b}Findings{c_r}")
    if result.findings:
        for f in result.findings:
            weight_str = f"+{f.weight}"
            lines.append(f"  {c_s}{weight_str:<4}{c_r} {f.description}  {c_d}({f.rule_id}){c_r}")
    else:
        lines.append(f"  {c_s}No suspicious indicators detected.{c_r}")

    if result.llm and (result.llm.reasons or result.llm.tactics):
        lines.append("")
        lines.append(f"{c_b}LLM explanation{c_r}")
        for reason in result.llm.reasons:
            lines.append(f"  • {reason}")
        if result.llm.tactics:
            lines.append(f"  {c_d}Observed tactics: {', '.join(result.llm.tactics)}{c_r}")

    if result.skipped:
        lines.append("")
        for skip in result.skipped:
            lines.append(f"{c_d}Skipped: {skip}{c_r}")

    if verbose:
        lines.append("")
        lines.append(f"{c_b}Extracted IOCs{c_r}")
        lines.append(f"  URLs ({len(result.iocs.urls)}):")
        for u in result.iocs.urls[:5]:
            lines.append(f"    - {u}")
        if len(result.iocs.urls) > 5:
            lines.append(f"    ... (+{len(result.iocs.urls)-5} more)")
        lines.append(f"  Domains ({len(result.iocs.domains)}): {', '.join(result.iocs.domains[:8])}")
        lines.append(f"  Hashes ({len(result.iocs.hashes)}): {', '.join(result.iocs.hashes)}")

    return "\n".join(lines)


def format_json_report(results: AnalysisResult | list[AnalysisResult]) -> str:
    """FR-R2, Section 7.5: JSON export schema."""
    if isinstance(results, list):
        data = [r.to_dict() for r in results]
    else:
        data = results.to_dict()
    return json.dumps(data, indent=2)


def format_csv_report(results: list[AnalysisResult] | AnalysisResult) -> str:
    """FR-R2: CSV batch export format."""
    items = results if isinstance(results, list) else [results]
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "file", "final_score", "severity", "rule_score",
        "llm_verdict", "llm_confidence", "findings_count",
        "urls_count", "domains_count", "hashes_count", "skipped_count"
    ])
    for item in items:
        writer.writerow([
            item.file,
            item.final_score,
            item.severity,
            item.rule_score,
            item.llm.verdict if item.llm else "none",
            round(item.llm.confidence, 2) if item.llm else "",
            len(item.findings),
            len(item.iocs.urls),
            len(item.iocs.domains),
            len(item.iocs.hashes),
            len(item.skipped),
        ])
    return out.getvalue()


def format_html_report(results: list[AnalysisResult] | AnalysisResult) -> str:
    """FR-R2: Generate a self-contained, beautifully styled single-file HTML report."""
    items = results if isinstance(results, list) else [results]

    card_sections: list[str] = []
    for res in items:
        sev_class = res.severity.lower()
        findings_html: list[str] = []
        if res.findings:
            for f in res.findings:
                findings_html.append(
                    f"<tr>"
                    f"<td><span class='badge badge-weight'>+{f.weight}</span></td>"
                    f"<td><strong>{html.escape(f.category)}</strong></td>"
                    f"<td>{html.escape(f.description)}</td>"
                    f"<td><code>{html.escape(f.rule_id)}</code></td>"
                    f"</tr>"
                )
        else:
            findings_html.append("<tr><td colspan='4'>No threat indicators detected.</td></tr>")

        llm_html = ""
        if res.llm:
            reasons_li = "".join(f"<li>{html.escape(r)}</li>" for r in res.llm.reasons)
            tactics_str = ", ".join(html.escape(t) for t in res.llm.tactics)
            llm_html = f"""
            <div class="llm-box">
              <h3>LLM Review Verdict: <strong>{res.llm.verdict.upper()}</strong> (Confidence: {res.llm.confidence:.2f})</h3>
              <ul>{reasons_li}</ul>
              {f"<p class='tactics'>Tactics: {tactics_str}</p>" if tactics_str else ""}
            </div>
            """

        skipped_html = ""
        if res.skipped:
            items_li = "".join(f"<li>{html.escape(s)}</li>" for s in res.skipped)
            skipped_html = f"<div class='skipped-box'><h4>Skipped Checks / Notes:</h4><ul>{items_li}</ul></div>"

        iocs_html = f"""
        <div class="iocs-box">
          <h4>Extracted IOCs</h4>
          <p><strong>Domains:</strong> {", ".join(html.escape(d) for d in res.iocs.domains) or "None"}</p>
          <p><strong>URLs ({len(res.iocs.urls)}):</strong> {", ".join(html.escape(u) for u in res.iocs.urls[:5]) or "None"}</p>
          <p><strong>Attachment Hashes:</strong> {", ".join(f"<code>{html.escape(h[:16])}...</code>" for h in res.iocs.hashes) or "None"}</p>
        </div>
        """

        card_sections.append(f"""
        <div class="card">
          <div class="card-header">
            <div>
              <h2>{html.escape(res.file)}</h2>
              <span class="timestamp">Analysed: {html.escape(res.analysed_at)}</span>
            </div>
            <div class="score-badge {sev_class}">
              <div class="score-number">{res.final_score}/100</div>
              <div class="severity-label">{res.severity.upper()}</div>
            </div>
          </div>
          <div class="meta-bar">
            <span><strong>Rule Score:</strong> {res.rule_score}/100</span>
            <span><strong>LLM Review:</strong> {"Yes" if res.llm else "No"}</span>
            <span><strong>Findings:</strong> {len(res.findings)}</span>
          </div>
          <table class="findings-table">
            <thead>
              <tr><th>Weight</th><th>Category</th><th>Description</th><th>Rule ID</th></tr>
            </thead>
            <tbody>
              {"".join(findings_html)}
            </tbody>
          </table>
          {llm_html}
          {iocs_html}
          {skipped_html}
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishScan Threat Analysis Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    h1 {{ color: #38bdf8; font-size: 24px; border-bottom: 1px solid #334155; padding-bottom: 12px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 20px; margin-bottom: 24px; }}
    .card-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 12px; }}
    .card-header h2 {{ margin: 0 0 6px 0; font-size: 18px; color: #e2e8f0; }}
    .timestamp {{ color: #94a3b8; font-size: 13px; }}
    .score-badge {{ text-align: center; padding: 8px 16px; border-radius: 6px; }}
    .score-badge.low {{ background: #064e3b; color: #6ee7b7; }}
    .score-badge.medium {{ background: #78350f; color: #fcd34d; }}
    .score-badge.high {{ background: #701a75; color: #f0abfc; }}
    .score-badge.critical {{ background: #7f1d1d; color: #fca5a5; }}
    .score-number {{ font-size: 22px; font-weight: bold; }}
    .severity-label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; }}
    .meta-bar {{ display: flex; gap: 24px; margin: 16px 0; color: #94a3b8; font-size: 14px; }}
    .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }}
    .findings-table th {{ text-align: left; background: #0f172a; padding: 10px; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #334155; }}
    .findings-table td {{ padding: 10px; border-bottom: 1px solid #334155; }}
    .badge-weight {{ background: #334155; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-weight: bold; }}
    code {{ background: #0f172a; padding: 2px 5px; border-radius: 3px; font-size: 12px; color: #cbd5e1; }}
    .llm-box {{ background: #172554; border-left: 4px solid #38bdf8; padding: 12px 16px; border-radius: 4px; margin-top: 16px; }}
    .llm-box h3 {{ margin: 0 0 8px 0; font-size: 15px; color: #bae6fd; }}
    .llm-box ul {{ margin: 0; padding-left: 20px; }}
    .tactics {{ margin: 8px 0 0 0; font-size: 13px; color: #93c5fd; }}
    .iocs-box {{ background: #0f172a; padding: 12px; border-radius: 6px; margin-top: 14px; font-size: 13px; }}
    .iocs-box h4 {{ margin: 0 0 6px 0; color: #cbd5e1; }}
    .iocs-box p {{ margin: 4px 0; color: #94a3b8; word-break: break-all; }}
    .skipped-box {{ font-size: 13px; color: #94a3b8; margin-top: 12px; }}
    .skipped-box ul {{ margin: 4px 0; padding-left: 20px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>PhishScan Email Security Report</h1>
    {"".join(card_sections)}
  </div>
</body>
</html>
"""


def format_benchmark_report(bench: BenchmarkResult) -> str:
    """Format benchmark evaluation metrics for terminal."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("PHISHSCAN BENCHMARK EVALUATION")
    lines.append("=" * 60)
    lines.append(f"Total Samples Scanned:    {bench.total_samples}")
    lines.append(f"  • Phishing Samples:     {bench.phishing_samples}")
    lines.append(f"  • Legitimate Samples:   {bench.legit_samples}")
    lines.append("-" * 60)
    lines.append("CONFUSION MATRIX METRICS:")
    lines.append(f"  True Positives (TP):    {bench.true_positives}")
    lines.append(f"  False Negatives (FN):   {bench.false_negatives}")
    lines.append(f"  True Negatives (TN):    {bench.true_negatives}")
    lines.append(f"  False Positives (FP):   {bench.false_positives}")
    lines.append("-" * 60)
    lines.append(f"Detection Rate (TP/Phish): {bench.detection_rate * 100:.1f}%  (Target: >= 85%)")
    lines.append(f"False-Positive Rate:       {bench.false_positive_rate * 100:.1f}%  (Target: <= 10%)")
    lines.append(f"Overall Accuracy:          {bench.accuracy * 100:.1f}%")
    lines.append(f"Precision:                 {bench.precision * 100:.1f}%")
    lines.append(f"Recall:                    {bench.recall * 100:.1f}%")
    lines.append(f"F1-Score:                  {bench.f1_score * 100:.1f}%")
    lines.append("=" * 60)
    return "\n".join(lines)


def write_report(content: str, out_path: str | Path | None = None) -> None:
    """FR-R3: Output report string to file or stdout."""
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    else:
        print(content)
