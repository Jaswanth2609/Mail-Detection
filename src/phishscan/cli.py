"""Command-line interface for PhishScan (FR-C1, FR-C2, FR-C3)."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

from phishscan.intel import ThreatIntelCache
from phishscan.models import AnalysisResult, BenchmarkResult
from phishscan.parser import ParserError, parse_eml
from phishscan.report import (
    format_benchmark_report,
    format_csv_report,
    format_html_report,
    format_json_report,
    format_terminal_report,
    write_report,
)
from phishscan.scoring import evaluate_email

SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def load_config(custom_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from custom path, current working dir, or package default."""
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    candidates.append(Path.cwd() / "config.toml")
    candidates.append(Path(__file__).resolve().parent.parent.parent / "config.toml")

    for path in candidates:
        if path.is_file():
            try:
                with path.open("rb") as f:
                    return tomllib.load(f)
            except Exception as err:
                sys.stderr.write(f"Warning: Failed to parse configuration from {path}: {err}\n")

    return {
        "weights": {
            "auth_failure": 15,
            "auth_failure_max": 30,
            "domain_mismatch": 15,
            "display_name_spoofing": 20,
            "received_anomaly": 10,
            "hidden_text": 15,
            "invisible_characters": 10,
            "urgency_credential_language": 10,
            "low_text_image_ratio": 10,
            "link_text_href_mismatch": 25,
            "suspicious_url_structure": 15,
            "lookalike_domain": 25,
            "recent_domain": 15,
            "threat_intel_url": 30,
            "high_risk_attachment": 25,
            "attachment_type_or_double_extension": 25,
            "threat_intel_attachment": 40,
        },
        "severity_bands": {
            "low_max": 24,
            "medium_max": 49,
            "high_max": 74,
            "critical_max": 100,
        },
        "gray_zone": {"min": 30, "max": 70},
        "keywords": {
            "urgency": [
                "urgent action required",
                "within 24 hours",
                "account suspended",
                "verify your account",
                "password reset",
                "unauthorized login",
            ]
        },
        "brands": {
            "popular": [
                {"name": "PayPal", "domains": ["paypal.com"]},
                {"name": "Microsoft", "domains": ["microsoft.com", "office.com"]},
                {"name": "Google", "domains": ["google.com", "gmail.com"]},
                {"name": "Apple", "domains": ["apple.com"]},
            ],
            "roles": ["ceo", "it support", "help desk", "admin"],
        },
        "url_shorteners": {"domains": ["bit.ly", "tinyurl.com", "t.co"]},
        "attachments": {
            "high_risk_extensions": [".exe", ".js", ".vbs", ".scr", ".iso", ".lnk", ".docm"]
        },
    }


def analyze_single_file(
    file_path: Path,
    config: dict[str, Any],
    no_llm: bool = False,
    offline: bool = False,
    cache: ThreatIntelCache | None = None,
) -> AnalysisResult:
    """Analyze a single .eml file."""
    parsed = parse_eml(file_path)
    return evaluate_email(parsed, config, no_llm=no_llm, offline=offline, cache=cache)


def run_batch_scan(
    folder_path: Path,
    config: dict[str, Any],
    no_llm: bool = False,
    offline: bool = False,
    cache: ThreatIntelCache | None = None,
) -> list[AnalysisResult]:
    """Scan all .eml files in a directory."""
    if not folder_path.exists():
        raise ParserError(f"Directory not found: {folder_path}", exit_code=2)
    if not folder_path.is_dir():
        raise ParserError(f"Target is not a directory: {folder_path}", exit_code=2)

    files = sorted([p for p in folder_path.rglob("*") if p.is_file() and p.suffix.lower() == ".eml"])
    if not files:
        raise ParserError(f"No .eml files found in directory: {folder_path}", exit_code=2)

    results: list[AnalysisResult] = []
    for file_p in files:
        res = analyze_single_file(file_p, config, no_llm=no_llm, offline=offline, cache=cache)
        results.append(res)
    return results


def run_benchmark(
    folder_path: Path,
    labels_path: Path,
    config: dict[str, Any],
    no_llm: bool = True,
    offline: bool = True,
) -> BenchmarkResult:
    """Compare verdicts against ground-truth labels.csv (Section 8.2)."""
    if not folder_path.exists() or not folder_path.is_dir():
        raise ParserError(f"Benchmark folder not found: {folder_path}", exit_code=2)
    if not labels_path.exists() or not labels_path.is_file():
        raise ParserError(f"Labels CSV file not found: {labels_path}", exit_code=2)

    labels: dict[str, str] = {}
    with labels_path.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().lower() in ("filename", "file"):
                continue
            fname = row[0].strip()
            lbl = row[1].strip().lower() if len(row) > 1 else ""
            labels[fname] = lbl

    if not labels:
        raise ParserError("Labels file is empty or missing data rows", exit_code=2)

    cache = ThreatIntelCache()
    results: list[dict[str, Any]] = []
    tp = fn = tn = fp = 0
    phish_count = legit_count = 0

    for fname, true_label in labels.items():
        # Look for file in folder
        file_candidates = list(folder_path.rglob(fname))
        if not file_candidates:
            continue
        file_p = file_candidates[0]

        res = analyze_single_file(file_p, config, no_llm=no_llm, offline=offline, cache=cache)
        is_phish_verdict = res.severity in ("Medium", "High", "Critical")
        is_high_or_crit = res.severity in ("High", "Critical")

        norm_label = "phishing" if true_label in ("phishing", "phish", "malicious", "spam") else "legit"
        if norm_label == "phishing":
            phish_count += 1
            if is_phish_verdict:
                tp += 1
            else:
                fn += 1
        else:
            legit_count += 1
            if is_high_or_crit:
                fp += 1
            else:
                tn += 1

        results.append({
            "filename": fname,
            "true_label": norm_label,
            "score": res.final_score,
            "severity": res.severity,
            "correct": (norm_label == "phishing" and is_phish_verdict) or (norm_label == "legit" and not is_high_or_crit),
        })

    total = phish_count + legit_count
    det_rate = (tp / phish_count) if phish_count > 0 else 0.0
    fp_rate = (fp / legit_count) if legit_count > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = det_rate
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return BenchmarkResult(
        total_samples=total,
        phishing_samples=phish_count,
        legit_samples=legit_count,
        true_positives=tp,
        false_negatives=fn,
        true_negatives=tn,
        false_positives=fp,
        detection_rate=det_rate,
        false_positive_rate=fp_rate,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        details=results,
    )


def should_fail_on(results: list[AnalysisResult], fail_on: str | None) -> bool:
    """Check if any analyzed result triggers the --fail-on threshold."""
    if not fail_on:
        return False
    threshold = SEVERITY_LEVELS.get(fail_on.lower())
    if not threshold:
        return False

    for res in results:
        res_level = SEVERITY_LEVELS.get(res.severity.lower(), 1)
        if res_level >= threshold:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    """FR-C1: CLI Argument Parser."""
    parser = argparse.ArgumentParser(
        prog="phishscan",
        description="PhishScan — Offline-first rule-based email phishing detection engine.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Common options helper
    def add_common_flags(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--no-llm", action="store_true", help="Skip LLM review")
        sub.add_argument("--offline", action="store_true", help="Skip all external network calls")
        sub.add_argument("--verbose", "-v", action="store_true", help="Show all checks, including zero findings")
        sub.add_argument(
            "--format",
            choices=["terminal", "json", "csv", "html"],
            default="terminal",
            help="Report output format (default: terminal)",
        )
        sub.add_argument("--out", type=str, default=None, help="Output destination file path")
        sub.add_argument("--config", type=str, default=None, help="Custom config.toml path")
        sub.add_argument(
            "--fail-on",
            choices=["low", "medium", "high", "critical"],
            default=None,
            help="Exit with code 1 when severity reaches or exceeds this level",
        )

    # 1. analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze one .eml file")
    analyze_parser.add_argument("target", type=str, help="Path to .eml file or directory")
    add_common_flags(analyze_parser)

    # 2. batch command
    batch_parser = subparsers.add_parser("batch", help="Analyze all .eml files in a directory")
    batch_parser.add_argument("folder", type=str, help="Path to folder containing .eml files")
    add_common_flags(batch_parser)

    # 3. benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark detection against labeled dataset")
    bench_parser.add_argument("folder", type=str, help="Path to benchmark samples directory")
    bench_parser.add_argument("--labels", type=str, required=True, help="Path to labels.csv")
    bench_parser.add_argument("--format", choices=["terminal", "json"], default="terminal", help="Report format")
    bench_parser.add_argument("--out", type=str, default=None, help="Output destination file path")
    bench_parser.add_argument("--config", type=str, default=None, help="Custom config.toml path")

    return parser


def format_output(results: list[AnalysisResult] | AnalysisResult, fmt: str, verbose: bool = False) -> str:
    """Format single or batch analysis results."""
    items = results if isinstance(results, list) else [results]
    if fmt == "json":
        return format_json_report(results if len(items) > 1 else items[0])
    elif fmt == "csv":
        return format_csv_report(items)
    elif fmt == "html":
        return format_html_report(items)
    else:
        return "\n\n".join(format_terminal_report(r, verbose=verbose) for r in items)


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint handling return codes."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        config = load_config(getattr(args, "config", None))

        if args.command in ("analyze", "batch"):
            target_path = Path(args.target if args.command == "analyze" else args.folder)
            if not target_path.exists():
                raise ParserError(f"Target path not found: {target_path}", exit_code=2)

            cache = ThreatIntelCache()

            if args.command == "analyze" and target_path.is_file():
                results = [analyze_single_file(
                    target_path, config, no_llm=args.no_llm, offline=args.offline, cache=cache
                )]
            else:
                results = run_batch_scan(
                    target_path, config, no_llm=args.no_llm, offline=args.offline, cache=cache
                )

            output_str = format_output(results if len(results) > 1 else results[0], args.format, verbose=args.verbose)
            write_report(output_str, args.out)

            if should_fail_on(results, args.fail_on):
                return 1
            return 0

        elif args.command == "benchmark":
            folder = Path(args.folder)
            labels = Path(args.labels)
            bench = run_benchmark(folder, labels, config)

            if args.format == "json":
                import json
                output_str = json.dumps(bench.to_dict(), indent=2)
            else:
                output_str = format_benchmark_report(bench)

            write_report(output_str, args.out)
            return 0

    except ParserError as pe:
        sys.stderr.write(f"Error: {pe}\n")
        return pe.exit_code
    except Exception as exc:
        sys.stderr.write(f"Runtime error: {exc}\n")
        return 2

    return 0


def app_entry() -> None:
    """Entry point for installed script."""
    sys.exit(main())


if __name__ == "__main__":
    app_entry()
