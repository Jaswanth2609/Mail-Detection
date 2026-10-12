"""Command-line interface for PhishScan (FR-C1, FR-C2, FR-C3, FR-C4, NFR-5)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

from phishscan.models import AnalysisResult
from phishscan.parser import ParserError, parse_eml
from phishscan.report import format_json_report, format_terminal_report, write_report
from phishscan.scoring import evaluate_email


def load_config(custom_path: str | Path | None = None) -> dict[str, Any]:
    """Loads configuration from custom path, current directory, or bundled default."""
    search_paths: list[Path] = []
    if custom_path:
        search_paths.append(Path(custom_path))
    search_paths.append(Path.cwd() / "config.toml")
    search_paths.append(Path(__file__).resolve().parent.parent.parent / "config.toml")

    for p in search_paths:
        if p.is_file():
            try:
                with p.open("rb") as f:
                    return tomllib.load(f)
            except Exception as e:
                sys.stderr.write(f"Warning: Failed to parse configuration from {p}: {e}\n")

    # Fallback default configuration in case file is absent
    return {
        "weights": {
            "auth_failure": 15,
            "auth_failure_max": 30,
            "domain_mismatch": 15,
            "display_name_spoofing": 20,
            "hidden_text": 15,
            "invisible_characters": 10,
            "urgency_credential_language": 10,
            "link_text_href_mismatch": 25,
            "suspicious_url_structure": 15,
            "lookalike_domain": 25,
            "high_risk_attachment": 25,
            "attachment_type_or_double_extension": 25,
        },
        "severity_bands": {
            "low_max": 24,
            "medium_max": 49,
            "high_max": 74,
            "critical_max": 100,
        },
        "keywords": {
            "urgency": [
                "urgent action required",
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


def analyze_target(target_path: Path, config: dict[str, Any]) -> list[AnalysisResult]:
    """Analyzes a single .eml file or all .eml files in a directory."""
    if not target_path.exists():
        raise ParserError(f"Target path does not exist: {target_path}", exit_code=2)

    files_to_scan: list[Path] = []
    if target_path.is_file():
        files_to_scan.append(target_path)
    elif target_path.is_dir():
        # FR-C4: Directory batch mode
        files_to_scan = sorted(
            [p for p in target_path.rglob("*") if p.is_file() and p.suffix.lower() == ".eml"]
        )
        if not files_to_scan:
            raise ParserError(f"No .eml files found in directory: {target_path}", exit_code=2)
    else:
        raise ParserError(f"Target is neither a file nor a directory: {target_path}", exit_code=2)

    results: list[AnalysisResult] = []
    for file_p in files_to_scan:
        parsed = parse_eml(file_p)
        res = evaluate_email(parsed, config)
        results.append(res)

    return results


def build_parser() -> argparse.ArgumentParser:
    """Creates the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="phishscan",
        description="Deterministic, rule-based email phishing detection and analysis CLI.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze command (FR-C1)
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an .eml email file or a directory containing .eml files",
    )
    analyze_parser.add_argument(
        "target",
        type=str,
        help="Path to an .eml file or a directory of .eml files",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output report format (default: terminal)",
    )
    analyze_parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Write report output to designated file path",
    )
    analyze_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom config.toml file",
    )
    analyze_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Include detailed metadata and check explanations in terminal report",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "analyze":
        try:
            config = load_config(args.config)
            target = Path(args.target)
            results = analyze_target(target, config)

            if args.format == "json":
                output_str = format_json_report(results if len(results) > 1 else results[0])
            else:
                reports = [
                    format_terminal_report(
                        res,
                        verbose=args.verbose,
                        use_color=(args.out is None and sys.stdout.isatty()),
                    )
                    for res in results
                ]
                output_str = "\n\n".join(reports)

            write_report(output_str, args.out)
            return 0

        except ParserError as pe:
            sys.stderr.write(f"Error: {pe}\n")
            return pe.exit_code
        except Exception as e:
            sys.stderr.write(f"Runtime error: {e}\n")
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
