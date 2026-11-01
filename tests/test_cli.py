"""Tests for CLI interface and exit codes (FR-C1, FR-C2, FR-C3, FR-P5)."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from phishscan.cli import main


def test_cli_help(capsys):
    """Verify help message is displayed with return code 0."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "phishscan" in captured.out
    assert "analyze" in captured.out


def test_cli_no_args_shows_help(capsys):
    """Verify invoking with empty args displays help and returns 0."""
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "phishscan" in captured.out
    assert "analyze" in captured.out


def test_cli_analyze_terminal(capsys):
    """FR-C1: Analyze sample produces terminal output matching Appendix A with code 0."""
    code = main(["analyze", "samples/legitimate/welcome_newsletter.eml"])
    assert code == 0
    captured = capsys.readouterr()
    assert "welcome_newsletter.eml" in captured.out
    assert "LOW" in captured.out
    assert "0/100" in captured.out


def test_cli_analyze_json(capsys):
    """FR-C2: Analyze with --format json outputs valid JSON conforming to Section 7.5."""
    code = main(["analyze", "samples/phishing/account_suspended_urgent.eml", "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["final_score"] == 100
    assert data["severity"] == "Critical"
    assert len(data["findings"]) > 0
    assert "iocs" in data
    assert "skipped" in data


def test_cli_analyze_out_file(tmp_path):
    """FR-C2 & FR-R3: Support writing report to file with --out."""
    out_file = tmp_path / "report.json"
    code = main([
        "analyze",
        "samples/phishing/account_suspended_urgent.eml",
        "--format", "json",
        "--out", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["final_score"] == 100


def test_cli_analyze_csv_format(capsys):
    """FR-R2: Support CSV format."""
    code = main(["analyze", "samples/phishing/account_suspended_urgent.eml", "--format", "csv"])
    assert code == 0
    captured = capsys.readouterr()
    assert "final_score,severity" in captured.out
    assert "account_suspended_urgent.eml,100,Critical" in captured.out


def test_cli_analyze_html_format(tmp_path):
    """FR-R2: Support self-contained HTML format."""
    out_html = tmp_path / "report.html"
    code = main([
        "analyze",
        "samples/phishing/account_suspended_urgent.eml",
        "--format", "html",
        "--out", str(out_html),
    ])
    assert code == 0
    assert out_html.exists()
    content = out_html.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "PhishScan Email Security Report" in content
    assert "account_suspended_urgent.eml" in content


def test_cli_fail_on_trigger_exit_code_1(capsys):
    """FR-C3: Exit code 1 when --fail-on threshold is met or exceeded."""
    code = main([
        "analyze",
        "samples/phishing/account_suspended_urgent.eml",
        "--fail-on", "high",
    ])
    assert code == 1


def test_cli_fail_on_not_triggered(capsys):
    """FR-C3: Exit code 0 when --fail-on threshold is not met."""
    code = main([
        "analyze",
        "samples/legitimate/welcome_newsletter.eml",
        "--fail-on", "high",
    ])
    assert code == 0


def test_cli_batch_command(capsys):
    """FR-C1: Batch command analyzes all emails in directory."""
    code = main(["batch", "samples/legitimate", "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 2


def test_cli_benchmark_command(capsys):
    """FR-C1: Benchmark command evaluates samples with ground-truth labels."""
    code = main([
        "benchmark",
        "samples",
        "--labels", "samples/labels.csv",
        "--format", "json",
    ])
    assert code == 0
    captured = capsys.readouterr()
    bench = json.loads(captured.out)
    assert bench["total_samples"] >= 50
    assert bench["detection_rate"] >= 0.85
    assert bench["false_positive_rate"] <= 0.10


def test_cli_missing_file_exit_code_2(capsys):
    """FR-C3 & FR-P5: Missing file returns exit code 2."""
    code = main(["analyze", "non_existent_file.eml"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_empty_file_exit_code_2(tmp_path, capsys):
    """FR-C3 & FR-P5: Empty file returns exit code 2."""
    empty_eml = tmp_path / "empty.eml"
    empty_eml.write_text("")
    code = main(["analyze", str(empty_eml)])
    assert code == 2
    captured = capsys.readouterr()
    assert "Error:" in captured.err
