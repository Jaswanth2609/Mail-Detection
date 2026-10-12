"""Tests for CLI interface and exit codes (FR-C1 to FR-C4, FR-P5)."""

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
    """FR-C1: Analyze sample produces terminal output with code 0."""
    code = main(["analyze", "samples/legitimate/welcome_newsletter.eml"])
    assert code == 0
    captured = capsys.readouterr()
    assert "PHISHSCAN EMAIL THREAT REPORT" in captured.out
    assert "Score:     0/100" in captured.out


def test_cli_analyze_json(capsys):
    """FR-C2: Analyze with --format json outputs valid JSON."""
    code = main(["analyze", "samples/phishing/account_suspended_urgent.eml", "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["score"] == 100
    assert data["severity"] == "Critical"
    assert len(data["findings"]) > 0


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
    data = json.loads(out_file.read_text())
    assert data["score"] == 100


def test_cli_analyze_directory_batch(capsys):
    """FR-C4: Batch analyze directory of .eml files."""
    code = main(["analyze", "samples/legitimate", "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 2


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
