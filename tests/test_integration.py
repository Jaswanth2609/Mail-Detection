"""Integration tests on realistic phishing and legitimate emails (Section 7)."""

from pathlib import Path
import time
import pytest

from phishscan.cli import load_config
from phishscan.parser import parse_eml
from phishscan.scoring import evaluate_email


def test_integration_phishing_pipeline():
    """End-to-end analysis on realistic phishing sample email."""
    config = load_config()
    phish_path = Path("samples/phishing/account_suspended_urgent.eml")
    assert phish_path.exists()

    parsed = parse_eml(phish_path)
    result = evaluate_email(parsed, config)

    # Validate findings across all 4 modules
    categories = {f.category for f in result.findings}
    assert "Header" in categories
    assert "Body" in categories
    assert "Link" in categories
    assert "Attachment" in categories

    assert result.score >= 75
    assert result.severity == "Critical"
    assert len(result.findings) >= 5


def test_integration_legitimate_pipeline():
    """End-to-end analysis on legitimate sample email."""
    config = load_config()
    legit_path = Path("samples/legitimate/welcome_newsletter.eml")
    assert legit_path.exists()

    parsed = parse_eml(legit_path)
    result = evaluate_email(parsed, config)

    assert result.score <= 24
    assert result.severity == "Low"
    assert len(result.findings) == 0


def test_integration_performance_nfr1():
    """NFR-1: Analyse email in under 2 seconds."""
    config = load_config()
    target_path = Path("samples/phishing/account_suspended_urgent.eml")

    start_time = time.perf_counter()
    parsed = parse_eml(target_path)
    result = evaluate_email(parsed, config)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 2.0, f"Analysis took {elapsed:.3f}s, exceeding 2.0s requirement"
    assert result is not None
