"""Tests for benchmark module and acceptance criteria AC-2, AC-3 (Section 8.2)."""
from __future__ import annotations

from pathlib import Path
import pytest

from phishscan.cli import load_config, run_benchmark


def test_benchmark_acceptance_criteria_ac2_ac3():
    """Section 8.2 & AC-2, AC-3: Benchmark on >= 50 labeled samples meets targets."""
    samples_dir = Path("samples")
    labels_file = samples_dir / "labels.csv"

    assert samples_dir.exists() and samples_dir.is_dir()
    assert labels_file.exists() and labels_file.is_file()

    config = load_config()
    bench = run_benchmark(samples_dir, labels_file, config, no_llm=True, offline=True)

    # Section 8.2: At least 50 emails
    assert bench.total_samples >= 50
    assert bench.phishing_samples >= 20
    assert bench.legit_samples >= 20

    # AC-2: Detection rate (phishing rated Medium or higher) >= 85%
    assert bench.detection_rate >= 0.85, f"Detection rate {bench.detection_rate:.2%} below 85%"

    # AC-3: False-positive rate (legitimate rated High or higher) <= 10%
    assert bench.false_positive_rate <= 0.10, f"False-positive rate {bench.false_positive_rate:.2%} above 10%"

    # Validate confusion matrix consistency
    assert bench.true_positives + bench.false_negatives == bench.phishing_samples
    assert bench.true_negatives + bench.false_positives == bench.legit_samples
