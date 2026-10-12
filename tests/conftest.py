"""Pytest configuration and shared test fixtures."""

from pathlib import Path
import pytest

from phishscan.cli import load_config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def config():
    """Provides default test configuration."""
    return load_config()


@pytest.fixture
def fixtures_dir():
    """Provides path to fixtures directory."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    return FIXTURES_DIR
