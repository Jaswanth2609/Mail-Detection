"""Pytest configuration, fallback shim, and shared fixtures."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import types
from typing import Any

from phishscan.cli import load_config

# If real pytest is not installed, install a lightweight compatibility shim into sys.modules
if "pytest" not in sys.modules:
    try:
        import pytest
    except ImportError:
        class RaisesContext:
            def __init__(self, expected_exc: type[Exception]):
                self.expected_exc = expected_exc
                self.value: Any = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    raise AssertionError(f"Expected exception {self.expected_exc.__name__} was not raised.")
                if not issubclass(exc_type, self.expected_exc):
                    return False
                self.value = exc_val
                return True

        shim = types.ModuleType("pytest")
        shim.raises = RaisesContext
        shim.fixture = lambda f: f
        shim.mark = types.SimpleNamespace()
        sys.modules["pytest"] = shim
        import pytest  # type: ignore

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def config():
    """Provides default test configuration."""
    return load_config()


def fixtures_dir():
    """Provides path to fixtures directory."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    return FIXTURES_DIR


class Capsys:
    """Mock for pytest capsys fixture."""
    def __init__(self):
        self._stdout = io.StringIO()
        self._stderr = io.StringIO()

    def readouterr(self):
        out = self._stdout.getvalue()
        err = self._stderr.getvalue()
        self._stdout = io.StringIO()
        self._stderr = io.StringIO()
        return types.SimpleNamespace(out=out, err=err)


class MonkeyPatch:
    """Mock for pytest monkeypatch fixture."""
    def __init__(self):
        self._undo = []

    def setenv(self, key: str, val: str):
        old = os.environ.get(key)
        os.environ[key] = val
        self._undo.append((os.environ, key, old))

    def delenv(self, key: str, raising: bool = False):
        old = os.environ.get(key)
        if key in os.environ:
            del os.environ[key]
        self._undo.append((os.environ, key, old))

    def setattr(self, target: Any, name: str | Any = None, value: Any = None):
        if value is None and isinstance(target, str):
            mod_name, attr_name = target.rsplit(".", 1)
            import importlib
            mod = importlib.import_module(mod_name)
            value = name
            target = mod
            name = attr_name
        old = getattr(target, name, None)
        setattr(target, name, value)
        self._undo.append((target, name, old))

    def undo(self):
        for target, name, old in reversed(self._undo):
            if isinstance(target, dict) or target is os.environ:
                if old is None:
                    target.pop(name, None)
                else:
                    target[name] = old
            else:
                setattr(target, name, old)
