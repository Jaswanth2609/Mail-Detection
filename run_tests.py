#!/usr/bin/env python3
"""Test runner for PhishScan test suite (works with or without pytest)."""
from __future__ import annotations

import importlib
import inspect
import os
from pathlib import Path
import sys
import tempfile
import time
import traceback

# Ensure src and tests are in sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "src"))
sys.path.insert(0, str(BASE_DIR / "tests"))

import conftest
from conftest import Capsys, MonkeyPatch, config, fixtures_dir


def run_all_tests() -> int:
    test_files = sorted((BASE_DIR / "tests").glob("test_*.py"))
    total_run = 0
    failures = 0
    start_time = time.time()

    print(f"Running PhishScan test suite on Python {sys.version.split()[0]}...")
    print("=" * 70)

    for file_path in test_files:
        module_name = file_path.stem
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:
            print(f"FAILED TO IMPORT {file_path.name}: {exc}")
            failures += 1
            continue

        test_funcs = [
            (name, fn)
            for name, fn in inspect.getmembers(mod, inspect.isfunction)
            if name.startswith("test_")
        ]

        for name, fn in test_funcs:
            total_run += 1
            sig = inspect.signature(fn)
            kwargs = {}
            temp_dirs = []
            monkey_patcher = None
            capsys_obj = None

            for param in sig.parameters.values():
                if param.name == "config":
                    kwargs["config"] = config()
                elif param.name == "fixtures_dir":
                    kwargs["fixtures_dir"] = fixtures_dir()
                elif param.name == "tmp_path":
                    td = tempfile.TemporaryDirectory()
                    temp_dirs.append(td)
                    kwargs["tmp_path"] = Path(td.name)
                elif param.name == "monkeypatch":
                    monkey_patcher = MonkeyPatch()
                    kwargs["monkeypatch"] = monkey_patcher
                elif param.name == "capsys":
                    capsys_obj = Capsys()
                    kwargs["capsys"] = capsys_obj

            old_stdout = sys.stdout
            old_stderr = sys.stderr
            if capsys_obj:
                sys.stdout = capsys_obj._stdout
                sys.stderr = capsys_obj._stderr

            try:
                fn(**kwargs)
                print(f"  PASS: {module_name}::{name}")
            except Exception as exc:
                failures += 1
                if capsys_obj:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                print(f"\n  FAIL: {module_name}::{name}")
                traceback.print_exc(file=sys.stdout)
                print()
            finally:
                if capsys_obj:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                if monkey_patcher:
                    monkey_patcher.undo()
                for td in temp_dirs:
                    td.cleanup()

    duration = time.time() - start_time
    print("=" * 70)
    print(f"Results: {total_run - failures} passed, {failures} failed in {duration:.2f}s")

    return 1 if failures > 0 else 0


if __name__ == "__main__":
    sys.exit(run_all_tests())
