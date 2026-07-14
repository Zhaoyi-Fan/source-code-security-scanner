"""Shared black-box helpers for the v2.1 regression suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "vulnscan.py"


@pytest.fixture
def run_scanner() -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run the public CLI exactly as a user or CI job would run it."""

    def _run(
        *args: object,
        cwd: Path | None = None,
        timeout: float = 15.0,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["NO_COLOR"] = "1"
        return subprocess.run(
            [sys.executable, str(SCANNER), *(str(arg) for arg in args)],
            cwd=str(cwd or REPO_ROOT),
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    return _run


def json_report(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse a JSON report while keeping assertion output free of fixture secrets."""
    if result.returncode not in (0, 1):
        pytest.fail(
            f"scanner returned {result.returncode}; stderr was {result.stderr!r}",
            pytrace=False,
        )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"stdout is not a standalone JSON document: {exc}; "
            f"stderr was {result.stderr!r}",
            pytrace=False,
        )
    assert isinstance(report, dict)
    return report


def findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    value = report.get("findings")
    assert isinstance(value, list), "JSON report must contain a findings list"
    return value


def rule_id(finding: dict[str, Any]) -> str:
    """Return the stable per-rule identifier exposed by v2.1."""
    value = finding.get("rule_id")
    if value is None:
        value = finding.get("ruleId")
    assert isinstance(value, str) and value.strip(), (
        "each v2.1 finding must expose a non-empty stable rule ID"
    )
    return value


def assert_sentinel_absent(sentinel: str, *outputs: str) -> None:
    """Fail without echoing the synthetic sentinel into pytest diagnostics."""
    if any(sentinel in output for output in outputs):
        pytest.fail("a synthetic secret sentinel leaked into scanner output", pytrace=False)
