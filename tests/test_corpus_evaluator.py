"""CLI contract for the dependency-free corpus quality gate."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import vulnscan


REPO_ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = REPO_ROOT / "scripts" / "evaluate_corpus.py"
MANIFEST = Path(__file__).parent / "corpus" / "manifest.jsonl"


def _run_evaluator(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(EVALUATOR), *(str(arg) for arg in args)],
        cwd=REPO_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def test_evaluator_reports_clean_overall_and_per_rule_metrics() -> None:
    result = _run_evaluator("--format", "json")
    report = json.loads(result.stdout)

    assert result.returncode == 0
    assert result.stderr == ""
    assert report["passed"] is True
    assert report["overall"]["cases"] > len(vulnscan.RULES)
    assert report["overall"]["exact_cases"] == report["overall"]["cases"]
    assert report["overall"]["rules"] == len(vulnscan.RULES)
    assert report["overall"]["tp"] == len(vulnscan.RULES)
    assert report["overall"]["fp"] == 0
    assert report["overall"]["fn"] == 0
    assert report["overall"]["duplicates"] == 0
    assert report["overall"]["precision"] == 1.0
    assert report["overall"]["recall"] == 1.0
    assert {item["rule_id"] for item in report["per_rule"]} == set(
        vulnscan.RULE_BY_ID
    )


def test_evaluator_returns_nonzero_for_a_corpus_regression(
    tmp_path: Path,
) -> None:
    cases = [
        json.loads(line)
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    password_case = next(
        case for case in cases if case["case_id"] == "credentials-password-positive"
    )
    password_case["source"] = "password = load_from_environment()\n"
    regressed = tmp_path / "regressed.jsonl"
    regressed.write_text(
        "\n".join(json.dumps(case, separators=(",", ":")) for case in cases) + "\n",
        encoding="utf-8",
    )

    result = _run_evaluator("--manifest", regressed, "--format", "json")
    report = json.loads(result.stdout)

    assert result.returncode == 1
    assert report["passed"] is False
    assert report["overall"]["fn"] >= 1
    assert "credentials-password-positive" in {
        failure["case_id"] for failure in report["failures"]
    }
