"""Boundary coverage for public CLI options not frozen by the v2.1 suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import vulnscan

from conftest import findings, json_report, rule_id


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_version_is_a_target_free_machine_friendly_command(run_scanner) -> None:
    result = run_scanner("--version")

    assert result.returncode == 0
    assert vulnscan.TOOL_NAME in result.stdout
    assert vulnscan.TOOL_VERSION in result.stdout
    assert result.stderr == ""


def test_min_entropy_explicitly_filters_a_low_entropy_secret(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(tmp_path / "weak.py", 'password = "aaaaaa"\n')

    baseline = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )
    filtered = json_report(
        run_scanner(
            source,
            "--credentials",
            "--min-entropy",
            "0.1",
            "--format",
            "json",
        )
    )

    assert {rule_id(hit) for hit in findings(baseline)} == {
        "CREDENTIALS.PASSWORD"
    }
    assert findings(filtered) == []
    assert filtered["summary"]["filtered"] == 1


def test_min_confidence_filters_low_confidence_findings(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(tmp_path / "command.py", "os.system(user_command)\n")

    baseline = json_report(run_scanner(source, "--cmd", "--format", "json"))
    filtered = json_report(
        run_scanner(
            source,
            "--cmd",
            "--min-confidence",
            "medium",
            "--format",
            "json",
        )
    )

    assert {rule_id(hit) for hit in findings(baseline)} == {"CMD.OS_SYSTEM"}
    assert findings(filtered) == []
    assert filtered["summary"]["filtered"] == 1


def test_max_file_size_is_fail_closed_and_best_effort_is_explicit(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "large.py",
        "os.system(user_command)\n" + ("# synthetic padding\n" * 8),
    )

    strict = run_scanner(source, "--max-file-size", "8", "--format", "json")
    best_effort = run_scanner(
        source,
        "--max-file-size",
        "8",
        "--best-effort",
        "--format",
        "json",
    )

    strict_report = json.loads(strict.stdout)
    best_effort_report = json_report(best_effort)
    assert strict.returncode == 2
    assert strict_report["summary"]["scan_errors"] == 1
    assert strict_report["summary"]["files_scanned"] == 0
    assert "exceeds max size" in strict.stderr.lower()
    assert best_effort.returncode == 0
    assert best_effort_report["summary"]["scan_errors"] == 1
    assert findings(best_effort_report) == []


def test_zero_max_file_size_disables_the_per_file_limit(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "unlimited.py",
        "os.system(user_command)\n" + ("# synthetic padding\n" * 8),
    )

    report = json_report(
        run_scanner(source, "--max-file-size", "0", "--format", "json")
    )

    assert {rule_id(hit) for hit in findings(report)} == {"CMD.OS_SYSTEM"}
    assert report["summary"]["scan_errors"] == 0
    assert report["summary"]["files_scanned"] == 1


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--min-entropy", "-0.1", "--min-entropy must be non-negative"),
        ("--max-file-size", "-1", "--max-file-size must be non-negative"),
    ],
)
def test_non_negative_numeric_options_reject_negative_values(
    tmp_path: Path, run_scanner, option: str, value: str, message: str
) -> None:
    source = _write(tmp_path / "app.py", "print('synthetic')\n")

    result = run_scanner(source, option, value)

    assert result.returncode == 2
    assert message in result.stderr
    assert "Traceback" not in result.stderr


def test_base_dir_controls_the_reported_repository_relative_path(
    tmp_path: Path, run_scanner
) -> None:
    base = tmp_path / "repository"
    source = _write(base / "src" / "app.py", "os.system(user_command)\n")

    report = json_report(
        run_scanner(source, "--base-dir", base, "--format", "json", cwd=tmp_path)
    )

    assert {hit["file"] for hit in findings(report)} == {"src/app.py"}


def test_base_dir_rejects_a_target_outside_its_boundary(
    tmp_path: Path, run_scanner
) -> None:
    base = tmp_path / "repository"
    base.mkdir()
    source = _write(tmp_path / "outside" / "app.py", "os.system(user_command)\n")

    result = run_scanner(source, "--base-dir", base, "--format", "json")
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert findings(report) == []
    assert report["summary"]["scan_errors"] == 1
    assert "outside --base-dir" in result.stderr


def test_file_forces_an_explicit_unsupported_extension(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(tmp_path / "synthetic.source", 'digest_name = "MD5"\n')

    skipped = json_report(run_scanner(source, "--format", "json"))
    forced = json_report(run_scanner(source, "--file", "--format", "json"))

    assert findings(skipped) == []
    assert skipped["summary"]["files_scanned"] == 0
    assert {rule_id(hit) for hit in findings(forced)} == {"CRYPTO.MD5"}
    assert forced["summary"]["files_scanned"] == 1


def test_file_rejects_a_directory_target(tmp_path: Path, run_scanner) -> None:
    result = run_scanner(tmp_path, "--file", "--format", "json")

    assert result.returncode == 2
    assert "--file requires a regular file target" in result.stderr
    assert result.stdout == ""


def test_show_categories_lists_every_stable_rule_once(run_scanner) -> None:
    result = run_scanner("--show-categories")

    assert result.returncode == 0
    assert result.stderr == ""
    for rule in vulnscan.RULES:
        assert result.stdout.count(f"- {rule.id}:") == 1


@pytest.mark.parametrize(
    ("source_text", "threshold", "expected_exit"),
    [
        ("os.system(user_command)\n", "high", 1),
        ('digest = "MD5"\n', "high", 0),
        ('digest = "MD5"\n', "medium", 1),
        ("connection = mysqli_connect(host, user, password)\n", "medium", 0),
        ("connection = mysqli_connect(host, user, password)\n", "low", 1),
        ("DEBUG = True\n", "low", 0),
        ("DEBUG = True\n", "info", 1),
    ],
)
def test_fail_on_uses_an_inclusive_severity_threshold(
    tmp_path: Path,
    run_scanner,
    source_text: str,
    threshold: str,
    expected_exit: int,
) -> None:
    source = _write(tmp_path / "boundary.py", source_text)

    result = run_scanner(
        source, "--fail-on", threshold, "--format", "json"
    )

    assert result.returncode == expected_exit
    assert findings(json.loads(result.stdout))
