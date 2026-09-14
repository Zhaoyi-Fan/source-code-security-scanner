"""v2.2 public API, suppression-audit, and bounded-scan contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import vulnscan


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_scan_api_is_quiet_and_returns_structured_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _write(tmp_path / "app.py", "os.system(user_command)\n")

    result = vulnscan.scan(
        vulnscan.ScanConfig(
            target=str(source),
            categories=("command_injection",),
        )
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert [item.rule_id for item in result.findings] == ["CMD.OS_SYSTEM"]
    assert result.suppressions == []
    assert result.stats.files_considered == 1
    assert result.stats.files_scanned == 1
    assert result.stats.bytes_scanned == source.stat().st_size
    assert result.stats.complete is True
    assert result.stats.truncated is False


def test_json_exposes_versioned_redacted_suppression_audit(
    tmp_path: Path, run_scanner
) -> None:
    sentinel = "SYNTH-SUPPRESSION-A1b2C3d4"
    source = _write(
        tmp_path / "fixture.py",
        f'password = "{sentinel}"  '
        "# nosec: CREDENTIALS.PASSWORD -- synthetic test fixture\n",
    )

    result = run_scanner(source, "--credentials", "--format", "json")
    report = json.loads(result.stdout)

    assert result.returncode == 0
    assert report["schema_version"] == "2.2"
    assert report["findings"] == []
    assert report["summary"]["suppressed"] == 1
    assert report["summary"]["complete"] is True
    assert len(report["suppressions"]) == 1
    suppression = report["suppressions"][0]
    assert suppression["rule_id"] == "CREDENTIALS.PASSWORD"
    assert suppression["justification"] == "synthetic test fixture"
    assert suppression["context"] == "[REDACTED]"
    assert sentinel not in result.stdout
    assert sentinel not in result.stderr


def test_sarif_marks_in_source_suppression_as_accepted(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "fixture.py",
        'password = "SYNTH-SARIF-A1b2C3d4"  '
        "# nosec: CREDENTIALS.PASSWORD -- synthetic fixture\n",
    )

    result = run_scanner(source, "--credentials", "--format", "sarif")
    sarif = json.loads(result.stdout)
    sarif_result = sarif["runs"][0]["results"][0]

    assert result.returncode == 0
    assert sarif_result["ruleId"] == "CREDENTIALS.PASSWORD"
    assert sarif_result["suppressions"] == [
        {
            "kind": "inSource",
            "status": "accepted",
            "justification": "synthetic fixture",
        }
    ]
    assert sarif["runs"][0]["properties"]["suppressedFindings"] == 1


def test_suppression_justification_cannot_reintroduce_a_provider_secret(
    tmp_path: Path, run_scanner
) -> None:
    provider_token = "ghp_" + "SYNTHETIC" + ("0" * 27)
    source = _write(
        tmp_path / "unsafe_reason.py",
        "os.system(user_command)  # nosec: CMD.OS_SYSTEM -- "
        + provider_token
        + "\n",
    )

    result = run_scanner(source, "--cmd", "--format", "json")
    report = json.loads(result.stdout)

    assert result.returncode == 0
    assert report["suppressions"][0]["justification"] == "[REDACTED]"
    assert provider_token not in result.stdout
    assert provider_token not in result.stderr


def test_unknown_and_stale_suppression_ids_are_visible_warnings(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "stale.py",
        "print('safe')  # nosec: CMD.OS_SYSTEM, TYPO.UNKNOWN -- reviewed\n",
    )

    result = run_scanner(source, "--cmd", "--format", "json")
    report = json.loads(result.stdout)
    messages = [item["message"] for item in report["diagnostics"]]

    assert result.returncode == 0
    assert report["findings"] == []
    assert report["suppressions"] == []
    assert any("unknown rule ID" in message and "TYPO.UNKNOWN" in message for message in messages)
    assert any("did not match" in message and "CMD.OS_SYSTEM" in message for message in messages)


def test_required_suppression_reason_fails_closed(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "missing_reason.py",
        "os.system(user_command)  # nosec: CMD.OS_SYSTEM\n",
    )

    result = run_scanner(
        source,
        "--cmd",
        "--require-suppression-reason",
        "--format",
        "json",
    )
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert [item["rule_id"] for item in report["findings"]] == ["CMD.OS_SYSTEM"]
    assert report["suppressions"] == []
    assert report["summary"]["complete"] is False
    assert "requires a justification" in result.stderr


def test_fail_on_suppressed_is_an_explicit_policy_gate(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "accepted.py",
        "os.system(user_command)  "
        "# nosec: CMD.OS_SYSTEM -- controlled synthetic command\n",
    )

    result = run_scanner(
        source,
        "--cmd",
        "--fail-on-suppressed",
        "--format",
        "json",
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["summary"]["suppressed"] == 1


def test_max_files_stops_deterministically_and_marks_report_incomplete(
    tmp_path: Path, run_scanner
) -> None:
    source_root = tmp_path / "src"
    _write(source_root / "a.py", "os.system(first_command)\n")
    _write(source_root / "b.py", "os.system(second_command)\n")

    result = run_scanner(
        source_root,
        "--recursive",
        "--cmd",
        "--max-files",
        "1",
        "--format",
        "json",
    )
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert len(report["findings"]) == 1
    assert report["summary"]["files_considered"] == 1
    assert report["summary"]["files_scanned"] == 1
    assert report["summary"]["complete"] is False
    assert report["summary"]["truncated"] is True
    assert "--max-files" in result.stderr


def test_max_total_bytes_stops_before_reading_oversized_total(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(tmp_path / "app.py", "os.system(user_command)\n")

    result = run_scanner(
        source,
        "--cmd",
        "--max-total-bytes",
        "8",
        "--format",
        "json",
    )
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert report["findings"] == []
    assert report["summary"]["bytes_scanned"] == 0
    assert report["summary"]["truncated"] is True
    assert "--max-total-bytes" in result.stderr


def test_max_findings_caps_output_and_marks_report_incomplete(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "two.py",
        "os.system(first_command)\nos.system(second_command)\n",
    )

    result = run_scanner(
        source,
        "--cmd",
        "--max-findings",
        "1",
        "--format",
        "json",
    )
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert len(report["findings"]) == 1
    assert report["summary"]["truncated"] is True
    assert "--max-findings" in result.stderr


def test_max_findings_also_caps_suppression_audit_output(
    tmp_path: Path, run_scanner
) -> None:
    source = _write(
        tmp_path / "suppressed.py",
        "os.system(first_command)  # nosec: CMD.OS_SYSTEM -- first fixture\n"
        "os.system(second_command)  # nosec: CMD.OS_SYSTEM -- second fixture\n",
    )

    result = run_scanner(
        source,
        "--cmd",
        "--max-findings",
        "1",
        "--format",
        "json",
    )
    report = json.loads(result.stdout)

    assert result.returncode == 2
    assert report["findings"] == []
    assert len(report["suppressions"]) == 1
    assert report["summary"]["suppressed"] == 1
    assert report["summary"]["truncated"] is True


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("--max-files", "--max-files must be non-negative"),
        ("--max-total-bytes", "--max-total-bytes must be non-negative"),
        ("--max-findings", "--max-findings must be non-negative"),
    ],
)
def test_new_limits_reject_negative_values(
    tmp_path: Path, run_scanner, option: str, message: str
) -> None:
    source = _write(tmp_path / "app.py", "print('safe')\n")

    result = run_scanner(source, option, "-1")

    assert result.returncode == 2
    assert message in result.stderr
