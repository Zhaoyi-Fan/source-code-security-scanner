"""Security and output-contract regressions fixed by the v2.1 milestone.

All credential-like values below are synthetic sentinels made solely for tests.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import vulnscan

from conftest import assert_sentinel_absent, findings, json_report, rule_id


def _write(path: Path, content: str, *, encoding: str = "utf-8") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)
    return path


def _credential_findings(report: dict[str, object]) -> list[dict[str, object]]:
    return [f for f in findings(report) if f.get("category") == "credentials"]


def _assert_operational_error_contract(
    result: subprocess.CompletedProcess[str],
) -> dict[str, object]:
    assert result.returncode == 2
    assert result.stderr.strip()
    report = json.loads(result.stdout)
    assert report["summary"]["scan_errors"] >= 1
    diagnostics = report.get("diagnostics")
    assert isinstance(diagnostics, list) and diagnostics
    assert all(
        isinstance(item, dict)
        and {"level", "message", "file"} <= item.keys()
        and item["level"] == "error"
        and isinstance(item["message"], str)
        and item["message"].strip()
        for item in diagnostics
    )
    return report


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_default_output_redacts_jwt_and_every_colocated_secret(
    tmp_path: Path,
    run_scanner,
    output_format: str,
) -> None:
    password = "SYNTH-PASS-A1b2C3d4E5f6"
    api_key = "SYNTH-API-z9Y8x7W6v5U4"
    jwt = "eyJSYNTHETICheader123.SYNTHETICpayload456.SYNTHsig789"
    source = _write(
        tmp_path / "app.py",
        (
            f'password = "{password}"; api_key = "{api_key}"; '
            f'token = "{jwt}"; os.system(user_input)\n'
        ),
    )

    result = run_scanner(source, "--format", output_format)

    assert result.returncode == 0
    for sentinel in (password, api_key, jwt):
        assert_sentinel_absent(sentinel, result.stdout, result.stderr)
    assert "finding" in result.stdout.lower() or output_format == "sarif"
    assert "No findings" not in result.stdout
    if output_format == "json":
        ids = {rule_id(hit) for hit in findings(json.loads(result.stdout))}
        assert {
            "CREDENTIALS.PASSWORD",
            "CREDENTIALS.API_KEY",
            "CREDENTIALS.JWT",
        } <= ids
    elif output_format == "sarif":
        sarif = json.loads(result.stdout)
        ids = {item["ruleId"] for item in sarif["runs"][0]["results"]}
        assert {
            "CREDENTIALS.PASSWORD",
            "CREDENTIALS.API_KEY",
            "CREDENTIALS.JWT",
        } <= ids


def test_same_line_credentials_are_not_deduplicated_and_high_gate_fails(
    tmp_path: Path,
    run_scanner,
) -> None:
    low_entropy_password = "123456"
    api_key = "SYNTH-HIGH-API-A1b2C3d4E5f6G7h8"
    source = _write(
        tmp_path / "settings.py",
        f'password = "{low_entropy_password}"; api_key = "{api_key}"\n',
    )

    result = run_scanner(
        source,
        "--credentials",
        "--format",
        "json",
        "--fail-on",
        "high",
    )
    report = json_report(result)
    hits = _credential_findings(report)

    assert result.returncode == 1
    assert len(hits) == 2
    assert {rule_id(hit) for hit in hits} == {
        "CREDENTIALS.PASSWORD",
        "CREDENTIALS.API_KEY",
    }
    assert {hit["severity"] for hit in hits} == {"HIGH"}
    assert_sentinel_absent(low_entropy_password, result.stdout)
    assert_sentinel_absent(api_key, result.stdout)


def test_low_entropy_password_keeps_high_impact_with_low_confidence(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "weak.py", 'password = "123456"\n')

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )
    hit = _credential_findings(report)[0]

    assert hit["severity"] == "HIGH"
    assert hit["confidence"] == "low"


def test_unscoped_or_non_directive_nosec_text_does_not_suppress(
    tmp_path: Path,
    run_scanner,
) -> None:
    unscoped = "SYNTH-UNSCOPED-A1b2C3d4"
    in_string = "SYNTH-IN-STRING-A1b2C3d4"
    in_secret = "SYNTH-NOSEC-VALUE-A1b2C3d4"
    negative_prose = "SYNTH-NEGATIVE-A1b2C3d4"
    source = _write(
        tmp_path / "nosec.py",
        "\n".join(
            [
                f'password = "{unscoped}"  # nosec',
                f'marker = "nosec"; password = "{in_string}"',
                f'password = "{in_secret}"',
                f'password = "{negative_prose}"  # this is not nosec approved',
                "",
            ]
        ),
    )

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json", "--no-redact")
    )
    output = json.dumps(report)

    assert unscoped in output
    assert in_string in output
    assert in_secret in output
    assert negative_prose in output
    assert len(_credential_findings(report)) == 4


def test_rule_scoped_nosec_suppresses_only_the_named_rule(
    tmp_path: Path,
    run_scanner,
) -> None:
    password = "SYNTH-SCOPED-PASS-A1b2C3d4"
    baseline = _write(
        tmp_path / "baseline.py",
        f'password = "{password}"; os.system(user_input)\n',
    )
    baseline_report = json_report(run_scanner(baseline, "--format", "json"))
    password_hit = next(
        hit for hit in findings(baseline_report) if hit["category"] == "credentials"
    )
    password_rule = rule_id(password_hit)
    assert password_rule == "CREDENTIALS.PASSWORD"

    scoped = _write(
        tmp_path / "scoped.py",
        f'password = "{password}"; os.system(user_input)  # nosec: {password_rule}\n',
    )
    scoped_report = json_report(run_scanner(scoped, "--format", "json"))
    categories = [hit["category"] for hit in findings(scoped_report)]

    assert "credentials" not in categories
    assert "command_injection" in categories


@pytest.mark.parametrize(
    ("filename", "content", "minimum_hits"),
    [
        (".env", "PASSWORD=SYNTH_DOTENV_PASS_A1b2C3d4\n", 1),
        ("settings.env", "API_KEY=SYNTH_DOTENV_API_z9Y8x7W6\n", 1),
        (
            "settings.json",
            '{"password": "SYNTH_JSON_PASS_A1b2C3d4", '
            '"api_key": "SYNTH_JSON_API_z9Y8x7W6"}\n',
            2,
        ),
    ],
)
def test_dotenv_and_quoted_json_credentials_are_detected(
    tmp_path: Path,
    run_scanner,
    filename: str,
    content: str,
    minimum_hits: int,
) -> None:
    source = _write(tmp_path / filename, content)

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )

    assert len(_credential_findings(report)) >= minimum_hits


def test_utf16_source_is_scanned_instead_of_treated_as_binary(
    tmp_path: Path,
    run_scanner,
) -> None:
    secret = "SYNTH-UTF16-PASS-A1b2C3d4"
    source = _write(
        tmp_path / "utf16.py",
        f'password = "{secret}"\n',
        encoding="utf-16",
    )

    result = run_scanner(source, "--credentials", "--format", "json")
    report = json_report(result)

    assert len(_credential_findings(report)) == 1
    assert_sentinel_absent(secret, result.stdout)


def test_decode_failure_is_an_operational_error_with_exit_two(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = tmp_path / "invalid_utf8.py"
    source.write_bytes(b"\x80\x81\x82 invalid UTF-8 without a BOM\n")

    result = run_scanner(source, "--format", "json")

    _assert_operational_error_contract(result)


@pytest.mark.skipif(os.name != "nt", reason="Windows exclusive-file sharing test")
def test_io_failure_is_an_operational_error_with_exit_two_on_windows(
    tmp_path: Path,
    run_scanner,
) -> None:
    import ctypes
    from ctypes import wintypes

    source = _write(tmp_path / "locked.py", "print('synthetic fixture')\n")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    open_existing = 3
    normal_attribute = 0x80
    handle = create_file(
        str(source),
        generic_read,
        0,
        None,
        open_existing,
        normal_attribute,
        None,
    )
    invalid_handle = wintypes.HANDLE(-1).value
    if handle == invalid_handle:
        pytest.skip(f"could not acquire an exclusive test handle: {ctypes.get_last_error()}")
    try:
        result = run_scanner(source, "--format", "json")
    finally:
        close_handle(handle)

    _assert_operational_error_contract(result)


def test_recursive_scan_does_not_follow_file_symlink_outside_root(
    tmp_path: Path,
    run_scanner,
) -> None:
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    outside = _write(
        tmp_path / "outside.py",
        "os.system(user_supplied_command)\n",
    )
    link = scan_root / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    report = json_report(
        run_scanner(scan_root, "--recursive", "--format", "json")
    )

    assert findings(report) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_recursive_scan_does_not_follow_junction_outside_root(
    tmp_path: Path,
    run_scanner,
) -> None:
    scan_root = tmp_path / "root"
    outside = tmp_path / "outside"
    scan_root.mkdir()
    outside.mkdir()
    _write(outside / "outside.py", "os.system(user_supplied_command)\n")
    junction = scan_root / "outside_link"
    created = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {created.stderr.strip()}")
    try:
        report = json_report(
            run_scanner(scan_root, "--recursive", "--format", "json")
        )
    finally:
        os.rmdir(junction)

    assert findings(report) == []


def test_verbose_progress_uses_stderr_and_stdout_remains_json(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(tmp_path / "src" / "app.py", "os.system(user_input)\n")

    result = run_scanner(
        ".",
        "--recursive",
        "--verbose",
        "--format",
        "json",
        cwd=tmp_path,
    )
    report = json.loads(result.stdout)

    assert result.returncode == 0
    assert findings(report)
    assert "scanning:" not in result.stdout.lower()
    assert "scanning:" in result.stderr.lower()


def test_text_output_option_writes_text_not_json(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "app.py", "os.system(user_input)\n")
    output = tmp_path / "report.txt"

    result = run_scanner(source, "--format", "text", "--output", output)
    text = output.read_text(encoding="utf-8")

    assert result.returncode == 0
    assert "[HIGH]" in text
    assert "Command" in text or "command" in text
    with pytest.raises(json.JSONDecodeError):
        json.loads(text)


def test_recursive_dot_paths_are_repository_relative(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(tmp_path / "src" / "app.py", "os.system(user_input)\n")

    report = json_report(
        run_scanner(".", "--recursive", "--format", "json", cwd=tmp_path)
    )
    reported_path = findings(report)[0]["file"]

    assert reported_path == "src/app.py"
    assert "\\" not in reported_path
    assert not re.match(r"^[A-Za-z]:", reported_path)


def test_parameterized_percent_s_sql_is_not_reported(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "safe_sql.py",
        'cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))\n',
    )

    report = json_report(run_scanner(source, "--sqli", "--format", "json"))

    assert findings(report) == []


def test_sql_dot_format_with_untrusted_value_is_reported(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "unsafe_sql.py",
        'query = "SELECT * FROM users WHERE id={}".format(user_id)\n',
    )

    report = json_report(run_scanner(source, "--sqli", "--format", "json"))
    hits = findings(report)

    assert hits
    assert all(hit["category"] == "sql_injection" for hit in hits)
    assert any(hit["severity"] == "HIGH" for hit in hits)
    assert "SQL.FORMAT" in {rule_id(hit) for hit in hits}


def test_yaml_safe_loader_import_forms_are_not_reported(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "safe_yaml.py",
        """import yaml
from yaml import SafeLoader

first = yaml.load(document_one, Loader=yaml.SafeLoader)
second = yaml.load(document_two, Loader=SafeLoader)
""",
    )

    report = json_report(run_scanner(source, "--deser", "--format", "json"))

    assert findings(report) == []


def test_unsafe_yaml_load_uses_stable_rule_id(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "unsafe_yaml.py", "yaml.load(untrusted_document)\n")

    report = json_report(run_scanner(source, "--deser", "--format", "json"))

    assert {rule_id(hit) for hit in findings(report)} == {"DESER.YAML_LOAD"}


def test_nested_subprocess_arguments_with_shell_true_are_reported(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "subprocess_case.py",
        """subprocess.run(
    build_command(user_input),
    cwd=working_directory,
    shell=True,
)
""",
    )

    report = json_report(run_scanner(source, "--cmd", "--format", "json"))
    hits = findings(report)

    assert hits
    assert any(hit["category"] == "command_injection" for hit in hits)
    assert "CMD.SUBPROCESS_SHELL" in {rule_id(hit) for hit in hits}


def test_sarif_uses_stable_per_rule_ids_and_posix_relative_uris(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(
        tmp_path / "src" / "settings.py",
        'password = "SYNTH-SARIF-PASS-A1b2C3d4"\n'
        'api_key = "SYNTH-SARIF-API-z9Y8x7W6"\n',
    )

    def scan() -> dict[str, object]:
        result = run_scanner(
            ".",
            "--recursive",
            "--credentials",
            "--format",
            "sarif",
            cwd=tmp_path,
        )
        assert result.returncode == 0
        return json.loads(result.stdout)

    first = scan()
    second = scan()
    first_run = first["runs"][0]
    second_run = second["runs"][0]
    result_ids = [item["ruleId"] for item in first_run["results"]]
    second_ids = [item["ruleId"] for item in second_run["results"]]
    declared_ids = {
        item["id"] for item in first_run["tool"]["driver"]["rules"]
    }
    uris = [
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in first_run["results"]
    ]

    assert set(result_ids) == {
        "CREDENTIALS.PASSWORD",
        "CREDENTIALS.API_KEY",
    }
    assert result_ids == second_ids
    assert set(result_ids) <= declared_ids
    assert "credentials" not in result_ids
    assert uris == ["src/settings.py", "src/settings.py"]
    assert all("\\" not in uri for uri in uris)
    assert all(not re.match(r"^[A-Za-z]:", uri) for uri in uris)


def test_report_write_failure_is_operational_error_without_traceback(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "app.py", "os.system(user_input)\n")

    result = run_scanner(source, "--format", "json", "--output", tmp_path)

    assert result.returncode == 2
    assert "could not write report" in result.stderr.lower()
    assert "traceback" not in result.stderr.lower()


def test_exclude_is_a_glob_not_an_implicit_substring(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(tmp_path / "contest.py", "os.system(user_input)\n")
    _write(tmp_path / "test.py", "os.system(user_input)\n")

    report = json_report(
        run_scanner(
            ".",
            "--recursive",
            "--format",
            "json",
            "--exclude",
            "test",
            cwd=tmp_path,
        )
    )
    reported = {hit["file"] for hit in findings(report)}

    assert reported == {"contest.py", "test.py"}


def test_dotfile_include_and_exclude_preserve_the_leading_dot(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(tmp_path / ".env", "PASSWORD=SYNTH_DOTFILE_A1b2C3d4\n")

    excluded = json_report(
        run_scanner(
            ".",
            "--recursive",
            "--credentials",
            "--format",
            "json",
            "--exclude",
            ".env",
            cwd=tmp_path,
        )
    )
    included = json_report(
        run_scanner(
            ".",
            "--recursive",
            "--credentials",
            "--format",
            "json",
            "--include",
            ".env",
            cwd=tmp_path,
        )
    )

    assert findings(excluded) == []
    assert excluded["summary"]["files_scanned"] == 0
    assert {rule_id(hit) for hit in findings(included)} == {
        "CREDENTIALS.PASSWORD"
    }


def test_python_triple_quoted_nosec_text_cannot_suppress_real_code(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "triple_string.py",
        'doc = """\n# nosec: CREDENTIALS.PASSWORD"""; '
        'password = "SYNTH-REAL-PASS-A1b2C3d4"\n',
    )

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )

    assert {rule_id(hit) for hit in findings(report)} == {
        "CREDENTIALS.PASSWORD"
    }
    assert report["summary"]["suppressed"] == 0


def test_multiline_rule_scoped_nosec_can_follow_the_relevant_argument(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "multiline_suppression.py",
        """subprocess.run(
    build_command(user_input),
    shell=True,  # nosec: CMD.SUBPROCESS_SHELL
)
""",
    )

    report = json_report(run_scanner(source, "--cmd", "--format", "json"))

    assert findings(report) == []
    assert report["summary"]["suppressed"] == 1


def test_javascript_regex_literal_cannot_create_a_suppression(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "regex_literal.js",
        'const password = "SYNTH-REAL-A1b2C3d4"; '
        'const re = /[//] nosec: CREDENTIALS.PASSWORD/;\n',
    )

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )

    assert {rule_id(hit) for hit in findings(report)} == {
        "CREDENTIALS.PASSWORD"
    }
    assert report["summary"]["suppressed"] == 0


def test_short_secrets_use_fixed_redaction_without_prefix_or_suffix_leak(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "short.py", 'password = "abcde"\n')

    result = run_scanner(source, "--credentials", "--format", "json")
    report = json_report(result)
    serialized = result.stdout

    assert "abcde" not in serialized
    assert "ab*de" not in serialized
    assert "[REDACTED]" in serialized
    assert len(findings(report)) == 1


def test_overlapping_aws_patterns_produce_one_finding(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "aws.py",
        'aws_access_key_id = "AKIAABCDEFGHIJKLMNOP"\n',
    )

    report = json_report(
        run_scanner(source, "--credentials", "--format", "json")
    )
    aws_hits = [
        hit
        for hit in findings(report)
        if rule_id(hit) == "CREDENTIALS.AWS_ACCESS_KEY_ID"
    ]

    assert len(aws_hits) == 1


def test_range_deduplication_uses_ordered_neighbour_checks() -> None:
    class NoFullIteration(list):
        def __iter__(self):
            raise AssertionError("range deduplication must not linearly rescan")

    ranges = NoFullIteration()
    for index in range(10_000):
        assert vulnscan._claim_nonoverlapping_range(
            ranges, index * 3, index * 3 + 2
        )

    assert len(ranges) == 10_000
    assert not vulnscan._claim_nonoverlapping_range(ranges, 15_000, 15_001)


def test_subprocess_rule_does_not_cross_a_completed_safe_call(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "safe_subprocess.py",
        "subprocess.run(['echo', 'safe'])\nother_call(shell=True)\n",
    )

    report = json_report(run_scanner(source, "--cmd", "--format", "json"))

    assert findings(report) == []


def test_subprocess_rule_uses_python_call_syntax(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "subprocess_syntax.py",
        """subprocess.run(["echo", "shell=True"])
subprocess.run(
    ["echo"]  # shell=True
)
subprocess.run(build(os.path.join(base, user)), shell=True)
""",
    )

    report = json_report(run_scanner(source, "--cmd", "--format", "json"))
    hits = [
        hit
        for hit in findings(report)
        if rule_id(hit) == "CMD.SUBPROCESS_SHELL"
    ]

    assert len(hits) == 1
    assert hits[0]["line"] == 5


def test_nested_subprocess_calls_remain_distinct_findings(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "nested_subprocess.py",
        "subprocess.run(subprocess.run(inner, shell=True), shell=True)\n",
    )

    report = json_report(run_scanner(source, "--cmd", "--format", "json"))

    assert sum(
        rule_id(hit) == "CMD.SUBPROCESS_SHELL" for hit in findings(report)
    ) == 2


def test_yaml_safe_loader_words_inside_an_unrelated_string_do_not_bypass(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "unsafe_yaml_note.py",
        'yaml.load(data, note="Loader=SafeLoader")\n',
    )

    report = json_report(run_scanner(source, "--deser", "--format", "json"))

    assert {rule_id(hit) for hit in findings(report)} == {"DESER.YAML_LOAD"}


def test_yaml_safe_loader_words_inside_a_comment_do_not_bypass(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "unsafe_yaml_comment.py",
        """yaml.load(data  # , Loader=SafeLoader
)
""",
    )

    report = json_report(run_scanner(source, "--deser", "--format", "json"))

    assert {rule_id(hit) for hit in findings(report)} == {"DESER.YAML_LOAD"}


@pytest.mark.parametrize("report_format", ["text", "json", "sarif"])
@pytest.mark.parametrize(
    "source_text",
    [
        r'password = "SYNTH-HEAD\"LEAK-TAIL-A1b2"' + "\n",
        r"password = 'SYNTH-HEAD\'LEAK-TAIL-A1b2'" + "\n",
    ],
)
def test_escaped_quotes_cannot_leak_secret_suffixes(
    tmp_path: Path,
    run_scanner,
    report_format: str,
    source_text: str,
) -> None:
    source = _write(tmp_path / "escaped_secret.py", source_text)

    result = run_scanner(
        source, "--credentials", "--format", report_format
    )

    assert result.returncode == 0
    assert "SYNTH-HEAD" not in result.stdout
    assert "LEAK-TAIL" not in result.stdout
    assert "[REDACTED]" in result.stdout


@pytest.mark.parametrize("report_format", ["text", "json", "sarif"])
@pytest.mark.parametrize(
    ("filename", "source_text"),
    [
        (
            "adjacent.py",
            'password = "SYNTH-HEAD" "LEAK-TAIL-A1b2"\n',
        ),
        (
            "doubled.yaml",
            "password: 'SYNTH-HEAD''LEAK-TAIL-A1b2'\n",
        ),
    ],
)
def test_credential_lines_are_redacted_as_a_safe_output_boundary(
    tmp_path: Path,
    run_scanner,
    report_format: str,
    filename: str,
    source_text: str,
) -> None:
    source = _write(tmp_path / filename, source_text)

    result = run_scanner(
        source, "--credentials", "--format", report_format
    )

    assert result.returncode == 0
    assert "SYNTH-HEAD" not in result.stdout
    assert "LEAK-TAIL" not in result.stdout
    assert "[REDACTED]" in result.stdout


def test_ast_backed_rules_handle_cr_only_and_crlf_sources(
    tmp_path: Path,
    run_scanner,
) -> None:
    yaml_source = tmp_path / "cr_only.py"
    yaml_source.write_bytes(b"x = 1\ryaml.load(data)\r")
    command_source = tmp_path / "crlf.py"
    command_source.write_bytes(
        b"x = 1\r\nsubprocess.run(build(value), shell=True)\r\n"
    )

    yaml_result = run_scanner(yaml_source, "--deser", "--format", "json")
    command_result = run_scanner(command_source, "--cmd", "--format", "json")
    yaml_report = json_report(yaml_result)
    command_report = json_report(command_result)

    assert {rule_id(hit) for hit in findings(yaml_report)} == {
        "DESER.YAML_LOAD"
    }
    assert {rule_id(hit) for hit in findings(command_report)} == {
        "CMD.SUBPROCESS_SHELL"
    }
    assert "traceback" not in (yaml_result.stderr + command_result.stderr).lower()


def test_newer_python_syntax_uses_version_tolerant_semantic_fallback(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "modern_syntax.py",
        """type Alias = int
subprocess.run(["echo", "safe"])
yaml.load(data, Loader=yaml.SafeLoader)
""",
    )

    report = json_report(run_scanner(source, "--format", "json"))

    assert "CMD.SUBPROCESS_SHELL" not in {
        rule_id(hit) for hit in findings(report)
    }
    assert "DESER.YAML_LOAD" not in {
        rule_id(hit) for hit in findings(report)
    }
    fallback = vulnscan._python_token_semantic_rule_offsets(
        source.read_text(encoding="utf-8")
    )
    assert fallback is not None
    assert fallback["CMD.SUBPROCESS_SHELL"] == {}
    assert fallback["DESER.YAML_LOAD"] == {}

    unsafe_fallback = vulnscan._python_token_semantic_rule_offsets(
        """type Alias = int
subprocess.run(build(os.path.join(base, user)), shell=True)
yaml.load(data)
"""
    )
    assert unsafe_fallback is not None
    assert len(unsafe_fallback["CMD.SUBPROCESS_SHELL"]) == 1
    assert len(unsafe_fallback["DESER.YAML_LOAD"]) == 1


def test_windows_style_traversal_sequence_is_reported(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(
        tmp_path / "windows_path.py",
        'path = r"..\\..\\Windows\\win.ini"\n',
    )

    report = json_report(run_scanner(source, "--path", "--format", "json"))

    assert "PATH.TRAVERSAL_SEQUENCE" in {
        rule_id(hit) for hit in findings(report)
    }


def test_sarif_uri_is_percent_encoded_and_declares_column_kind(
    tmp_path: Path,
    run_scanner,
) -> None:
    _write(tmp_path / "src" / "a # x% 雪.py", "os.system(user_input)\n")

    result = run_scanner(
        ".", "--recursive", "--format", "sarif", cwd=tmp_path
    )
    sarif = json.loads(result.stdout)
    run = sarif["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]

    assert result.returncode == 0
    assert run["columnKind"] == "unicodeCodePoints"
    assert uri == "src/a%20%23%20x%25%20%E9%9B%AA.py"
    assert "partialFingerprints" not in run["results"][0]


def test_scan_target_cannot_also_be_the_output_file(
    tmp_path: Path,
    run_scanner,
) -> None:
    source = _write(tmp_path / "source.py", "os.system(user_input)\n")
    before = source.read_bytes()

    result = run_scanner(source, "--format", "text", "--output", source)

    assert result.returncode == 2
    assert "output path is the scan target" in result.stderr.lower()
    assert source.read_bytes() == before


def test_directory_scan_cannot_overwrite_an_existing_source_file(
    tmp_path: Path,
    run_scanner,
) -> None:
    scan_root = tmp_path / "repo"
    victim = _write(scan_root / "victim.py", "os.system(victim_input)\n")
    _write(scan_root / "other.py", "os.system(other_input)\n")
    before = victim.read_bytes()

    result = run_scanner(
        scan_root,
        "--recursive",
        "--format",
        "json",
        "--output",
        victim,
    )

    assert result.returncode == 2
    assert "refusing to overwrite" in result.stderr.lower()
    assert victim.read_bytes() == before


def test_report_output_rejects_a_linked_parent_directory(
    tmp_path: Path,
    run_scanner,
) -> None:
    scan_root = tmp_path / "root"
    outside = tmp_path / "outside"
    scan_root.mkdir()
    outside.mkdir()
    _write(scan_root / "app.py", "os.system(user_input)\n")
    linked = scan_root / "reports"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("directory symlinks are unavailable")
        created = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(linked), str(outside)],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if created.returncode != 0:
            pytest.skip(f"linked output directory is unavailable: {created.stderr}")
    try:
        output = linked / "scan.json"
        result = run_scanner(
            scan_root,
            "--recursive",
            "--format",
            "json",
            "--output",
            output,
        )
    finally:
        if linked.is_symlink():
            linked.unlink()
        else:
            os.rmdir(linked)

    assert result.returncode == 2
    assert "symlink, junction, or reparse point" in result.stderr.lower()
    assert not (outside / "scan.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction fallback")
def test_windows_junction_fallback_works_without_os_path_isjunction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scan_root = tmp_path / "root"
    outside = tmp_path / "outside"
    scan_root.mkdir()
    outside.mkdir()
    _write(outside / "outside.py", "os.system(user_input)\n")
    junction = scan_root / "outside_link"
    created = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {created.stderr.strip()}")
    try:
        monkeypatch.delattr(os.path, "isjunction", raising=False)
        assert vulnscan._is_link_or_junction(str(junction))

        nested_scanner = vulnscan.Scanner()
        assert nested_scanner.scan_path(str(scan_root), recursive=True) == []
        assert nested_scanner.skipped_links == 1
        assert not nested_scanner.has_errors

        top_level_scanner = vulnscan.Scanner()
        assert top_level_scanner.scan_path(str(junction), recursive=True) == []
        assert top_level_scanner.skipped_links == 1
        assert top_level_scanner.has_errors
    finally:
        os.rmdir(junction)
