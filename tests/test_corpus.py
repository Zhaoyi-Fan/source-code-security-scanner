"""Exact synthetic corpus checks for every stable scanner rule."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path, PurePath
from typing import Any

import pytest
import vulnscan


MANIFEST = Path(__file__).parent / "corpus" / "manifest.jsonl"
REQUIRED_FIELDS = {"case_id", "filename", "source", "expected_rules", "tags"}
SYNTHETIC_EXPANSIONS = {
    "{{SYNTHETIC_GITHUB_TOKEN}}": "ghp_" + "SYNTHETIC" + ("0" * 27),
    "{{SYNTHETIC_GITLAB_TOKEN}}": "glpat-" + "SYNTHETIC" + ("0" * 11),
}


def _load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        MANIFEST.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not raw_line.strip():
            continue
        try:
            case = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"invalid JSON on {MANIFEST.name} line {line_number}: {exc}"
            ) from exc
        assert isinstance(case, dict), f"manifest line {line_number} must be an object"
        cases.append(case)
    return cases


CASES = _load_cases()


def _target_rule(case: dict[str, Any]) -> str:
    tagged = [tag[5:] for tag in case["tags"] if tag.startswith("rule:")]
    assert len(tagged) == 1, f"{case['case_id']} needs exactly one rule:<ID> tag"
    return tagged[0]


def _materialize_source(source: str) -> str:
    for marker, value in SYNTHETIC_EXPANSIONS.items():
        source = source.replace(marker, value)
    assert "{{SYNTHETIC_" not in source, "unknown synthetic expansion marker"
    return source


def test_manifest_schema_and_identifiers_are_stable() -> None:
    assert CASES, "the exact-result corpus must not be empty"
    case_ids: list[str] = []
    filenames: list[str] = []
    known_rules = set(vulnscan.RULE_BY_ID)

    for case in CASES:
        assert set(case) == REQUIRED_FIELDS
        assert all(isinstance(case[field], str) and case[field] for field in (
            "case_id",
            "filename",
            "source",
        ))
        assert isinstance(case["expected_rules"], list)
        assert isinstance(case["tags"], list) and case["tags"]
        assert all(isinstance(value, str) and value for value in case["expected_rules"])
        assert all(isinstance(value, str) and value for value in case["tags"])
        assert set(case["expected_rules"]) <= known_rules
        assert "synthetic" in case["tags"]
        assert ("positive" in case["tags"]) ^ ("negative" in case["tags"])
        assert PurePath(case["filename"]).name == case["filename"]
        assert vulnscan.Scanner.should_scan(case["filename"]), (
            f"{case['case_id']} uses a filename skipped by normal scans"
        )
        if "negative" in case["tags"]:
            assert case["expected_rules"] == []
        else:
            assert case["expected_rules"] == [_target_rule(case)]
        if (
            "positive" in case["tags"]
            and _target_rule(case).startswith("CREDENTIALS.")
        ):
            assert "SYNTHETIC" in case["source"], (
                f"{case['case_id']} must visibly use synthetic credential material"
            )
        case_ids.append(case["case_id"])
        filenames.append(case["filename"])

    assert len(case_ids) == len(set(case_ids)), "case_id values must be unique"
    assert len(filenames) == len(set(filenames)), "corpus filenames must be unique"


def test_manifest_has_positive_and_nearby_negative_for_every_rule() -> None:
    coverage: dict[str, set[str]] = defaultdict(set)
    for case in CASES:
        polarity = "positive" if "positive" in case["tags"] else "negative"
        coverage[_target_rule(case)].add(polarity)

    missing = {
        rule.id: sorted({"positive", "negative"} - coverage[rule.id])
        for rule in vulnscan.RULES
        if coverage[rule.id] != {"positive", "negative"}
    }
    assert not missing, f"rules missing exact corpus coverage: {missing}"
    assert set(coverage) == set(vulnscan.RULE_BY_ID)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["case_id"])
def test_corpus_case_has_exact_findings_and_valid_locations(
    case: dict[str, Any], tmp_path: Path
) -> None:
    source = tmp_path / case["filename"]
    materialized_source = _materialize_source(case["source"])
    source.write_text(materialized_source, encoding="utf-8")
    scanner = vulnscan.Scanner()

    observed = scanner.scan_file(str(source), case["filename"])
    observed_ids = [finding.rule_id for finding in observed]

    assert Counter(observed_ids) == Counter(case["expected_rules"]), (
        f"expected exact rules {case['expected_rules']}, got {observed_ids}"
    )
    assert not scanner.diagnostics

    source_lines = materialized_source.splitlines() or [""]
    for finding in observed:
        assert finding.file == case["filename"]
        assert 1 <= finding.line <= len(source_lines)
        assert 1 <= finding.end_line <= len(source_lines)
        assert finding.end_line >= finding.line
        assert 1 <= finding.column <= len(source_lines[finding.line - 1]) + 1
        assert 1 <= finding.end_column <= len(source_lines[finding.end_line - 1]) + 1
        if finding.line == finding.end_line:
            assert finding.end_column >= finding.column
        assert finding.match
        assert finding.context
