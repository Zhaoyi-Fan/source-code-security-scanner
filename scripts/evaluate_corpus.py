#!/usr/bin/env python3
"""Evaluate the exact synthetic rule corpus and fail on regressions.

The evaluator is dependency-free so it can run locally or as a CI quality gate.
It reports corpus-wide and per-rule TP/FP/FN, precision, recall, and duplicate
findings. Exit 0 means the catalogue has positive/negative coverage and every
case produced its exact expected finding multiset; exit 1 means a regression;
exit 2 means the manifest itself could not be evaluated.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path, PurePath
import sys
import tempfile
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import vulnscan  # noqa: E402  (repository root is intentionally added first)


DEFAULT_MANIFEST = REPO_ROOT / "tests" / "corpus" / "manifest.jsonl"
REQUIRED_FIELDS = {"case_id", "filename", "source", "expected_rules", "tags"}
SYNTHETIC_EXPANSIONS = {
    "{{SYNTHETIC_GITHUB_TOKEN}}": "ghp_" + "SYNTHETIC" + ("0" * 27),
    "{{SYNTHETIC_GITLAB_TOKEN}}": "glpat-" + "SYNTHETIC" + ("0" * 11),
}


class CorpusError(ValueError):
    """Raised when a corpus cannot be interpreted safely and deterministically."""


def materialize_source(source: str) -> str:
    """Expand test-only provider tokens without storing token-shaped strings."""

    for marker, value in SYNTHETIC_EXPANSIONS.items():
        source = source.replace(marker, value)
    if "{{SYNTHETIC_" in source:
        raise CorpusError("manifest contains an unknown synthetic expansion marker")
    return source


@dataclass
class RuleMetrics:
    rule_id: str
    positive_cases: int = 0
    negative_cases: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicates: int = 0

    @property
    def precision(self) -> float:
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.tp + self.fn
        if denominator:
            return self.tp / denominator
        return 0.0 if self.positive_cases == 0 else 1.0

    def report(self) -> dict[str, Any]:
        value = asdict(self)
        value["precision"] = round(self.precision, 6)
        value["recall"] = round(self.recall, 6)
        return value


def _strings(value: object, field: str, line_number: int) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise CorpusError(
            f"manifest line {line_number}: {field} must be a list of non-empty strings"
        )
    return value


def load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CorpusError(f"could not read manifest {path}: {exc}") from exc

    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_filenames: set[str] = set()
    known_rules = set(vulnscan.RULE_BY_ID)
    for line_number, raw_line in enumerate(raw_lines, 1):
        if not raw_line.strip():
            continue
        try:
            case = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise CorpusError(f"manifest line {line_number}: invalid JSON: {exc}") from exc
        if not isinstance(case, dict) or not REQUIRED_FIELDS <= set(case):
            raise CorpusError(
                f"manifest line {line_number}: required fields are "
                + ", ".join(sorted(REQUIRED_FIELDS))
            )
        for field in ("case_id", "filename", "source"):
            if not isinstance(case[field], str) or not case[field]:
                raise CorpusError(
                    f"manifest line {line_number}: {field} must be a non-empty string"
                )
        expected = _strings(case["expected_rules"], "expected_rules", line_number)
        tags = _strings(case["tags"], "tags", line_number)
        unknown = set(expected) - known_rules
        if unknown:
            raise CorpusError(
                f"manifest line {line_number}: unknown expected rules {sorted(unknown)}"
            )
        if case["case_id"] in seen_ids:
            raise CorpusError(f"manifest line {line_number}: duplicate case_id")
        if case["filename"] in seen_filenames:
            raise CorpusError(f"manifest line {line_number}: duplicate filename")
        if PurePath(case["filename"]).name != case["filename"]:
            raise CorpusError(
                f"manifest line {line_number}: filename must not contain a directory"
            )
        polarity = {tag for tag in tags if tag in {"positive", "negative"}}
        target_tags = [tag[5:] for tag in tags if tag.startswith("rule:")]
        if len(polarity) != 1 or len(target_tags) != 1:
            raise CorpusError(
                f"manifest line {line_number}: exactly one polarity and rule:<ID> tag required"
            )
        if target_tags[0] not in known_rules:
            raise CorpusError(
                f"manifest line {line_number}: unknown tagged rule {target_tags[0]}"
            )
        if "negative" in polarity and expected:
            raise CorpusError(
                f"manifest line {line_number}: negative case must expect no findings"
            )
        if "positive" in polarity and expected != target_tags:
            raise CorpusError(
                f"manifest line {line_number}: positive case must expect its tagged rule once"
            )
        seen_ids.add(case["case_id"])
        seen_filenames.add(case["filename"])
        cases.append(case)
    if not cases:
        raise CorpusError("manifest contains no cases")
    return cases


def _target_rule(tags: Iterable[str]) -> str:
    return next(tag[5:] for tag in tags if tag.startswith("rule:"))


def evaluate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = {rule.id: RuleMetrics(rule.id) for rule in vulnscan.RULES}
    failures: list[dict[str, Any]] = []
    exact_cases = 0
    diagnostic_count = 0

    with tempfile.TemporaryDirectory(prefix="vulnscan-corpus-") as temporary:
        root = Path(temporary)
        for index, case in enumerate(cases):
            case_root = root / f"case-{index:04d}"
            case_root.mkdir()
            source = case_root / case["filename"]
            source.write_text(materialize_source(case["source"]), encoding="utf-8")

            scanner = vulnscan.Scanner()
            observed_findings = scanner.scan_file(str(source), case["filename"])
            expected = Counter(case["expected_rules"])
            observed = Counter(finding.rule_id for finding in observed_findings)
            target = _target_rule(case["tags"])
            if "positive" in case["tags"]:
                metrics[target].positive_cases += 1
            else:
                metrics[target].negative_cases += 1

            for rule_id, rule_metrics in metrics.items():
                expected_count = expected[rule_id]
                observed_count = observed[rule_id]
                rule_metrics.tp += min(expected_count, observed_count)
                rule_metrics.fp += max(0, observed_count - expected_count)
                rule_metrics.fn += max(0, expected_count - observed_count)
                rule_metrics.duplicates += max(0, observed_count - 1)

            diagnostics = [asdict(item) for item in scanner.diagnostics]
            diagnostic_count += len(diagnostics)
            if expected == observed and not diagnostics:
                exact_cases += 1
            else:
                failures.append(
                    {
                        "case_id": case["case_id"],
                        "expected_rules": list(expected.elements()),
                        "observed_rules": list(observed.elements()),
                        "diagnostics": diagnostics,
                    }
                )

    uncovered = {
        rule_id: [
            polarity
            for polarity, count in (
                ("positive", item.positive_cases),
                ("negative", item.negative_cases),
            )
            if count == 0
        ]
        for rule_id, item in metrics.items()
        if item.positive_cases == 0 or item.negative_cases == 0
    }
    tp = sum(item.tp for item in metrics.values())
    fp = sum(item.fp for item in metrics.values())
    fn = sum(item.fn for item in metrics.values())
    duplicates = sum(item.duplicates for item in metrics.values())
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    passed = not (failures or uncovered or fp or fn or duplicates or diagnostic_count)
    return {
        "passed": passed,
        "overall": {
            "cases": len(cases),
            "exact_cases": exact_cases,
            "rules": len(metrics),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "duplicates": duplicates,
            "diagnostics": diagnostic_count,
        },
        "per_rule": [item.report() for item in metrics.values()],
        "uncovered": uncovered,
        "failures": failures,
    }


def render_text(report: dict[str, Any]) -> str:
    overall = report["overall"]
    lines = [
        (
            "Corpus: {exact_cases}/{cases} exact cases; {rules} rules; "
            "TP={tp} FP={fp} FN={fn} duplicates={duplicates} "
            "precision={precision:.3f} recall={recall:.3f} diagnostics={diagnostics}"
        ).format(**overall),
        "",
        "Rule                                      +    -   TP   FP   FN  Dup   Prec    Rec",
        "-" * 87,
    ]
    for item in report["per_rule"]:
        lines.append(
            f"{item['rule_id']:<40} {item['positive_cases']:>4} "
            f"{item['negative_cases']:>4} {item['tp']:>4} {item['fp']:>4} "
            f"{item['fn']:>4} {item['duplicates']:>4} "
            f"{item['precision']:>6.3f} {item['recall']:>6.3f}"
        )
    if report["uncovered"]:
        lines.extend(("", "Missing catalogue coverage:"))
        for rule_id, missing in report["uncovered"].items():
            lines.append(f"  {rule_id}: {', '.join(missing)}")
    if report["failures"]:
        lines.extend(("", "Non-exact cases:"))
        for failure in report["failures"]:
            lines.append(
                f"  {failure['case_id']}: expected={failure['expected_rules']} "
                f"observed={failure['observed_rules']} "
                f"diagnostics={len(failure['diagnostics'])}"
            )
    lines.extend(("", "PASS" if report["passed"] else "FAIL"))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="JSONL corpus manifest (default: tests/corpus/manifest.jsonl)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = evaluate(load_cases(args.manifest.resolve()))
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
