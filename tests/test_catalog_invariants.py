"""Structural invariants for the public rule catalogue."""

from __future__ import annotations

import re

import vulnscan


RULE_ID = re.compile(r"^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$")


def test_rule_ids_are_unique_stable_and_indexed() -> None:
    ids = [rule.id for rule in vulnscan.RULES]

    assert ids
    assert len(ids) == len(set(ids)), "stable rule IDs must be unique"
    assert all(RULE_ID.fullmatch(rule_id) for rule_id in ids)
    assert set(vulnscan.RULE_BY_ID) == set(ids)
    assert all(vulnscan.RULE_BY_ID[rule.id] is rule for rule in vulnscan.RULES)


def test_rule_enums_descriptions_and_categories_are_valid() -> None:
    known_categories = set(vulnscan.CATEGORY_FLAGS)

    for rule in vulnscan.RULES:
        assert rule.category in known_categories, rule.id
        assert rule.severity in vulnscan.SEVERITY_ORDER, rule.id
        assert rule.confidence in vulnscan.CONFIDENCE_ORDER, rule.id
        assert isinstance(rule.description, str) and rule.description.strip(), rule.id
        assert rule.patterns, rule.id


def test_patterns_compile_and_declared_secret_groups_exist() -> None:
    valid_kinds = set(vulnscan.EXTENSION_KIND.values())

    for rule in vulnscan.RULES:
        for spec in rule.patterns:
            assert isinstance(spec.pattern, str) and spec.pattern, rule.id
            compiled = re.compile(spec.pattern, re.IGNORECASE | re.MULTILINE)
            assert all(isinstance(kind, str) and kind for kind in spec.kinds), rule.id
            assert set(spec.kinds) <= valid_kinds, (
                f"{rule.id} declares unknown file kinds {set(spec.kinds) - valid_kinds}"
            )
            if spec.secret_group is not None:
                assert isinstance(spec.secret_group, str) and spec.secret_group
                assert spec.secret_group in compiled.groupindex, (
                    f"{rule.id} names missing capture group {spec.secret_group!r}"
                )


def test_cwe_values_are_positive_integers_when_present() -> None:
    for rule in vulnscan.RULES:
        assert rule.cwe is None or (
            isinstance(rule.cwe, int)
            and not isinstance(rule.cwe, bool)
            and rule.cwe > 0
        ), rule.id
