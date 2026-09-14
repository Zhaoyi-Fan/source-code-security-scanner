# Changelog

All notable changes to this project are documented here. The project follows semantic versioning
for release tags; entries under **Unreleased** may change before the next tag is created.

## [Unreleased] - planned 2.2.0

### Added

- A rule corpus and repeatable accuracy report so rule changes can be reviewed against named
  positive and negative cases.
- A standard Python package definition and `vulnscan` console command while retaining direct,
  dependency-free `python vulnscan.py` execution.
- A versioned JSON report schema, resource-bound reporting, suppression audit information, and
  clearer CI integration guidance.
- A side-effect-free `scan(ScanConfig) -> ScanResult` library boundary with explicit `ScanStats`.
- Auditable Python suppressions in JSON/SARIF, stale/unknown-ID warnings, justification enforcement,
  and an optional suppression policy gate.
- Aggregate file-count, byte-count, and finding-count limits in addition to the existing per-file
  limit; incomplete and truncated state is machine readable.
- A synthetic quick-start example, an assurance model, a threat model, and a security policy.

### Changed

- Improved selected Python call rules with alias/from-import and shadowing-aware AST checks;
  corrected safe/unsafe PyYAML loader handling.
- Added GitHub/GitLab token, OAuth client-secret, connection-URL, Python `eval`/`exec`, and PyYAML
  `unsafe_load` rules, plus issue-level credential overlap clustering and broader placeholder
  recognition.
- Reworked the README around a 30-second first run, expected output, reviewer workflow, and honest
  scope boundaries.
- Hardened the project's own CI with minimal permissions, pinned actions, time limits, a
  dependency-free smoke test, corpus evaluation, and an installed-wheel test.

### Compatibility

- Python 3.10 or newer is required.
- Direct single-file use remains supported and has no required third-party dependency.
- JSON consumers should select behavior by `schema_version` and validate v2.2 reports against
  [`schemas/vulnscan-2.2.schema.json`](schemas/vulnscan-2.2.schema.json).

## [2.1] - 2026-07-11

### Added

- Centralized line-safe credential redaction for text, JSON, and SARIF output.
- Stable rule IDs, overlap-aware finding de-duplication, strict diagnostics, and stable relative
  report paths.
- Scoped Python-only `nosec` suppressions, `.env` coverage, safe no-clobber report writing, and
  Linux/Windows regression CI.

### Changed

- Separated severity from confidence and made scan errors take precedence over finding gates.
- Kept machine-readable output clean by sending progress and diagnostics to stderr.

## [2.0] - 2026-07-11

- Added severity, credential entropy, default redaction, JSON/SARIF output, CI gating,
  suppressions, and weak-crypto/deserialization categories.
- Historical release: later v2.1 work corrected output-safety and fail-open behavior found during
  review. Prefer the newest release for active use.

[Unreleased]: https://github.com/Zhaoyi-Fan/source-code-security-scanner/compare/v2.0...HEAD
[2.1]: https://github.com/Zhaoyi-Fan/source-code-security-scanner/commits/161fc76f45c1ea5c07daa298d999ffe8a507c78b
[2.0]: https://github.com/Zhaoyi-Fan/source-code-security-scanner/releases/tag/v2.0
