# Source Code Security Scanner

[![CI](https://github.com/Zhaoyi-Fan/source-code-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Zhaoyi-Fan/source-code-security-scanner/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An **offline, regex-led source-review triage tool** for quickly surfacing embedded credentials and
potentially unsafe code before manual review. It is dependency-free by default, ships as one
Python module, and produces safe text, JSON, or SARIF reports for local and CI workflows.

It is intentionally narrower than a full SAST engine: findings are review candidates, not proof
of exploitability, and a clean scan is not proof that an application is secure.

## 30-second demo

No installation, account, network access, or real secret is needed after cloning the repository:

```bash
git clone https://github.com/Zhaoyi-Fan/source-code-security-scanner.git
cd source-code-security-scanner
python vulnscan.py examples/demo_vulnerable.py --fail-on high
```

Expected output (paths and columns may vary slightly by platform):

```text
[HIGH]    L11:1 CREDENTIALS.PASSWORD - Hardcoded password (entropy 4.32, high)
          [REDACTED]
[HIGH]    L13:10 SQL.CONCAT - SQL built by string concatenation (medium)
          query = "SELECT * FROM users WHERE id=" + user_id
[HIGH]    L14:1 CMD.SUBPROCESS_SHELL - Python subprocess with shell=True (high)
          subprocess.run("account-tool --id " + user_id, shell=True)
[HIGH]    L15:11 DESER.PICKLE - Python pickle deserialization (medium)
          profile = pickle.loads(input("Serialized profile: ").encode())
[MEDIUM]  L16:18 CRYPTO.MD5 - Weak hash: MD5 (medium)
          digest = hashlib.md5(b"synthetic-demo").hexdigest()

SUMMARY: 5 finding(s) | HIGH 4  MEDIUM 1  LOW 0  INFO 0  ERRORS 0  SUPPRESSED 0
```

Exit `1` is expected because the demo deliberately asks the scanner to fail on high-severity
findings. The file contains only fictional synthetic values. On Windows, use `py` in place of
`python` if that is how Python is registered.

## Why use it

- **Fast local first pass:** run a single file offline with Python 3.10+ and no required package.
- **Reviewable findings:** stable rule IDs, severity, confidence, CWE metadata, source locations,
  and repository-relative paths.
- **Safer reports:** candidate credential lines are redacted by default in text, JSON, and SARIF.
- **CI-aware behavior:** distinct clean, finding-gate, and incomplete-scan exit codes; diagnostics
  do not corrupt machine-readable stdout.
- **Bounded operation:** containment checks, no-clobber output, input/report limits, and visible
  incomplete-result diagnostics.
- **Measured changes:** a positive/negative rule corpus makes supported behavior and regressions
  inspectable instead of relying only on a rule count.

## Install or keep the single file

Direct execution remains the simplest offline path:

```bash
python vulnscan.py --version
python vulnscan.py -r ./src
```

For a standard command-line installation from a reviewed checkout:

```bash
python -m pip install .
vulnscan --version
vulnscan -r ./src
```

Optional terminal colours are the only runtime extra:

```bash
python -m pip install ".[color]"
```

Installing the package and downloading the standalone `vulnscan.py` are two interfaces to the
same module. The scanner never uploads target code.

## Common workflows

```bash
# Scan all enabled categories recursively
python vulnscan.py -r ./target-source

# Narrow triage to SQL and command injection candidates
python vulnscan.py -r --sqli --cmd ./target-source

# Review credential candidates at medium confidence or higher
python vulnscan.py -r -c --min-confidence medium ./src

# Machine-readable reports
python vulnscan.py -r ./src --format json -o vulnscan.json
python vulnscan.py -r ./src --format sarif -o vulnscan.sarif

# CI gate: exit 1 for a medium/high finding
python vulnscan.py -r ./src --fail-on medium

# Governance gate: require reasons and fail if any accepted suppression remains
python vulnscan.py -r ./src --require-suppression-reason --fail-on-suppressed

# Discover rule IDs and run the built-in smoke test
python vulnscan.py --show-categories
python vulnscan.py --test-patterns
```

Run `python vulnscan.py --help` for include/exclude globs, confidence and entropy filters, base
paths, resource limits, and output options.

## Detection scope

| Category | Default severity | Flag | Typical candidates |
|---|---:|---|---|
| Credentials | HIGH | `-c` | passwords, API keys, tokens, private-key headers, connection strings |
| SQL injection | HIGH | `--sqli` | concatenated/formatted SQL and unsafe statement construction |
| Command injection | HIGH | `--cmd` | shell/evaluation sinks with dynamic input |
| Deserialization | HIGH | `--deser` | pickle, unsafe YAML load, and common object-loading APIs |
| Weak crypto | MEDIUM | `--crypto` | MD5, SHA-1, DES, ECB mode, and non-cryptographic PRNG use |
| Path traversal | MEDIUM | `--path` | dynamic file paths, include/read patterns, and traversal sequences |
| Database operations | LOW | `--db` | connection, file-backed SQL, and MongoDB operator patterns |
| Interesting files | INFO | `--interesting` | configuration, backup, debug, and development markers |

The scanner covers common Python, Java, PHP, JavaScript/TypeScript, C#, Go, Ruby, shell, XML,
YAML, JSON, SQL, dotenv, and configuration files. Most rules inspect local text patterns. Limited
Python AST/token checks improve selected syntax-sensitive rules, but there is no general parser,
interprocedural analysis, value flow, reachability model, or sanitizer model.

Inspect the exact enabled catalog with `--show-categories`. Stable IDs such as
`CREDENTIALS.PASSWORD`, `SQL.CONCAT`, and `CMD.SUBPROCESS_SHELL` are shared by reports,
benchmarks, and suppressions.

## Review a result

Use this sequence for each candidate:

1. Confirm the matched API or value and whether the file is production-relevant.
2. Trace whether attacker-controlled data can reach it and what validation occurs first.
3. Check framework behavior, permissions, deployment context, and compensating controls.
4. Record the result as confirmed, not exploitable, accepted risk, or needing deeper review.
5. Fix the root cause or add a narrow, reviewable suppression only when justified.

For Python, an inline suppression must be a real comment naming an exact rule ID:

```python
password = load_test_fixture()  # nosec: CREDENTIALS.PASSWORD -- synthetic test fixture
```

Other languages intentionally do not support inline suppressions because regex alone cannot
reliably identify every comment form. v2.2 reports audit suppression behavior; treat suppressions
as governed exceptions, not invisible removals.

JSON exposes redacted accepted items in `suppressions`, and SARIF emits standard `inSource` /
`accepted` suppression metadata. Unknown IDs and directives that match no active finding are
warnings. `--require-suppression-reason` rejects an unreasoned matching directive; use
`--fail-on-suppressed` when policy requires the CI job to fail even for accepted exceptions.

See [Accuracy and assurance](docs/accuracy-and-assurance.md) for the evidence model, known false
positive/negative sources, and benchmark reporting requirements. See the [Threat model](docs/threat-model.md)
for trust boundaries and residual risks.

## Output and exit contract

- Without `--output`, the selected report is written to stdout.
- With `--output`, a new report file is created; an existing path is never overwritten.
- Progress and diagnostics go to stderr, so JSON and SARIF on stdout remain parseable.
- Default credential redaction protects the complete matched source line. Avoid `--no-redact` in
  CI, retained reports, shared terminals, and issue attachments.
- JSON reports carry a top-level `schema_version`; v2.2 consumers can validate against
  [`schemas/vulnscan-2.2.schema.json`](schemas/vulnscan-2.2.schema.json).
- When a read error, containment failure, write failure, or resource limit makes a scan
  incomplete, the result records diagnostics and exits `2` by default.
- Default limits are 10 MiB per file, 100,000 eligible files, 1 GiB total input, and 50,000
  findings. Tune `--max-file-size`, `--max-files`, `--max-total-bytes`, or `--max-findings`;
  setting one to `0` disables that specific limit. JSON and SARIF record completeness and
  truncation, so a partial scan cannot look clean.

| Exit | Meaning |
|---:|---|
| `0` | Scan completed and the configured finding threshold was not reached |
| `1` | Scan completed and `--fail-on` found one or more results at/above the threshold |
| `2` | Usage, input, scan/read, containment, limit, or report-write error; do not treat as clean |

`--fail-on-suppressed` also uses exit `1` when the scan otherwise completes but contains an
accepted suppression.

`--best-effort` is useful for exploratory local triage but intentionally relaxes the strict scan
error exit. Do not use it for an authoritative security gate.

## Trusted CI use

A pull request can weaken `vulnscan.py` if the gate uses the scanner copy from that same pull
request. For a meaningful boundary, pin a reviewed scanner commit in a separate checkout (or a
centrally controlled workflow), grant read-only permissions, and scan the untrusted source without
building, importing, or executing it.

```yaml
name: Source security triage

on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    timeout-minutes: 10
    runs-on: ubuntu-latest
    steps:
      - name: Check out source under review
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          path: source
          persist-credentials: false

      - name: Check out reviewed scanner
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          repository: Zhaoyi-Fan/source-code-security-scanner
          ref: "<FULL_40_CHARACTER_REVIEWED_COMMIT>"
          path: scanner
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.14"

      - name: Scan without executing target code
        run: >-
          python scanner/vulnscan.py -r source --base-dir source
          --format sarif -o vulnscan.sarif --fail-on high
```

Replace the placeholder with an immutable commit you reviewed; do not copy an unknown SHA from
documentation. Protect changes to the consuming workflow and make exit `2` a failed check. SARIF
upload is optional and requires the appropriate platform permission; report portability does not
increase detector accuracy. The [threat model](docs/threat-model.md#ci-trust-boundary) explains
what this does and does not protect.

## Development and verification

```bash
python -m pip install -e ".[dev,color]"
python -m pytest -q
python vulnscan.py --test-patterns
python scripts/evaluate_corpus.py
python -m build
```

For integrations, the module also exposes a side-effect-free scan boundary. `scan()` reads source
but does not print or write reports; the caller owns presentation and persistence:

```python
from vulnscan import ScanConfig, scan

result = scan(ScanConfig(target="src", recursive=True))
for finding in result.findings:
    print(finding.rule_id, finding.file, finding.line)
assert result.stats.complete, "do not treat an incomplete scan as clean"
```

`ScanResult` separates findings, accepted suppressions, diagnostics, and `ScanStats`. The CLI is a
thin adapter over this boundary, while the downloadable single-file workflow remains intact.

The project CI also proves that the standalone scanner starts without third-party dependencies,
then builds a wheel, installs it, and exercises the `vulnscan` console command. Rule changes should
add exact positive and near-miss negative corpus cases. The v2.2 snapshot contains 52 stable rules
and 104 exact-result cases—one positive and one nearby negative for every rule. That is a
regression baseline, not an external accuracy claim; the assurance guide explains the distinction.

Release history and compatibility notes live in [CHANGELOG.md](CHANGELOG.md). Security issues
should follow [SECURITY.md](SECURITY.md).

## Project rationale

I built the original scanner during an authorized application-security source review where broad
text search was useful but too noisy. The project evolved around the engineering boundaries that
matter in a Secure SDLC: stable identifiers, safe retained output, explicit failure semantics,
auditable exceptions, interoperable reports, and measurable regression evidence.

The intended workflow remains deliberately simple:

```text
fast offline triage -> human confirmation -> language-aware tooling or remediation
```

This repository does not aim to become a cloud platform, dependency scanner, DAST engine, or
custom multi-language taint engine.

## Responsible use

Use the scanner only on source code you own or are explicitly authorized to assess. Never paste
real secrets into public reproductions. A match should lead to careful validation, not an
unverified vulnerability claim.

## License

MIT — see [LICENSE](LICENSE).
