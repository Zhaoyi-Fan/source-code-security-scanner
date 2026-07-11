# Source Code Security Scanner v2.1

A lightweight, dependency-light Python tool for **secure-code-review triage**. It walks a
codebase, flags source patterns that may indicate vulnerabilities or embedded credentials, and
emits text, JSON, or SARIF for a reviewer or CI pipeline.

The scanner is deliberately **regex-led** and remains a single Python file with no required
runtime dependency. Two Python rules use the standard-library AST for syntax-sensitive checks. It
is a fast first pass for authorized review, not a replacement for a SAST engine, general language
parser, taint analysis, or human confirmation.

## What changed in v2.1

v2.1 is a correctness and safe-output release. It focuses on making the existing narrow scanner
trustworthy before adding more rule categories:

- **Centralized secret sanitization:** every renderer receives sanitized finding fields. When a
  credential candidate occurs, default text, JSON, and SARIF output protect that entire source line
  so adjacent literals and language-specific escapes cannot leak a suffix. This also protects
  non-credential findings on the same line. `--no-redact` is an explicit unsafe override.
- **Stable rule IDs and exact findings:** each conceptual rule has a stable rule ID. Findings are
  de-duplicated by rule ID and match span, so one match cannot hide a second finding on the same
  line. The same IDs appear in reports and scoped suppressions.
- **Severity is separate from confidence:** a rule's severity describes potential impact. Secret
  entropy can change detection confidence or filter a hit through `--min-entropy`, but it does not
  downgrade severity and accidentally bypass a severity gate.
- **Strict scan failures:** an unreadable target, traversal/read failure, or report-write failure is
  a scan error (exit `2`), never a clean scan. Recursive scans stay within the requested root.
- **Scoped Python suppressions:** `nosec` is recognized only where Python's tokenizer confirms a
  real comment, and it must name a rule ID, for example
  `# nosec: CREDENTIALS.PASSWORD`. Other languages fail closed and do not enable inline
  suppressions in v2.1. A bare `nosec`, text such as `nosecurity`, or a secret containing `NOSEC`
  cannot suppress a finding.
- **Configuration-file coverage:** standard `.env` files, unquoted dotenv assignments, and common
  quoted-key JSON credentials are included in credential triage.
- **Stable report locations:** recursive results and SARIF artifact URIs use forward-slash,
  repository-relative paths instead of host-specific absolute paths.
- **Clean output streams:** the selected report is written only to stdout or `--output`; progress,
  diagnostics, and write confirmations go to stderr. `--verbose` therefore cannot corrupt JSON or
  SARIF on stdout.
- **Regression CI:** pytest fixtures and the built-in pattern self-test run on Linux and Windows
  across the supported Python matrix in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## What it detects

| Category | Severity | Flag | Examples |
|---|---:|---|---|
| Credentials | HIGH | `-c` | passwords, API keys, tokens, AWS keys, JWTs, private-key headers, JDBC credentials |
| SQL injection | HIGH | `--sqli` | concatenated or formatted SQL and unsafe statement construction |
| Command injection | HIGH | `--cmd` | command/evaluation sinks with variable input, `shell=True`, `Runtime.exec` |
| Deserialization | HIGH | `--deser` | pickle, unsafe YAML load, PHP `unserialize`, Java/Ruby object loading |
| Weak crypto | MEDIUM | `--crypto` | MD5, SHA-1, DES, ECB mode, non-cryptographic PRNG use |
| Path traversal | MEDIUM | `--path` | dynamically constructed file paths, dynamic include/read, traversal sequences |
| Database operations | LOW | `--db` | database connections, file read/write SQL, MongoDB operators |
| Interesting files | INFO | `--interesting` | configuration/backup references, debug flags, development markers |

Rule IDs are part of the v2.1 output contract. Examples include
`CREDENTIALS.PASSWORD`, `CREDENTIALS.API_KEY`, `CREDENTIALS.JWT`, `SQL.FORMAT`,
`CMD.SUBPROCESS_SHELL`, and `DESER.YAML_LOAD`.

The scanner covers common source and configuration extensions (Python, Java, PHP, JavaScript,
TypeScript, C#, Go, Ruby, shell, XML, YAML, JSON, SQL, `.env`, `.properties`, and others) plus
well-known files such as `Dockerfile`, `web.config`, and `pom.xml`.

## Usage

Download `vulnscan.py` and run it directly with Python. `colorama` is optional and only provides
coloured terminal output.

```bash
# Optional colour support
python -m pip install -r requirements.txt

# Recursive scan, all categories
python vulnscan.py -r ./target-source/

# Selected categories
python vulnscan.py -r --sqli --cmd ./target-source/
python vulnscan.py -r -c --min-entropy 3.0 ./src/

# Single file
python vulnscan.py -f path/to/File.java

# Machine-readable reports and a CI gate
python vulnscan.py -r ./src/ --format sarif -o out.sarif
python vulnscan.py -r ./src/ --format json -o out.json
python vulnscan.py -r ./src/ --fail-on high

# Rule information and a lightweight built-in self-test
python vulnscan.py --show-categories
python vulnscan.py --test-patterns
```

`--min-entropy` filters credential candidates below the chosen entropy value. It is a noise-control
option, not a change to rule severity. Avoid `--no-redact` in CI or any report that may be retained
or shared.

### Rule-scoped Python suppression

A suppression must be in a Python comment and list the stable ID of the rule being suppressed:

```python
password = get_test_fixture()  # nosec: CREDENTIALS.PASSWORD
```

Use the actual ID shown by a finding or `--show-categories`. A suppression applies only to the
named rule on that line; it does not hide unrelated findings. Suppressions should carry a reviewable
reason in the surrounding code or change record. v2.1 deliberately disables inline suppression
for other languages because a regex cannot reliably distinguish comments from constructs such as
JavaScript regex literals.

## Output and exit-code contract

- Without `--output`, the selected text/JSON/SARIF report goes to stdout.
- With `--output`, that same format is written to a new named file. Existing paths are never
  overwritten; choose a fresh path or remove an obsolete report explicitly.
- Progress and diagnostics go to stderr, including in `--verbose` mode.
- Completed JSON and SARIF reports remain machine-parseable, including in `--verbose` mode.
- A JSON report from a partial scan records `summary.scan_errors` and structured top-level
  `diagnostics` while the process exits `2`.

| Exit | Meaning |
|---:|---|
| `0` | Scan completed and no configured gate threshold was reached |
| `1` | Scan completed, and `--fail-on` found at least one result at or above the threshold |
| `2` | Usage, target, scan/read, containment, or report-write error; results are incomplete |

Exit `2` takes precedence over a finding gate so CI cannot treat a partial scan as authoritative.
`--best-effort` deliberately relaxes that strict default: scan diagnostics are still reported, but
operational scan errors no longer force exit `2`. Use it only for exploratory local triage, never
for an authoritative CI result or security gate.

## CI examples

### GitHub Actions with optional SARIF upload

This example preserves the scanner's pass/fail outcome while giving the upload step a chance to
run. The SARIF upload requires GitHub code scanning to be available for the repository and the
workflow to have the shown permission; producing SARIF does not turn this regex triage tool into a
full SAST engine.

```yaml
name: Security triage

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.14"

      - name: Run source triage
        id: scanner
        continue-on-error: true
        run: python vulnscan.py -r . --format sarif -o vulnscan.sarif --fail-on high

      - name: Upload SARIF when a report exists
        if: always() && hashFiles('vulnscan.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: vulnscan.sarif

      - name: Enforce scanner result
        if: steps.scanner.outcome == 'failure'
        run: exit 1
```

### GitLab CI with report retention on failure

`artifacts: when: always` keeps the SARIF file when `--fail-on` returns `1`. GitLab versions that
support a native SARIF report declaration can add it alongside the portable artifact path.

```yaml
sast_triage:
  image: python:3.14-slim
  script:
    - python vulnscan.py -r . --format sarif -o vulnscan.sarif --fail-on high
  artifacts:
    when: always
    paths:
      - vulnscan.sarif
```

## Development

The production scanner remains a directly runnable single file. Development dependencies are kept
separate:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
python vulnscan.py --test-patterns
```

The repository CI runs both checks on Ubuntu and Windows with Python 3.10 and 3.14.

## Known limitations

- Most rules inspect text patterns. Limited standard-library Python tokenization/AST checks protect
  suppressions and validate `shell=True`/safe YAML-loader syntax; a token fallback keeps these two
  rules consistent when the target uses newer Python syntax. There is no general multi-language
  parser, value flow, reachability, or sanitizer/parameterization model.
- A match is a review candidate, not proof of exploitability. False positives and false negatives
  are expected, and rule severity is a triage priority rather than a CVSS score.
- Minified/generated files, uncommon encodings, novel secret formats, and code outside supported
  file types may need separate review or explicit tooling.
- SARIF provides interoperable locations and metadata, but accuracy still depends on the underlying
  regex rule and human validation.
- This project intentionally does not include a dashboard, cloud service, custom AST/taint engine,
  IDE extension, or unrelated SCA/DAST/container/IaC features. Its scope is auditable source-review
  triage.

## Why I built it

During an **authorized source-code review** in an application-security assessment, I needed a fast
way to triage a codebase for embedded credentials and potentially injectable sinks. Generic `grep`
was too noisy, so I built a category-based scanner and then adapted it to a Secure SDLC workflow:
stable rule IDs, safe reports, CI exit codes, scoped suppressions, and SARIF for review systems.

The intended workflow remains pattern-driven triage followed by manual confirmation and the
language-aware security tools appropriate to the application.

## Responsible use

Use this scanner only for source code and systems you own or are explicitly authorized to assess.
Keep default redaction enabled for retained or shared reports, and treat every result as a review
candidate requiring human validation.

## License

MIT — see [LICENSE](LICENSE).
