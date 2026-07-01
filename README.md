# Source Code Security Scanner

A lightweight, dependency-light Python tool for **secure code review**. It walks a codebase and
flags patterns that commonly indicate vulnerabilities or sensitive information, assigns a
**severity**, cuts secret false-positives with a **Shannon-entropy** check, redacts matched
secrets, and emits **text / JSON / SARIF** so it can plug into a CI/CD pipeline and gate a build.

Built to quickly triage source code obtained during an application-security assessment.

> A fast **first-pass triage** tool (regex-based, single file, no build) — it surfaces candidates
> for a human reviewer to confirm, not a replacement for a full SAST engine.

## Features

- **8 rule categories** with severities — credentials, SQL injection, command injection, insecure
  **deserialization**, **weak crypto**, path traversal, database operations, interesting files.
- **Entropy-based secret detection** — computes the Shannon entropy of each captured secret;
  low-entropy placeholders (`password = "changeme"`) are downgraded to `LOW`, high-entropy values
  are flagged `HIGH`/high-confidence. `--min-entropy` drops weak matches entirely.
- **Secret redaction** — matched secrets are masked in output by default (`--no-redact` to disable).
- **CI-ready output** — `--format json` and `--format sarif` (SARIF 2.1.0 loads straight into GitHub
  code scanning or any SARIF viewer).
- **Build gating** — `--fail-on high|medium|low|info` returns a non-zero exit code when a finding at
  or above that severity exists.
- **Inline suppression** — a `nosec` comment on a line skips its findings (bandit-style).
- **Noise control** — skips binaries and `node_modules`/`vendor`/`.git`/… , `--exclude GLOB` for more,
  de-duplicates per line, precompiled patterns.

## What it detects

| Category | Severity | Flag | Examples |
|---|---|---|---|
| Credentials | HIGH¹ | `-c` | passwords, API keys, tokens, AWS keys (`AKIA…`), JWTs, private keys, creds in JDBC URLs |
| SQL injection | HIGH | `--sqli` | concatenated queries, `Statement` vs `PreparedStatement`, dynamic/format-string SQL |
| Command injection | HIGH | `--cmd` | `exec/system/shell_exec/eval` with variables, `subprocess(shell=True)`, `Runtime.exec` |
| Deserialization | HIGH | `--deser` | `pickle.loads`, `yaml.load` w/o SafeLoader, PHP `unserialize`, Java `ObjectInputStream` |
| Weak crypto | MEDIUM | `--crypto` | MD5 / SHA1, DES, ECB mode, insecure PRNG for security use |
| Path traversal | MEDIUM | `--path` | file open/include built from concatenated input, `../../` |
| Database ops | LOW | `--db` | DB connections, `INTO OUTFILE`/`LOAD_FILE`, MongoDB operators |
| Interesting files | INFO | `--interesting` | config/env/backup refs, debug flags, `phpinfo()`, TODO/FIXME |

¹ Credential severity is entropy-adjusted (placeholders → LOW).

Scans common source/config extensions (Java, PHP, Python, JS/TS, C#, Go, Ruby, shell, XML, `.env`,
`.properties`, `.yml`, `.json`, `.sql`, …) plus always-scanned files like `Dockerfile`,
`web.config`, `pom.xml`, `.htpasswd`.

## Usage

```bash
pip install colorama          # optional (coloured output); the tool runs fine without it

# scan
python vulnscan.py -r ./target-source/                 # recursive, all categories
python vulnscan.py -r --sqli --cmd ./target-source/    # only injection sinks
python vulnscan.py -r -c --min-entropy 3.0 ./src/      # only strong hardcoded secrets
python vulnscan.py -f path/to/File.java                # single file

# CI / reporting
python vulnscan.py -r ./src/ --format sarif -o out.sarif   # SARIF for code scanning
python vulnscan.py -r ./src/ --format json  -o out.json    # machine-readable
python vulnscan.py -r ./src/ --fail-on high                # exit 1 if any HIGH → fails the build

# info
python vulnscan.py --show-categories
python vulnscan.py --test-patterns
```

Suppress a line with a `nosec` comment; exclude paths with `--exclude '*/tests/*' --exclude '*.min.js'`.

### Example: use it as a CI gate (GitLab)

```yaml
sast_triage:
  script:
    - python vulnscan.py -r . --format sarif -o gl-sast.sarif --fail-on high
  artifacts:
    paths: [gl-sast.sarif]
```

## Why I built it

During an application-security engagement I obtained a target server's source code and needed to
sift it quickly for credentials and injectable sinks. Generic `grep` was too noisy, so I built a
category-based scanner I could point at any codebase and reuse — then grew it toward how real
secure-code-review fits a pipeline: severity, entropy-based secret triage, and SARIF/exit-code
output for CI. It reflects how I approach code review: a fast pattern-driven first pass, then manual
confirmation of the interesting hits.

## License

MIT — see [LICENSE](LICENSE). For authorized security assessments and your own code only.
