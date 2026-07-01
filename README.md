# Source Code Security Scanner

A lightweight, dependency-light Python tool for **secure code review**: it walks a codebase and
flags patterns that commonly indicate vulnerabilities or sensitive information — hardcoded
credentials, SQL/command-injection sinks, path traversal, insecure database usage, and other
interesting artifacts. Built to quickly triage source code obtained during application security
assessments.

> It's a fast **first-pass triage** tool (regex-based, single-file, no build), not a replacement for
> a full SAST engine — it surfaces candidates for a human reviewer to confirm.

## What it detects

| Category | Flag | Examples |
|---|---|---|
| Credentials | `-c` | hardcoded passwords, API keys, tokens, AWS keys, private keys, connection strings |
| SQL injection | `--sqli` | string-concatenated queries, `Statement` vs `PreparedStatement`, dynamic SQL, format-string SQL |
| Command injection | `--cmd` | `exec`/`system`/`shell_exec`/`eval` with variables, `subprocess(..., shell=True)`, `Runtime.exec` |
| Path traversal | `--path` | `../` patterns, file open/include with concatenated user input |
| Interesting files | `--interesting` | config/env/backup references, debug flags, admin paths, `phpinfo()`, (de)serialization |
| Database operations | `--db` | DB connections, credentials in URLs, `INTO OUTFILE`/`LOAD_FILE`, NoSQL operators |

Scans common source/config extensions (Java, PHP, Python, JS, C#, Ruby, shell, XML, `.env`,
`.properties`, `.yml`, `.json`, `.sql`, …) plus always-scanned files like `Dockerfile`,
`web.config`, `pom.xml`, `.htpasswd`.

## Usage

```bash
pip install colorama                      # optional (colored output); runs without it

python vulnscan.py -r ./target-source/               # recursive scan, all categories
python vulnscan.py -r --sqli --cmd ./target-source/  # only injection sinks
python vulnscan.py -r -c ./target-source/            # only hardcoded credentials
python vulnscan.py -f path/to/File.java              # single file
python vulnscan.py --show-categories                 # list categories + example patterns
python vulnscan.py --test-patterns                   # self-test the regex patterns
```

Each finding reports the file, line number, matched text, and surrounding context, grouped and
colour-coded by category, with a summary at the end.

## Why I built it

During an application security engagement I obtained a target server's source code and needed to
sift it quickly for credentials and injectable sinks. Generic `grep` was noisy, so I built a small,
category-based scanner I could point at any codebase and re-use. It reflects how I approach secure
code review: pattern-driven first pass, then manual confirmation of the interesting hits.

## License

MIT — see [LICENSE](LICENSE). For use in authorized security assessments and your own code only.
