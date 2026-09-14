# Threat model

## Scope and security objective

The scanner reads a caller-selected source tree and emits review findings. Its security objective
is to analyse untrusted file content without executing it, stay within the requested scan root,
avoid disclosing candidate secrets by default, and fail visibly when an authoritative result is
incomplete.

```text
untrusted source tree  ->  scanner process  ->  text / JSON / SARIF report
       filesystem              config                terminal, CI, artifact store
```

The source tree, filenames, links/reparse points, file contents, configuration flags, and report
destination are trust-boundary inputs. CI workflow definitions and the scanner executable are a
separate supply-chain boundary.

## Assets

- secrets or sensitive source text encountered during scanning;
- integrity and completeness of findings, diagnostics, and CI exit status;
- containment of file reads within the authorized root;
- integrity of pre-existing files near the output destination;
- reviewer trust in rule IDs, locations, suppressions, and report provenance.

## Principal threats and controls

| Threat | Current control | Residual risk |
|---|---|---|
| A credential appears in logs or artifacts | Credential source lines are redacted centrally by default | Novel secret formats and `--no-redact` can expose data |
| A link or junction escapes the scan root | Linked/reparse-point paths are skipped and containment failures are diagnostics | Filesystem races and platform-specific path behavior need continued regression testing |
| An unreadable or malformed file produces a false clean result | Scan/read failures are errors and default to exit `2` | `--best-effort`, excludes, size limits, and unsupported encodings deliberately reduce coverage |
| An output overwrites source or an existing report | Output is no-clobber, checked against scanned input, and written atomically | Caller-controlled surrounding directories remain outside the scanner's protection |
| Crafted text suppresses unrelated findings | Python suppressions require a tokenizer-confirmed comment and explicit rule ID; accepted items remain visible in JSON/SARIF | The justification's truth and exception lifecycle remain human/governance controls |
| Machine output is corrupted by progress text | Reports use stdout or the output file; diagnostics use stderr | Wrappers can still merge streams or mishandle exit codes |
| A pull request weakens or replaces the scanner used to gate itself | CI consumers can pin a separately controlled scanner commit and restrict workflow changes | A workflow controlled by the same untrusted change is not an independent security boundary |
| Regex matches are treated as proven vulnerabilities or proof of safety | Documentation separates match, severity, confidence, and confirmation | Human or downstream automation may still over-interpret results |
| Very large trees cause excessive resource use | Per-file and v2.2 aggregate limits bound work and report incompleteness | Limits trade availability for coverage and do not make hostile scanning risk-free |

## CI trust boundary

Scanning a pull request with the copy of `vulnscan.py` from that same pull request allows the
change under review to alter the gate. For a stronger boundary, run a reviewed scanner commit from
a separate checkout or centrally controlled workflow, use read-only permissions, do not execute
the target project, and treat exit `2` or a resource-limit stop as incomplete rather than clean.
See the [CI example](../README.md#trusted-ci-use).

Action tags and package versions are supply-chain inputs too. The repository's own CI pins actions
to reviewed full commit SHAs. Downstream users should pin the scanner to an immutable release
commit or verified artifact checksum and review upgrades deliberately.

## Out of scope

- proving exploitability, complete vulnerability discovery, or multi-language taint flow;
- executing, building, importing, or testing target source;
- malware sandboxing or safely processing arbitrary hostile files at unlimited scale;
- dependency, container, IaC, DAST, or runtime analysis;
- authorization to scan a third party's code.

## Security verification priorities

Changes to path handling, decoding, redaction, suppressions, report writing, limits, schema, and
exit precedence require regression tests. Rule changes require positive and negative corpus cases.
Release review should also inspect dependency metadata, action pins, built artifacts, and the
documented JSON/SARIF compatibility contract.
