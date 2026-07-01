#!/usr/bin/env python3
"""
Source Code Security Scanner
============================
A lightweight, dependency-light static triage tool for secure code review. It walks a codebase
and flags patterns that commonly indicate vulnerabilities or sensitive information (hardcoded
credentials, injection sinks, weak crypto, insecure deserialization, path traversal, ...),
assigns a severity, reduces secret false-positives with a Shannon-entropy check, and can emit
text / JSON / SARIF and gate a CI pipeline via its exit code.

It is a fast first-pass triage tool, not a full SAST engine: it surfaces candidates for a human
reviewer to confirm. Use only against code you are authorized to review.
"""

import os
import re
import sys
import json
import math
import fnmatch
import argparse
from dataclasses import dataclass, asdict, field

TOOL_NAME = "source-code-security-scanner"
TOOL_VERSION = "2.0"
TOOL_URI = "https://github.com/Zhaoyi-Fan/source-code-security-scanner"

# --- optional colour ---------------------------------------------------------
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

    class Style:
        BRIGHT = RESET_ALL = ""


# --- severity model ----------------------------------------------------------
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
SEVERITY_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.MAGENTA,
    "LOW": Fore.YELLOW,
    "INFO": Fore.CYAN,
}
# SARIF uses: error / warning / note / none
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


@dataclass
class Finding:
    category: str
    severity: str
    description: str
    file: str
    line: int
    match: str
    context: str
    confidence: str = "medium"
    entropy: float = field(default=0.0)

    def sort_key(self):
        return (-SEVERITY_ORDER[self.severity], self.file, self.line)


# --- rule set ----------------------------------------------------------------
# Each category: severity + list of (regex, description). `secret` marks categories whose last
# capture group is a secret value we entropy-check and redact.
RULES = {
    "credentials": {
        "severity": "HIGH",
        "secret": True,
        "patterns": [
            (r'password\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'passwd\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'pwd\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'\.put\s*\(\s*["\'](?:password|pass|pwd)["\']\s*,\s*["\']([^"\']+)["\']',
             "Hardcoded password in method call"),
            (r'setPassword\s*\(\s*["\']([^"\']+)["\']', "Hardcoded password in setter"),
            (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "API key"),
            (r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', "Access token"),
            (r'auth[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', "Auth token"),
            (r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "Secret key"),
            (r'(?:db[_-]?pass|database[_-]?password)\s*[=:]\s*["\']([^"\']+)["\']', "Database password"),
            (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']([^"\']+)["\']', "AWS access key id"),
            (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "AWS secret key"),
            (r'(AKIA[0-9A-Z]{16})', "AWS access key (by format)"),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}', "Hardcoded JWT"),
            (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "Private key"),
            (r'jdbc:[a-zA-Z0-9]+://[^"\'\s]*:([^@"\'\s]+)@', "Credentials in JDBC URL"),
        ],
    },
    "sql_injection": {
        "severity": "HIGH",
        "patterns": [
            (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"\']*[\'"]\s*\+\s*\w+', "SQL built by concatenation"),
            (r'(?:query|sql)\s*[=:]\s*["\'][^"\']*[\'"]\s*\+', "SQL string concatenation"),
            (r'WHERE\s+\w+\s*=\s*[\'"][\'"]?\s*\+', "WHERE clause concatenation"),
            (r'createStatement\(\)', "Statement (vs PreparedStatement)"),
            (r'execute(?:Query|Update)?\s*\(\s*["\'][^"\']*[\'"]\s*\+', "Dynamic SQL execution"),
            (r'(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*%[sd]', "SQL built with string formatting"),
            (r'\.format\([^)]*\)[^;]*(?:SELECT|INSERT|UPDATE|DELETE)', "SQL built with .format()"),
        ],
    },
    "command_injection": {
        "severity": "HIGH",
        "patterns": [
            (r'(?:exec|system|shell_exec|passthru|popen)\s*\([^)]*\$', "Command execution with variable"),
            (r'eval\s*\([^)]*\$', "eval() with variable"),
            (r'Runtime\.getRuntime\(\)\.exec', "Java Runtime.exec"),
            (r'subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True', "subprocess shell=True"),
            (r'os\.system\s*\(', "os.system() call"),
        ],
    },
    "deserialization": {
        "severity": "HIGH",
        "patterns": [
            (r'pickle\.loads?\s*\(', "Python pickle deserialization"),
            (r'yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)', "yaml.load without SafeLoader"),
            (r'\bunserialize\s*\(', "PHP unserialize()"),
            (r'ObjectInputStream', "Java ObjectInputStream"),
            (r'Marshal\.load', "Ruby Marshal.load"),
        ],
    },
    "weak_crypto": {
        "severity": "MEDIUM",
        "patterns": [
            (r'\bMD5\b', "Weak hash: MD5"),
            (r'\bSHA-?1\b', "Weak hash: SHA1"),
            (r'\bDES(?:ede)?\b|"DES/', "Weak cipher: DES"),
            (r'AES/ECB|"ECB"|/ECB/', "Insecure cipher mode: ECB"),
            (r'Math\.random\(|random\.random\(', "Insecure PRNG for security use"),
        ],
    },
    "path_traversal": {
        "severity": "MEDIUM",
        "patterns": [
            (r'new\s+File\s*\([^)]*\+', "File path built by concatenation"),
            (r'open\s*\([^)]*\+\s*\w+', "File open with concatenation"),
            (r'(?:include|require)\s*\([^)]*\$', "Dynamic file inclusion"),
            (r'file_get_contents\s*\([^)]*\$', "Dynamic file read"),
            (r'\.\./\.\./', "Path traversal sequence"),
        ],
    },
    "database_operations": {
        "severity": "LOW",
        "patterns": [
            (r'(?:mysqli?_connect|pg_connect|new\s+PDO\s*\(|DriverManager\.getConnection)', "DB connection"),
            (r'INTO\s+OUTFILE', "MySQL INTO OUTFILE (file write)"),
            (r'LOAD_FILE\s*\(', "MySQL LOAD_FILE (file read)"),
            (r'\$where|\$ne|\$gt|\$regex', "MongoDB operator (NoSQLi surface)"),
        ],
    },
    "interesting_files": {
        "severity": "INFO",
        "patterns": [
            (r'(?:config\.(?:php|py|js)|\.env|web\.config|app\.config)', "Config file reference"),
            (r'\.(?:bak|backup|old|orig)\b', "Backup file reference"),
            (r'(?:DEBUG|debug)\s*=\s*[Tt]rue', "Debug mode enabled"),
            (r'\b(?:TODO|FIXME|HACK|XXX)\b', "Development marker"),
            (r'phpinfo\(\)', "phpinfo() call"),
        ],
    },
}

SCAN_EXTENSIONS = {
    ".java", ".php", ".py", ".js", ".ts", ".jsp", ".asp", ".aspx", ".c", ".cpp", ".cs", ".go",
    ".rb", ".pl", ".sh", ".bat", ".ps1", ".xml", ".conf", ".config", ".properties", ".ini",
    ".env", ".yml", ".yaml", ".json", ".sql",
}
ALWAYS_SCAN = {"Dockerfile", "docker-compose.yml", "Makefile", ".htaccess", ".htpasswd",
               "web.config", "build.gradle", "pom.xml"}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}


# --- helpers -----------------------------------------------------------------
def shannon_entropy(s):
    """Bits-per-char Shannon entropy; high for real secrets, low for words/placeholders."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(secret):
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"


# --- scanner -----------------------------------------------------------------
class Scanner:
    def __init__(self, categories=None, min_entropy=0.0, redact_secrets=True):
        self.categories = categories
        self.min_entropy = min_entropy
        self.redact_secrets = redact_secrets
        # precompile
        self.compiled = {}
        for cat, cfg in RULES.items():
            self.compiled[cat] = [
                (re.compile(rx, re.IGNORECASE), desc) for rx, desc in cfg["patterns"]
            ]

    def should_scan(self, path):
        name = os.path.basename(path)
        if name in ALWAYS_SCAN:
            return True
        return os.path.splitext(path)[1].lower() in SCAN_EXTENSIONS

    @staticmethod
    def _is_binary(path):
        try:
            with open(path, "rb") as f:
                return b"\x00" in f.read(2048)
        except OSError:
            return True

    def scan_file(self, path, display_path=None):
        display_path = display_path or path
        findings = []
        if self._is_binary(path):
            return findings
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return findings

        lines = content.splitlines()
        seen = set()  # (line, category) de-dupe

        for cat, patterns in self.compiled.items():
            if self.categories and cat not in self.categories:
                continue
            cfg = RULES[cat]
            base_sev = cfg["severity"]
            is_secret = cfg.get("secret", False)

            for regex, desc in patterns:
                for m in regex.finditer(content):
                    line_no = content.count("\n", 0, m.start()) + 1
                    key = (line_no, cat)
                    if key in seen:
                        continue
                    line_txt = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                    # inline suppression (bandit-style)
                    if "nosec" in line_txt.lower():
                        continue

                    severity = base_sev
                    confidence = "medium"
                    entropy = 0.0
                    shown_match = m.group(0)

                    if is_secret and m.lastindex:
                        secret = m.group(m.lastindex)
                        entropy = round(shannon_entropy(secret), 2)
                        # low-entropy value = likely a placeholder → downgrade / filter
                        if entropy < self.min_entropy:
                            continue
                        if entropy < 3.0:
                            severity, confidence = "LOW", "low"  # likely a placeholder
                        elif entropy >= 3.5:
                            confidence = "high"
                        if self.redact_secrets:
                            shown_match = shown_match.replace(secret, redact(secret))
                            line_txt = line_txt.replace(secret, redact(secret))

                    seen.add(key)
                    findings.append(Finding(
                        category=cat, severity=severity, description=desc,
                        file=display_path, line=line_no,
                        match=shown_match[:160], context=line_txt[:160],
                        confidence=confidence, entropy=entropy,
                    ))
        return findings

    def scan_path(self, target, recursive=False, excludes=None, verbose=False):
        excludes = excludes or []
        findings = []

        def excluded(p):
            return any(fnmatch.fnmatch(p, pat) or pat in p for pat in excludes)

        if os.path.isfile(target):
            if self.should_scan(target) and not excluded(target):
                findings += self.scan_file(target)
            return findings

        root_parent = os.path.dirname(os.path.abspath(target)) or "."
        walker = os.walk(target) if recursive else [(target, [], os.listdir(target))]
        for root, dirs, files in walker:
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not excluded(os.path.join(root, d))]
            for fn in files:
                fp = os.path.join(root, fn)
                if not os.path.isfile(fp) or not self.should_scan(fp) or excluded(fp):
                    continue
                rel = os.path.relpath(fp, root_parent).replace(os.sep, "/")
                if verbose:
                    _p(f"{Fore.BLUE}scanning: {rel}")
                findings += self.scan_file(fp, display_path=rel)
        return findings


# --- output ------------------------------------------------------------------
def _p(msg):
    print(msg if _COLOR else re.sub(r"\x1b\[[0-9;]*m", "", msg))


def render_text(findings):
    if not findings:
        _p(f"{Fore.GREEN}{Style.BRIGHT}No findings.")
        return
    findings = sorted(findings, key=lambda f: f.sort_key())
    current = None
    for f in findings:
        if f.file != current:
            current = f.file
            _p(f"\n{Fore.WHITE}{Style.BRIGHT}{'=' * 78}")
            _p(f"{Fore.WHITE}{Style.BRIGHT}{f.file}")
            _p(f"{Fore.WHITE}{Style.BRIGHT}{'=' * 78}")
        color = SEVERITY_COLOR[f.severity]
        tag = f"[{f.severity}]".ljust(9)
        extra = f" (entropy {f.entropy}, {f.confidence})" if f.category == "credentials" else ""
        _p(f"{color}{tag} L{f.line}: {f.description}{extra}")
        _p(f"{color}          {f.context}")


def print_summary(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    _p(f"\n{Fore.WHITE}{Style.BRIGHT}{'=' * 78}")
    _p(f"{Fore.WHITE}{Style.BRIGHT}SUMMARY: {len(findings)} finding(s)  "
       f"| HIGH {counts['HIGH']}  MEDIUM {counts['MEDIUM']}  LOW {counts['LOW']}  INFO {counts['INFO']}")


def to_json(findings):
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    return json.dumps({
        "tool": TOOL_NAME, "version": TOOL_VERSION,
        "summary": {"total": len(findings), **counts},
        "findings": [asdict(f) for f in findings],
    }, indent=2)


def to_sarif(findings):
    cats = sorted({f.category for f in findings})
    rules = [{
        "id": c, "name": c,
        "shortDescription": {"text": c.replace("_", " ").title()},
        "defaultConfiguration": {"level": SARIF_LEVEL[RULES[c]["severity"]]},
    } for c in cats]
    results = [{
        "ruleId": f.category,
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.description}: {f.context}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": f.line},
        }}],
    } for f in findings]
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME, "version": TOOL_VERSION,
                "informationUri": TOOL_URI, "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


# --- meta commands -----------------------------------------------------------
def show_categories():
    flags = {
        "credentials": "-c/--credentials", "sql_injection": "--sqli",
        "command_injection": "--cmd", "deserialization": "--deser",
        "weak_crypto": "--crypto", "path_traversal": "--path",
        "database_operations": "--db", "interesting_files": "--interesting",
    }
    _p(f"{Fore.CYAN}{Style.BRIGHT}Categories (severity) — filter flag:")
    for cat, cfg in RULES.items():
        _p(f"{SEVERITY_COLOR[cfg['severity']]}  [{cfg['severity']:<6}] {cat:<20} {flags.get(cat, '')}")
        for rx, desc in cfg["patterns"][:2]:
            _p(f"           - {desc}")


def test_patterns():
    scanner = Scanner()
    samples = [
        'String q = "SELECT x FROM t WHERE id=\'"+id+"\'";',
        'connectionProps.put("password", "S3cr3t!Rand0mValue#42");',
        'password = "changeme"',                       # low entropy -> LOW
        'api_key = "sk-a1b2c3d4e5f6g7h8i9j0"',
        'os.system("ping " + host)',
        'pickle.loads(data)',
        'MessageDigest.getInstance("MD5")',
        'password = "changeme"  # nosec',              # suppressed
    ]
    _p(f"{Fore.CYAN}{Style.BRIGHT}Pattern self-test:")
    import tempfile
    for s in samples:
        with tempfile.NamedTemporaryFile("w", suffix=".java", delete=False) as tf:
            tf.write(s)
            name = tf.name
        fs = scanner.scan_file(name, display_path="<sample>")
        os.unlink(name)
        verdict = ", ".join(f"[{f.severity}] {f.description}" for f in fs) or "no match"
        _p(f"{Fore.WHITE}  {s}\n      -> {verdict}")


# --- cli ---------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="vulnscan.py",
        description="Source code security scanner — secure code review triage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnscan.py -r ./target-source/                 recursive scan, all categories
  vulnscan.py -r --sqli --cmd ./target-source/    only injection sinks
  vulnscan.py -r -c --min-entropy 3.0 ./src/      only high-entropy hardcoded secrets
  vulnscan.py -r ./src/ --format sarif -o out.sarif   SARIF report for CI / code scanning
  vulnscan.py -r ./src/ --fail-on high            exit non-zero if any HIGH finding (CI gate)
  vulnscan.py -f File.java                          scan a single file
  vulnscan.py --show-categories | --test-patterns
""")
    p.add_argument("target", nargs="?", help="file or directory to scan")
    p.add_argument("-r", "--recursive", action="store_true", help="recurse into subdirectories")
    p.add_argument("-f", "--file", action="store_true", help="(compat) treat target as a single file")
    p.add_argument("-v", "--verbose", action="store_true", help="print files as they are scanned")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="output format")
    p.add_argument("-o", "--output", help="write report to a file instead of stdout")
    p.add_argument("--fail-on", choices=["info", "low", "medium", "high"],
                   help="exit code 1 if a finding at/above this severity exists (CI gate)")
    p.add_argument("--min-entropy", type=float, default=0.0,
                   help="drop hardcoded-secret hits whose value entropy is below this (reduces false positives)")
    p.add_argument("--no-redact", action="store_true", help="do not mask matched secret values")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="path glob to skip (repeatable)")
    p.add_argument("--show-categories", action="store_true", help="list categories and exit")
    p.add_argument("--test-patterns", action="store_true", help="run the pattern self-test and exit")

    g = p.add_argument_group("category filters (default: all)")
    g.add_argument("-c", "--credentials", action="store_true")
    g.add_argument("--sqli", action="store_true")
    g.add_argument("--cmd", action="store_true")
    g.add_argument("--deser", action="store_true")
    g.add_argument("--crypto", action="store_true")
    g.add_argument("--path", action="store_true")
    g.add_argument("--db", action="store_true")
    g.add_argument("--interesting", action="store_true")
    return p


def selected_categories(args):
    mapping = {
        "credentials": args.credentials, "sql_injection": args.sqli,
        "command_injection": args.cmd, "deserialization": args.deser,
        "weak_crypto": args.crypto, "path_traversal": args.path,
        "database_operations": args.db, "interesting_files": args.interesting,
    }
    chosen = [c for c, on in mapping.items() if on]
    return chosen or None


def main():
    args = build_parser().parse_args()

    if args.show_categories:
        show_categories()
        return 0
    if args.test_patterns:
        test_patterns()
        return 0
    if not args.target:
        build_parser().error("a target file or directory is required")
    if not os.path.exists(args.target):
        _p(f"{Fore.RED}error: '{args.target}' does not exist")
        return 2

    scanner = Scanner(
        categories=selected_categories(args),
        min_entropy=args.min_entropy,
        redact_secrets=not args.no_redact,
    )
    findings = scanner.scan_path(args.target, recursive=args.recursive,
                                 excludes=args.exclude, verbose=args.verbose)

    if args.format == "json":
        report = to_json(findings)
    elif args.format == "sarif":
        report = to_sarif(findings)
    else:
        report = None

    if report is not None:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            _p(f"{Fore.GREEN}wrote {len(findings)} finding(s) to {args.output}")
        else:
            print(report)
    else:
        render_text(findings)
        print_summary(findings)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(to_json(findings))
            _p(f"{Fore.GREEN}JSON report written to {args.output}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
