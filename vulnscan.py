#!/usr/bin/env python3
"""Source Code Security Scanner v2.2.0.

A dependency-light, regex-led triage tool for authorized secure code review.
It uses limited standard-library Python syntax checks, but is not a full SAST
engine and does not perform general parsing, taint tracking, or sanitizer analysis.
"""

import argparse
import ast
import bisect
import codecs
import fnmatch
import io
import json
import math
import os
import re
import stat
import sys
import tempfile
import tokenize
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote


TOOL_NAME = "source-code-security-scanner"
TOOL_VERSION = "2.2.0"
TOOL_URI = "https://github.com/Zhaoyi-Fan/source-code-security-scanner"
REPORT_SCHEMA_VERSION = "2.2"
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 50_000


# --- optional colour ---------------------------------------------------------
try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    _COLOR_AVAILABLE = True
except ImportError:
    _COLOR_AVAILABLE = False

    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

    class Style:
        BRIGHT = RESET_ALL = ""


# --- models ------------------------------------------------------------------
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SARIF_SECURITY_SEVERITY = {"HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "1.0"}
SEVERITY_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.MAGENTA,
    "LOW": Fore.YELLOW,
    "INFO": Fore.CYAN,
}


@dataclass(frozen=True)
class PatternSpec:
    pattern: str
    secret_group: Optional[str] = None
    kinds: Tuple[str, ...] = ()

    def applies_to(self, kind: str) -> bool:
        return not self.kinds or kind in self.kinds


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    description: str
    cwe: Optional[int]
    patterns: Tuple[PatternSpec, ...]
    confidence: str = "medium"


@dataclass(frozen=True)
class CompiledPattern:
    rule: Rule
    spec: PatternSpec
    regex: re.Pattern


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    file: str
    line: int
    column: int
    end_line: int
    end_column: int
    match: str
    context: str
    confidence: str = "medium"
    entropy: float = 0.0
    cwe: Optional[int] = None

    def sort_key(self):
        return (-SEVERITY_ORDER[self.severity], self.file, self.line, self.column, self.rule_id)


@dataclass
class Diagnostic:
    level: str
    message: str
    file: str = ""


@dataclass
class SuppressedFinding(Finding):
    """A redacted finding accepted by an in-source suppression."""

    justification: str = ""


@dataclass(frozen=True)
class ScanConfig:
    """Pure scan inputs for library users; rendering and file output stay in the CLI."""

    target: str
    recursive: bool = False
    force_file: bool = False
    categories: Optional[Tuple[str, ...]] = None
    excludes: Tuple[str, ...] = ()
    includes: Tuple[str, ...] = ()
    base_dir: Optional[str] = None
    min_entropy: float = 0.0
    min_confidence: str = "low"
    redact_secrets: bool = True
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_findings: int = DEFAULT_MAX_FINDINGS
    require_suppression_reason: bool = False


@dataclass(frozen=True)
class ScanStats:
    files_considered: int
    files_scanned: int
    bytes_scanned: int
    skipped_binary: int
    skipped_links: int
    filtered: int
    suppressed: int
    complete: bool
    truncated: bool


@dataclass
class ScanResult:
    findings: List[Finding]
    suppressions: List[SuppressedFinding]
    diagnostics: List[Diagnostic]
    stats: ScanStats
    rules: Tuple[Rule, ...]
    scanned_paths: List[str]
    scanned_display_paths: List[str]

    @property
    def has_errors(self) -> bool:
        return any(diagnostic.level == "error" for diagnostic in self.diagnostics)


@dataclass(frozen=True)
class _ScanCandidate:
    """Internal candidate retained until cross-rule credential clustering."""

    rule: Rule
    match_start: int
    match_end: int
    secret_start: int
    secret_end: int
    has_secret: bool
    confidence: str
    entropy: float
    suppressed: bool = False
    suppression_justification: str = ""


@dataclass
class _SuppressionDirective:
    column: int
    rule_ids: Set[str]
    justification: str
    used_rule_ids: Set[str]


def P(pattern: str, secret_group: Optional[str] = None, kinds: Sequence[str] = ()) -> PatternSpec:
    return PatternSpec(pattern=pattern, secret_group=secret_group, kinds=tuple(kinds))


CONFIG_KINDS = ("dotenv", "yaml", "config")
QUOTED_SECRET = r"(?P<quote>[\"'])(?P<secret>(?:\\.|[^\r\n\\])*?)(?P=quote)"
PYTHON_CALL_CANDIDATE = (
    r"(?<![A-Za-z0-9_])"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\("
)


# Stable rule IDs are part of the JSON/SARIF/suppression contract.
RULES: Tuple[Rule, ...] = (
    Rule(
        "CREDENTIALS.PASSWORD",
        "credentials",
        "HIGH",
        "Hardcoded password",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?(?:password|passwd|pwd)[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                rf"\.put\s*\(\s*[\"'](?:password|pass|pwd)[\"']\s*,\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(rf"setPassword\s*\(\s*{QUOTED_SECRET}", "secret"),
            P(
                r"^\s*(?:export\s+)?(?:password|passwd|pwd)\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.API_KEY",
        "credentials",
        "HIGH",
        "Hardcoded API key",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?api[_-]?key[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?api[_-]?key\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.ACCESS_TOKEN",
        "credentials",
        "HIGH",
        "Hardcoded access token",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?access[_-]?token[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?access[_-]?token\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.AUTH_TOKEN",
        "credentials",
        "HIGH",
        "Hardcoded authentication token",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?auth[_-]?token[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?auth[_-]?token\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.SECRET_KEY",
        "credentials",
        "HIGH",
        "Hardcoded secret key",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?secret[_-]?key[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?secret[_-]?key\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.DATABASE_PASSWORD",
        "credentials",
        "HIGH",
        "Hardcoded database password",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?(?:db[_-]?pass|database[_-]?password)[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?(?:db[_-]?pass|database[_-]?password)\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.AWS_ACCESS_KEY_ID",
        "credentials",
        "HIGH",
        "Hardcoded AWS access key ID",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?aws[_-]?access[_-]?key[_-]?id[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?aws[_-]?access[_-]?key[_-]?id\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
            P(r"(?P<secret>AKIA[0-9A-Z]{16})", "secret"),
        ),
        "high",
    ),
    Rule(
        "CREDENTIALS.AWS_SECRET_ACCESS_KEY",
        "credentials",
        "HIGH",
        "Hardcoded AWS secret access key",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?aws[_-]?secret[_-]?access[_-]?key[\"']?\s*(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?aws[_-]?secret[_-]?access[_-]?key\s*(?:=|:)\s*(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.JWT",
        "credentials",
        "HIGH",
        "Hardcoded JWT",
        798,
        (P(r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})", "secret"),),
        "high",
    ),
    Rule(
        "CREDENTIALS.GITHUB_TOKEN",
        "credentials",
        "HIGH",
        "Hardcoded GitHub token",
        798,
        (
            P(
                r"(?<![A-Za-z0-9_])(?P<secret>"
                r"(?:gh[pousr]_[A-Za-z0-9]{36}|"
                r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}))"
                r"(?![A-Za-z0-9_])",
                "secret",
            ),
        ),
        "high",
    ),
    Rule(
        "CREDENTIALS.GITLAB_TOKEN",
        "credentials",
        "HIGH",
        "Hardcoded GitLab personal access token",
        798,
        (
            P(
                r"(?<![A-Za-z0-9_-])(?P<secret>glpat-[A-Za-z0-9_-]{20})"
                r"(?![A-Za-z0-9_-])",
                "secret",
            ),
        ),
        "high",
    ),
    Rule(
        "CREDENTIALS.CLIENT_SECRET",
        "credentials",
        "HIGH",
        "Hardcoded OAuth client secret",
        798,
        (
            P(
                rf"(?<![A-Za-z0-9_])[\"']?client[_-]?secret[\"']?\s*"
                rf"(?::=|=|:)\s*{QUOTED_SECRET}",
                "secret",
            ),
            P(
                r"^\s*(?:export\s+)?client[_-]?secret\s*(?:=|:)\s*"
                r"(?P<secret>(?![\"'])[^\s#;,\]}]+)",
                "secret",
                CONFIG_KINDS,
            ),
        ),
    ),
    Rule(
        "CREDENTIALS.PRIVATE_KEY",
        "credentials",
        "HIGH",
        "Private key material",
        321,
        (P(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),),
        "high",
    ),
    Rule(
        "CREDENTIALS.JDBC_URL",
        "credentials",
        "HIGH",
        "Credentials in JDBC URL",
        798,
        (P(r"jdbc:[a-zA-Z0-9]+://[^\"'\s]*:(?P<secret>[^@\"'\s]+)@", "secret"),),
    ),
    Rule(
        "CREDENTIALS.CONNECTION_URL",
        "credentials",
        "HIGH",
        "Password embedded in a connection URL",
        798,
        (
            P(
                r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,31}://"
                r"[^\s:@/?#\"'<>]*:(?P<secret>[^@\s/?#\"'<>]+)@"
                r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::[0-9]{1,5})?",
                "secret",
            ),
        ),
        "high",
    ),
    Rule(
        "SQL.CONCAT",
        "sql_injection",
        "HIGH",
        "SQL built by string concatenation",
        89,
        (
            P(r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^\"']*[\"']\s*\+\s*\w+"),
            P(r"(?:query|sql)\s*(?::=|=|:)\s*[\"'][^\"']*[\"']\s*\+"),
            P(r"WHERE\s+\w+\s*=\s*[\"'][\"']?\s*\+"),
            P(r"execute(?:Query|Update)?\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        ),
    ),
    Rule(
        "SQL.STATEMENT",
        "sql_injection",
        "HIGH",
        "Java Statement usage requires manual SQL-injection review",
        89,
        (P(r"createStatement\(\)"),),
        "low",
    ),
    Rule(
        "SQL.PERCENT_FORMAT",
        "sql_injection",
        "HIGH",
        "SQL built with percent string interpolation",
        89,
        (
            P(
                r"(?:\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"\r\n]*%[sd][^\"\r\n]*\"|'(?:SELECT|INSERT|UPDATE|DELETE)[^'\r\n]*%[sd][^'\r\n]*')\s*%\s*(?:\w+|\()"
            ),
        ),
    ),
    Rule(
        "SQL.FORMAT",
        "sql_injection",
        "HIGH",
        "SQL built with .format()",
        89,
        (
            P(
                r"(?:\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"\r\n]*\"|'(?:SELECT|INSERT|UPDATE|DELETE)[^'\r\n]*')\s*\.format\s*\([^)]*\)"
            ),
        ),
    ),
    Rule(
        "SQL.FSTRING",
        "sql_injection",
        "HIGH",
        "SQL built with an f-string",
        89,
        (
            P(
                r"(?:f\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"\r\n]*\{[^}]+\}[^\"\r\n]*\"|f'(?:SELECT|INSERT|UPDATE|DELETE)[^'\r\n]*\{[^}]+\}[^'\r\n]*')"
            ),
        ),
    ),
    Rule(
        "CMD.PHP_VARIABLE",
        "command_injection",
        "HIGH",
        "Command execution with a PHP variable",
        78,
        (P(r"(?:exec|system|shell_exec|passthru|popen)\s*\([^)]*\$"),),
    ),
    Rule(
        "CMD.EVAL_VARIABLE",
        "command_injection",
        "HIGH",
        "eval() with a PHP variable",
        95,
        (P(r"eval\s*\([^)]*\$"),),
    ),
    Rule(
        "CMD.JAVA_RUNTIME",
        "command_injection",
        "HIGH",
        "Java Runtime.exec requires manual input review",
        78,
        (P(r"Runtime\.getRuntime\(\)\.exec"),),
        "low",
    ),
    Rule(
        "CMD.SUBPROCESS_SHELL",
        "command_injection",
        "HIGH",
        "Python subprocess with shell=True",
        78,
        (
            P(
                PYTHON_CALL_CANDIDATE,
                kinds=("python",),
            ),
        ),
        "high",
    ),
    Rule(
        "CMD.OS_SYSTEM",
        "command_injection",
        "HIGH",
        "Command execution via os.system() requires manual input review",
        78,
        (P(PYTHON_CALL_CANDIDATE, kinds=("python",)),),
        "low",
    ),
    Rule(
        "CMD.PYTHON_EVAL",
        "command_injection",
        "HIGH",
        "Python eval() requires manual untrusted-input review",
        95,
        (P(PYTHON_CALL_CANDIDATE, kinds=("python",)),),
        "low",
    ),
    Rule(
        "CMD.PYTHON_EXEC",
        "command_injection",
        "HIGH",
        "Python exec() requires manual untrusted-input review",
        95,
        (P(PYTHON_CALL_CANDIDATE, kinds=("python",)),),
        "low",
    ),
    Rule(
        "DESER.PICKLE",
        "deserialization",
        "HIGH",
        "Python pickle deserialization",
        502,
        (P(PYTHON_CALL_CANDIDATE, kinds=("python",)),),
    ),
    Rule(
        "DESER.YAML_LOAD",
        "deserialization",
        "HIGH",
        "yaml.load without a safe loader",
        502,
        (
            P(
                PYTHON_CALL_CANDIDATE,
                kinds=("python",),
            ),
        ),
    ),
    Rule(
        "DESER.YAML_UNSAFE_LOAD",
        "deserialization",
        "HIGH",
        "Explicit PyYAML unsafe_load deserialization",
        502,
        (P(PYTHON_CALL_CANDIDATE, kinds=("python",)),),
        "high",
    ),
    Rule("DESER.PHP_UNSERIALIZE", "deserialization", "HIGH", "PHP unserialize()", 502, (P(r"\bunserialize\s*\("),)),
    Rule("DESER.JAVA_OBJECT_STREAM", "deserialization", "HIGH", "Java ObjectInputStream", 502, (P(r"ObjectInputStream"),)),
    Rule("DESER.RUBY_MARSHAL", "deserialization", "HIGH", "Ruby Marshal.load", 502, (P(r"Marshal\.load"),)),
    Rule("CRYPTO.MD5", "weak_crypto", "MEDIUM", "Weak hash: MD5", 328, (P(r"\bMD5\b"),)),
    Rule("CRYPTO.SHA1", "weak_crypto", "MEDIUM", "Weak hash: SHA1", 328, (P(r"\bSHA-?1\b"),)),
    Rule("CRYPTO.DES", "weak_crypto", "MEDIUM", "Weak cipher: DES", 327, (P(r"\bDES(?:ede)?\b|\"DES/"),)),
    Rule("CRYPTO.ECB", "weak_crypto", "MEDIUM", "Insecure cipher mode: ECB", 327, (P(r"AES/ECB|\"ECB\"|/ECB/"),)),
    Rule("CRYPTO.WEAK_RANDOM", "weak_crypto", "MEDIUM", "Potentially insecure PRNG for security use", 330, (P(r"Math\.random\(|random\.random\("),), "low"),
    Rule("PATH.CONCAT_FILE", "path_traversal", "MEDIUM", "File path built by concatenation", 22, (P(r"new\s+File\s*\([^)]*\+"),)),
    Rule("PATH.CONCAT_OPEN", "path_traversal", "MEDIUM", "File open with concatenation", 22, (P(r"open\s*\([^)]*\+\s*\w+"),)),
    Rule("PATH.DYNAMIC_INCLUDE", "path_traversal", "MEDIUM", "Dynamic file inclusion", 22, (P(r"(?:include|require)\s*\([^)]*\$"),)),
    Rule("PATH.DYNAMIC_READ", "path_traversal", "MEDIUM", "Dynamic PHP file read", 22, (P(r"file_get_contents\s*\([^)]*\$"),)),
    Rule("PATH.TRAVERSAL_SEQUENCE", "path_traversal", "MEDIUM", "Path traversal sequence", 22, (P(r"(?:\.\.[/\\]){2}"),), "low"),
    Rule("DB.CONNECTION", "database_operations", "LOW", "Database connection", None, (P(r"(?:mysqli?_connect|pg_connect|new\s+PDO\s*\(|DriverManager\.getConnection)"),)),
    Rule("DB.INTO_OUTFILE", "database_operations", "LOW", "MySQL INTO OUTFILE", None, (P(r"INTO\s+OUTFILE"),)),
    Rule("DB.LOAD_FILE", "database_operations", "LOW", "MySQL LOAD_FILE", None, (P(r"LOAD_FILE\s*\("),)),
    Rule("DB.MONGODB_OPERATOR", "database_operations", "LOW", "MongoDB operator (NoSQLi surface)", 943, (P(r"\$where|\$ne|\$gt|\$regex"),)),
    Rule("INFO.CONFIG_REFERENCE", "interesting_files", "INFO", "Config file reference", None, (P(r"(?:config\.(?:php|py|js)|\.env|web\.config|app\.config)"),)),
    Rule("INFO.BACKUP_REFERENCE", "interesting_files", "INFO", "Backup file reference", None, (P(r"\.(?:bak|backup|old|orig)\b"),)),
    Rule("INFO.DEBUG_ENABLED", "interesting_files", "INFO", "Debug mode enabled", None, (P(r"(?:DEBUG|debug)\s*=\s*[Tt]rue"),)),
    Rule("INFO.DEVELOPMENT_MARKER", "interesting_files", "INFO", "Development marker", None, (P(r"\b(?:TODO|FIXME|HACK|XXX)\b"),), "low"),
    Rule("INFO.PHPINFO", "interesting_files", "INFO", "phpinfo() call", None, (P(r"phpinfo\(\)"),)),
)

RULE_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in RULES}

PYTHON_SEMANTIC_RULE_IDS = frozenset(
    {
        "CMD.SUBPROCESS_SHELL",
        "CMD.OS_SYSTEM",
        "CMD.PYTHON_EVAL",
        "CMD.PYTHON_EXEC",
        "DESER.PICKLE",
        "DESER.YAML_LOAD",
        "DESER.YAML_UNSAFE_LOAD",
    }
)
SUBPROCESS_METHODS = frozenset(
    {"call", "run", "Popen", "check_call", "check_output"}
)
SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
)
CREDENTIAL_RULE_PRIORITY = {
    "CREDENTIALS.GITHUB_TOKEN": 100,
    "CREDENTIALS.GITLAB_TOKEN": 100,
    "CREDENTIALS.AWS_ACCESS_KEY_ID": 100,
    "CREDENTIALS.JWT": 100,
    "CREDENTIALS.PRIVATE_KEY": 100,
    "CREDENTIALS.JDBC_URL": 95,
    "CREDENTIALS.CONNECTION_URL": 90,
    "CREDENTIALS.AWS_SECRET_ACCESS_KEY": 85,
    "CREDENTIALS.CLIENT_SECRET": 85,
    "CREDENTIALS.DATABASE_PASSWORD": 80,
    "CREDENTIALS.API_KEY": 70,
    "CREDENTIALS.ACCESS_TOKEN": 70,
    "CREDENTIALS.AUTH_TOKEN": 70,
    "CREDENTIALS.SECRET_KEY": 70,
    "CREDENTIALS.PASSWORD": 60,
}


# --- file policy -------------------------------------------------------------
SCAN_EXTENSIONS = {
    ".java", ".php", ".py", ".js", ".jsx", ".ts", ".tsx", ".jsp", ".asp", ".aspx",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rb", ".pl", ".sh", ".bat", ".ps1",
    ".xml", ".conf", ".config", ".properties", ".ini", ".env", ".yml", ".yaml", ".json",
    ".sql", ".toml", ".tf", ".tfvars", ".kt", ".kts", ".gradle", ".groovy", ".rs",
}
ALWAYS_SCAN = {
    "Dockerfile", "docker-compose.yml", "Makefile", "Jenkinsfile", ".htaccess", ".htpasswd",
    "web.config", "build.gradle", "pom.xml", ".env",
}
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".tox",
}

EXTENSION_KIND = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".java": "java", ".php": "php", ".rb": "ruby", ".pl": "perl",
    ".sh": "shell", ".ps1": "powershell", ".bat": "batch", ".sql": "sql", ".xml": "xml",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".env": "dotenv",
    ".ini": "config", ".conf": "config", ".config": "config", ".properties": "config",
    ".c": "c_like", ".cpp": "c_like", ".h": "c_like", ".hpp": "c_like", ".cs": "c_like",
    ".go": "c_like", ".rs": "c_like", ".kt": "c_like", ".kts": "c_like",
}

LINE_BREAK_RE = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
NOSEC_RE = re.compile(
    r"\bnosec\s*:\s*([A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*)\b"
    r"(?:\s*--\s*([^\r\n]*))?",
    re.IGNORECASE,
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"change(?:[_-]?me)?|password\d*|passwd\d*|secret\d*|"
    r"example(?:[_-]?(?:key|secret|token|password))?|"
    r"sample(?:[_-]?(?:key|secret|token|password))?|"
    r"dummy(?:[_-]?(?:key|secret|token|password))?|"
    r"test(?:ing)?(?:[_-]?(?:key|secret|token|password))?|"
    r"fake(?:[_-]?(?:key|secret|token|password))?|"
    r"mock(?:[_-]?(?:key|secret|token|password))?|"
    r"placeholder|redacted|not[_ -]?(?:a[_ -]?)?real(?:[_ -]?secret)?|"
    r"123456|qwerty|null|none|todo|replace[_-]?me|insert[_-]?.*[_-]?here"
    r")$",
    re.IGNORECASE,
)
TEMPLATE_SECRET_RE = re.compile(
    r"^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"
    r"%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^{}]+\}\}|<[^<>]+>)$"
)


# --- helpers -----------------------------------------------------------------
def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(secret: str) -> str:
    del secret
    return "[REDACTED]"


def _safe_excerpt(value: str, limit: int = 240) -> str:
    value = CONTROL_RE.sub(lambda match: f"\\x{ord(match.group(0)):02x}", value)
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return value[:limit]


def _posix(path: str) -> str:
    return path.replace("\\", "/")


def _file_kind(path: str) -> str:
    name = os.path.basename(path).lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "dotenv"
    return EXTENSION_KIND.get(os.path.splitext(name)[1], "other")


def _is_link_or_junction(path: str) -> bool:
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(path):
        return True
    if os.name == "nt":
        try:
            file_attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        except OSError:
            return False
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
        # Python <3.12 has no os.path.isjunction(). Treat every Windows
        # reparse point as an explicit traversal boundary: mount points,
        # junctions and provider-specific redirects can all leave the root.
        return bool(file_attributes & reparse_flag)
    return False


def _path_has_link_component(path: str) -> bool:
    current = os.path.abspath(path)
    while True:
        if os.path.lexists(current) and _is_link_or_junction(current):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _same_file(first: str, second: str) -> bool:
    try:
        if os.path.exists(first) and os.path.exists(second):
            return os.path.samefile(first, second)
    except OSError:
        pass
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _atomic_write_text(path: str, content: str) -> Optional[str]:
    output = os.path.abspath(path)
    parent = os.path.dirname(output) or os.getcwd()
    if not os.path.isdir(parent):
        return "output parent directory does not exist"
    if os.path.lexists(output):
        if os.path.isdir(output):
            return "output path is a directory"
        return "output path already exists; refusing to overwrite"
    if _path_has_link_component(output):
        return "output path contains a symlink, junction, or reparse point"

    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{os.path.basename(output)}.", suffix=".tmp", dir=parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if _path_has_link_component(output):
            return "output path changed to a symlink, junction, or reparse point"
        # Publish without clobbering a file created after the checks above.
        # The temporary file is in the same directory, so hard-link creation is
        # an atomic no-replace operation on the supported CI filesystems.
        os.link(temporary, output)
        return None
    except OSError as exc:
        return getattr(exc, "strerror", None) or exc.__class__.__name__
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _contained(root_real: str, candidate: str) -> bool:
    try:
        candidate_real = os.path.realpath(candidate)
        common = os.path.commonpath([root_real, candidate_real])
        return os.path.normcase(common) == os.path.normcase(root_real)
    except (OSError, ValueError):
        return False


def _path_matches(path: str, patterns: Sequence[str]) -> bool:
    normalized = _posix(path)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    candidates = (normalized, "/" + normalized)
    for raw_pattern in patterns:
        pattern = _posix(raw_pattern)
        if os.name == "nt":
            pattern = pattern.lower()
            values = (candidate.lower() for candidate in candidates)
        else:
            values = iter(candidates)
        if any(fnmatch.fnmatchcase(candidate, pattern) for candidate in values):
            return True
    return False


def _line_layout(content: str) -> Tuple[List[int], List[int]]:
    breaks = list(LINE_BREAK_RE.finditer(content))
    starts = [0] + [match.end() for match in breaks]
    ends = [match.start() for match in breaks] + [len(content)]
    return starts, ends


def _line_location(starts: Sequence[int], ends: Sequence[int], position: int) -> Tuple[int, int, int, int]:
    index = max(0, bisect.bisect_right(starts, position) - 1)
    index = min(index, len(ends) - 1)
    return index + 1, position - starts[index] + 1, starts[index], ends[index]


def _claim_nonoverlapping_range(
    ranges: List[Tuple[int, int]], start: int, end: int
) -> bool:
    """Insert a range if it does not overlap an existing range.

    Regex matches arrive in source order, so the append path keeps the common
    high-finding case linear.  Matches from later patterns use binary search
    and need only inspect their immediate neighbours.
    """
    if not ranges or start >= ranges[-1][1]:
        ranges.append((start, end))
        return True
    index = bisect.bisect_left(ranges, (start, end))
    if index and ranges[index - 1][1] > start:
        return False
    if index < len(ranges) and ranges[index][0] < end:
        return False
    ranges.insert(index, (start, end))
    return True


def _ast_position(
    content: str,
    line_starts: Sequence[int],
    line_ends: Sequence[int],
    line_number: int,
    byte_column: int,
) -> int:
    """Convert an AST UTF-8 byte column to a character offset."""
    if line_number < 1 or line_number > len(line_starts):
        raise ValueError("AST line is outside the source line map")
    line_start = line_starts[line_number - 1]
    line_end = line_ends[line_number - 1]
    line = content[line_start:line_end]
    character_column = len(
        line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore")
    )
    return line_start + character_column


_UNBOUND = object()
_SHADOWED = object()


@dataclass
class _PythonScope:
    parent: Optional["_PythonScope"]
    kind: str
    imports: Dict[str, Tuple[str, ...]]
    bound: Set[str]


class _BindingCollector(ast.NodeVisitor):
    """Collect bindings in one lexical scope without entering child scopes."""

    def __init__(self) -> None:
        self.imports: Dict[str, Tuple[str, ...]] = {}
        self.bound: Set[str] = set()
        self.global_names: Set[str] = set()
        self.nonlocal_names: Set[str] = set()

    def _add_import(self, local_name: str, target: Tuple[str, ...]) -> None:
        previous = self.imports.get(local_name)
        if previous is not None and previous != target:
            self.bound.add(local_name)
        self.imports[local_name] = target

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                local_name = alias.asname
                target = tuple(alias.name.split("."))
            else:
                local_name = alias.name.split(".", 1)[0]
                target = (local_name,)
            self._add_import(local_name, target)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = tuple((node.module or "").split(".")) if node.module else ()
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            if node.level or not module:
                self.bound.add(local_name)
                continue
            self._add_import(local_name, module + (alias.name,))

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bound.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bound.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bound.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return


def _argument_names(arguments: ast.arguments) -> Set[str]:
    names = {
        argument.arg
        for argument in (
            list(getattr(arguments, "posonlyargs", []))
            + list(arguments.args)
            + list(arguments.kwonlyargs)
        )
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return names


def _make_python_scope(node: ast.AST, parent: Optional[_PythonScope]) -> _PythonScope:
    collector = _BindingCollector()
    kind = "module"
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        kind = "function"
        collector.bound.update(_argument_names(node.args))
        for statement in node.body:
            collector.visit(statement)
    elif isinstance(node, ast.Lambda):
        kind = "lambda"
        collector.bound.update(_argument_names(node.args))
        collector.visit(node.body)
    elif isinstance(node, ast.ClassDef):
        kind = "class"
        for statement in node.body:
            collector.visit(statement)
    elif isinstance(node, ast.Module):
        for statement in node.body:
            collector.visit(statement)
    else:
        kind = "comprehension"
        for generator in getattr(node, "generators", []):
            collector.visit(generator.target)
    collector.bound.difference_update(collector.global_names)
    collector.bound.difference_update(collector.nonlocal_names)
    return _PythonScope(parent, kind, collector.imports, collector.bound)


class _PythonSemanticAnalyzer(ast.NodeVisitor):
    """Resolve selected security-sensitive calls with bounded name semantics."""

    def __init__(
        self,
        content: str,
        line_starts: Sequence[int],
        line_ends: Sequence[int],
    ) -> None:
        self.content = content
        self.line_starts = line_starts
        self.line_ends = line_ends
        self.scope: Optional[_PythonScope] = None
        self.offsets: Dict[str, Dict[int, Tuple[int, int]]] = {
            rule_id: {} for rule_id in PYTHON_SEMANTIC_RULE_IDS
        }

    def analyze(self, tree: ast.Module) -> Dict[str, Dict[int, Tuple[int, int]]]:
        self.scope = _make_python_scope(tree, None)
        for statement in tree.body:
            self.visit(statement)
        return self.offsets

    def _resolve(self, name: str):
        scope = self.scope
        while scope is not None:
            if name in scope.bound:
                return _SHADOWED
            if name in scope.imports:
                return scope.imports[name]
            scope = scope.parent
        return _UNBOUND

    def _qualified_target(self, value: ast.AST) -> Optional[Tuple[str, ...]]:
        if isinstance(value, ast.Name):
            resolved = self._resolve(value.id)
            if isinstance(resolved, tuple):
                return resolved
            if resolved is _UNBOUND and value.id in {
                "builtins",
                "os",
                "pickle",
                "subprocess",
                "yaml",
            }:
                # Preserve the v2.1 convention of recognizing canonical module
                # names even in short snippets that omit their import lines.
                return (value.id,)
            return None
        if isinstance(value, ast.Attribute):
            owner = self._qualified_target(value.value)
            return owner + (value.attr,) if owner is not None else None
        return None

    def _call_target(self, function: ast.AST) -> Optional[Tuple[str, ...]]:
        if isinstance(function, ast.Name):
            resolved = self._resolve(function.id)
            if isinstance(resolved, tuple):
                return resolved
            if resolved is _UNBOUND and function.id in {"eval", "exec"}:
                return ("builtins", function.id)
            return None
        return self._qualified_target(function)

    def _safe_yaml_loader(self, value: ast.AST) -> bool:
        target = self._qualified_target(value)
        if target is not None:
            return (
                len(target) >= 2
                and target[0] == "yaml"
                and target[-1] in SAFE_YAML_LOADERS
            )
        if isinstance(value, ast.Name):
            return self._resolve(value.id) is _UNBOUND and value.id in SAFE_YAML_LOADERS
        return False

    def _position(self, node: ast.AST, end: bool = False) -> int:
        line_number = getattr(node, "end_lineno" if end else "lineno")
        column = getattr(node, "end_col_offset" if end else "col_offset")
        return _ast_position(
            self.content,
            self.line_starts,
            self.line_ends,
            line_number,
            column,
        )

    def _record(
        self,
        rule_id: str,
        node: ast.Call,
        suppression_node: Optional[ast.AST] = None,
    ) -> None:
        start = self._position(node.func)
        end = self._position(node, end=True)
        suppression_end = self._position(suppression_node, end=True) if suppression_node else end
        self.offsets[rule_id][start] = (end, suppression_end)

    def visit_Call(self, node: ast.Call) -> None:
        target = self._call_target(node.func)
        if target is not None:
            if (
                len(target) == 2
                and target[0] == "subprocess"
                and target[1] in SUBPROCESS_METHODS
            ):
                shell_keyword = next(
                    (
                        keyword
                        for keyword in node.keywords
                        if keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ),
                    None,
                )
                if shell_keyword is not None:
                    self._record("CMD.SUBPROCESS_SHELL", node, shell_keyword.value)
            elif target == ("os", "system"):
                self._record("CMD.OS_SYSTEM", node)
            elif target == ("builtins", "eval"):
                self._record("CMD.PYTHON_EVAL", node)
            elif target == ("builtins", "exec"):
                self._record("CMD.PYTHON_EXEC", node)
            elif target in {("pickle", "load"), ("pickle", "loads")}:
                self._record("DESER.PICKLE", node)
            elif target == ("yaml", "unsafe_load"):
                self._record("DESER.YAML_UNSAFE_LOAD", node)
            elif target in {("yaml", "load"), ("yaml", "full_load")}:
                safe = False
                if target[-1] == "load":
                    loader_values = [
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "Loader"
                    ]
                    if len(node.args) >= 2:
                        loader_values.append(node.args[1])
                    safe = any(self._safe_yaml_loader(value) for value in loader_values)
                if not safe:
                    self._record("DESER.YAML_LOAD", node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.AST) -> None:
        for decorator in getattr(node, "decorator_list", []):
            self.visit(decorator)
        arguments = getattr(node, "args")
        for default in list(arguments.defaults) + [
            value for value in arguments.kw_defaults if value is not None
        ]:
            self.visit(default)
        all_arguments = (
            list(getattr(arguments, "posonlyargs", []))
            + list(arguments.args)
            + list(arguments.kwonlyargs)
        )
        if arguments.vararg is not None:
            all_arguments.append(arguments.vararg)
        if arguments.kwarg is not None:
            all_arguments.append(arguments.kwarg)
        for argument in all_arguments:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        returns = getattr(node, "returns", None)
        if returns is not None:
            self.visit(returns)
        parent = self.scope
        self.scope = _make_python_scope(node, parent)
        try:
            for statement in getattr(node, "body"):
                self.visit(statement)
        finally:
            self.scope = parent

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in list(node.args.defaults) + [
            value for value in node.args.kw_defaults if value is not None
        ]:
            self.visit(default)
        parent = self.scope
        self.scope = _make_python_scope(node, parent)
        try:
            self.visit(node.body)
        finally:
            self.scope = parent

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        parent = self.scope
        self.scope = _make_python_scope(node, parent)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope = parent

    def _visit_comprehension(self, node: ast.AST, values: Sequence[ast.AST]) -> None:
        parent = self.scope
        self.scope = _make_python_scope(node, parent)
        try:
            for generator in getattr(node, "generators"):
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            for value in values:
                self.visit(value)
        finally:
            self.scope = parent

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node, (node.key, node.value))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node, (node.elt,))


def _token_position(line_starts: Sequence[int], token_position: Tuple[int, int]) -> int:
    line_number, column = token_position
    if line_number < 1 or line_number > len(line_starts):
        raise ValueError("token line is outside the source line map")
    return line_starts[line_number - 1] + column


def _token_call_end(tokens: Sequence[tokenize.TokenInfo], open_index: int) -> Optional[int]:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: List[str] = []
    for index in range(open_index, len(tokens)):
        value = tokens[index].string
        if value in pairs:
            stack.append(pairs[value])
        elif value in pairs.values():
            if not stack or value != stack.pop():
                return None
            if not stack:
                return index
    return None


def _token_call_arguments(
    tokens: Sequence[tokenize.TokenInfo], open_index: int, close_index: int
) -> List[List[tokenize.TokenInfo]]:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: List[str] = []
    arguments: List[List[tokenize.TokenInfo]] = []
    current: List[tokenize.TokenInfo] = []
    for token in tokens[open_index + 1:close_index]:
        value = token.string
        if value == "," and not stack:
            arguments.append(current)
            current = []
            continue
        current.append(token)
        if value in pairs:
            stack.append(pairs[value])
        elif value in pairs.values() and stack and value == stack[-1]:
            stack.pop()
    if current:
        arguments.append(current)
    return arguments


def _python_token_semantic_rule_offsets(
    content: str,
) -> Optional[Dict[str, Dict[int, Tuple[int, int]]]]:
    """Version-tolerant fallback for Python syntax newer than this runtime."""
    ignored = {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
    try:
        tokens = [
            token
            for token in tokenize.generate_tokens(io.StringIO(content).readline)
            if token.type not in ignored
        ]
        line_starts, _ = _line_layout(content)
        offsets: Dict[str, Dict[int, Tuple[int, int]]] = {
            rule_id: {} for rule_id in PYTHON_SEMANTIC_RULE_IDS
        }
        aliases: Dict[str, Tuple[str, ...]] = {}
        assigned: Set[str] = set()

        for index, token in enumerate(tokens):
            if token.type == tokenize.NAME and index + 1 < len(tokens):
                if tokens[index + 1].string in {"=", ":="}:
                    assigned.add(token.string)
            if token.string == "import" and index + 1 < len(tokens):
                # The preceding `from` form is handled separately below.
                if index >= 2 and tokens[index - 2].string == "from":
                    continue
                imported = tokens[index + 1]
                if imported.type != tokenize.NAME:
                    continue
                local_name = imported.string
                if index + 3 < len(tokens) and tokens[index + 2].string == "as":
                    local_name = tokens[index + 3].string
                aliases[local_name] = (imported.string,)
            if (
                token.string == "from"
                and index + 3 < len(tokens)
                and tokens[index + 1].type == tokenize.NAME
                and tokens[index + 2].string == "import"
                and tokens[index + 3].type == tokenize.NAME
            ):
                module = tokens[index + 1].string
                member = tokens[index + 3].string
                local_name = member
                if index + 5 < len(tokens) and tokens[index + 4].string == "as":
                    local_name = tokens[index + 5].string
                aliases[local_name] = (module, member)

        def resolved_name(name: str):
            if name in assigned:
                return _SHADOWED
            return aliases.get(name, _UNBOUND)

        def token_value_target(value: Sequence[tokenize.TokenInfo]):
            if len(value) == 1 and value[0].type == tokenize.NAME:
                resolved = resolved_name(value[0].string)
                if isinstance(resolved, tuple):
                    return resolved
                if resolved is _UNBOUND and value[0].string in SAFE_YAML_LOADERS:
                    return ("yaml", value[0].string)
            if (
                len(value) == 3
                and value[0].type == tokenize.NAME
                and value[1].string == "."
                and value[2].type == tokenize.NAME
            ):
                resolved = resolved_name(value[0].string)
                if isinstance(resolved, tuple):
                    return resolved + (value[2].string,)
                if resolved is _UNBOUND and value[0].string == "yaml":
                    return ("yaml", value[2].string)
            return None

        def safe_loader_argument(argument: Sequence[tokenize.TokenInfo]) -> bool:
            value: Sequence[tokenize.TokenInfo] = argument
            if (
                len(argument) >= 3
                and argument[0].type == tokenize.NAME
                and argument[0].string == "Loader"
                and argument[1].string == "="
            ):
                value = argument[2:]
            target = token_value_target(value)
            return bool(
                target
                and target[0] == "yaml"
                and target[-1] in SAFE_YAML_LOADERS
            )

        for index, token in enumerate(tokens):
            if token.type != tokenize.NAME:
                continue
            target: Optional[Tuple[str, ...]] = None
            open_index: Optional[int] = None
            resolved = resolved_name(token.string)
            if (
                index + 3 < len(tokens)
                and tokens[index + 1].string == "."
                and tokens[index + 2].type == tokenize.NAME
                and tokens[index + 3].string == "("
            ):
                if isinstance(resolved, tuple):
                    target = resolved + (tokens[index + 2].string,)
                elif resolved is _UNBOUND and token.string in {
                    "builtins",
                    "os",
                    "pickle",
                    "subprocess",
                    "yaml",
                }:
                    target = (token.string, tokens[index + 2].string)
                open_index = index + 3
            elif index + 1 < len(tokens) and tokens[index + 1].string == "(":
                if index and tokens[index - 1].string == ".":
                    continue
                if isinstance(resolved, tuple):
                    target = resolved
                elif resolved is _UNBOUND and token.string in {"eval", "exec"}:
                    target = ("builtins", token.string)
                open_index = index + 1
            if target is None or open_index is None:
                continue

            recognized = (
                (len(target) == 2 and target[0] == "subprocess" and target[1] in SUBPROCESS_METHODS)
                or target
                in {
                    ("builtins", "eval"),
                    ("builtins", "exec"),
                    ("os", "system"),
                    ("pickle", "load"),
                    ("pickle", "loads"),
                    ("yaml", "full_load"),
                    ("yaml", "load"),
                    ("yaml", "unsafe_load"),
                }
            )
            if not recognized:
                continue
            close_index = _token_call_end(tokens, open_index)
            if close_index is None:
                continue
            arguments = _token_call_arguments(tokens, open_index, close_index)
            start = _token_position(line_starts, token.start)
            end = _token_position(line_starts, tokens[close_index].end)
            if target[0] == "subprocess":
                shell_argument = next(
                    (
                        argument
                        for argument in arguments
                        if len(argument) == 3
                        and argument[0].type == tokenize.NAME
                        and argument[0].string == "shell"
                        and argument[1].string == "="
                        and argument[2].type == tokenize.NAME
                        and argument[2].string == "True"
                    ),
                    None,
                )
                if shell_argument is not None:
                    suppression_end = _token_position(
                        line_starts, shell_argument[2].end
                    )
                    offsets["CMD.SUBPROCESS_SHELL"][start] = (
                        end,
                        suppression_end,
                    )
            elif target == ("os", "system"):
                offsets["CMD.OS_SYSTEM"][start] = (end, end)
            elif target == ("builtins", "eval"):
                offsets["CMD.PYTHON_EVAL"][start] = (end, end)
            elif target == ("builtins", "exec"):
                offsets["CMD.PYTHON_EXEC"][start] = (end, end)
            elif target in {("pickle", "load"), ("pickle", "loads")}:
                offsets["DESER.PICKLE"][start] = (end, end)
            elif target == ("yaml", "unsafe_load"):
                offsets["DESER.YAML_UNSAFE_LOAD"][start] = (end, end)
            elif target in {("yaml", "load"), ("yaml", "full_load")}:
                loader_arguments = [
                    argument
                    for argument in arguments
                    if len(argument) >= 2
                    and argument[0].type == tokenize.NAME
                    and argument[0].string == "Loader"
                    and argument[1].string == "="
                ]
                if len(arguments) >= 2:
                    loader_arguments.append(arguments[1])
                safe_loader = (
                    target[-1] == "load"
                    and any(safe_loader_argument(argument) for argument in loader_arguments)
                )
                if not safe_loader:
                    offsets["DESER.YAML_LOAD"][start] = (end, end)
        return offsets
    except (
        IndentationError,
        IndexError,
        MemoryError,
        SyntaxError,
        UnicodeDecodeError,
        ValueError,
        tokenize.TokenError,
    ):
        return None


def _python_semantic_rule_offsets(
    content: str,
) -> Optional[Dict[str, Dict[int, Tuple[int, int]]]]:
    """Index Python calls whose security meaning depends on Python syntax."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, TypeError, MemoryError):
        return _python_token_semantic_rule_offsets(content)

    line_starts, line_ends = _line_layout(content)
    try:
        return _PythonSemanticAnalyzer(content, line_starts, line_ends).analyze(tree)
    except (IndexError, UnicodeDecodeError, ValueError):
        # Fall back to conservative regex candidates rather than crashing or
        # silently exempting a syntax-sensitive call.
        return _python_token_semantic_rule_offsets(content)


def _suppression_parts(
    comment: str,
) -> Tuple[Set[str], str]:
    match = NOSEC_RE.search(comment)
    if not match:
        return set(), ""
    rule_ids = {
        part.strip().upper()
        for part in match.group(1).split(",")
        if part.strip()
    }
    justification = (match.group(2) or "").strip()
    return rule_ids, justification


def _ids_from_comment(comment: str) -> Set[str]:
    """Compatibility helper retained for callers that only need rule IDs."""

    return _suppression_parts(comment)[0]


def _suppression_directives(
    content: str, kind: str
) -> Dict[int, List[_SuppressionDirective]]:
    directives: Dict[int, List[_SuppressionDirective]] = {}
    # Suppressions are enabled only where the standard-library tokenizer can
    # prove that the directive is in a real comment.  Quote-only heuristics are
    # unsafe for languages with constructs such as JavaScript regex literals:
    # `/[//] nosec: RULE/` is valid code, not a comment.  Unsupported languages
    # therefore fail closed and retain their findings.
    if kind != "python":
        return directives
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            rule_ids, justification = _suppression_parts(token.string)
            if rule_ids:
                directives.setdefault(token.start[0], []).append(
                    _SuppressionDirective(
                        column=token.start[1],
                        rule_ids=rule_ids,
                        justification=justification,
                        used_rule_ids=set(),
                    )
                )
    except (IndentationError, SyntaxError, tokenize.TokenError):
        # Ambiguous Python tokenization must never enable a suppression.
        return {}
    return directives


def _merge_spans(spans: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[List[int]] = []
    for start, end in sorted(set(spans)):
        if start < 0 or end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _redact_range(content: str, start: int, end: int, spans: Sequence[Tuple[int, int]]) -> str:
    output: List[str] = []
    cursor = start
    for secret_start, secret_end in spans:
        if secret_end <= start:
            continue
        if secret_start >= end:
            break
        visible_start = max(secret_start, start)
        visible_end = min(secret_end, end)
        if visible_start > cursor:
            output.append(content[cursor:visible_start])
        output.append(redact(content[visible_start:visible_end]))
        cursor = max(cursor, visible_end)
    output.append(content[cursor:end])
    return "".join(output)


def _looks_like_placeholder(secret: str) -> bool:
    stripped = secret.strip()
    if PLACEHOLDER_RE.fullmatch(stripped) or TEMPLATE_SECRET_RE.fullmatch(stripped):
        return True
    lowered = stripped.lower().replace(" ", "_")
    if re.fullmatch(
        r"(?:your|replace|insert)[_-](?:api[_-]?)?(?:key|secret|token|password)(?:[_-]here)?",
        lowered,
    ):
        return True
    compact = re.sub(r"[^A-Za-z0-9]", "", stripped)
    return len(compact) >= 8 and len(set(compact.lower())) <= 2


def _credential_confidence(secret: str, entropy: float, default: str) -> str:
    stripped = secret.strip()
    if _looks_like_placeholder(stripped) or entropy < 3.0:
        return "low"
    if entropy >= 3.5:
        return "high"
    return default


def _cluster_credential_candidates(
    candidates: Sequence[_ScanCandidate],
) -> List[_ScanCandidate]:
    """Keep one highest-specificity credential issue per overlapping secret."""
    credential_indices = [
        index
        for index, candidate in enumerate(candidates)
        if candidate.rule.category == "credentials"
    ]
    if len(credential_indices) < 2:
        return list(candidates)

    ordered = sorted(
        credential_indices,
        key=lambda index: (
            candidates[index].secret_start,
            candidates[index].secret_end,
            index,
        ),
    )
    keep: Set[int] = {
        index
        for index, candidate in enumerate(candidates)
        if candidate.rule.category != "credentials"
    }

    def retain(component: Sequence[int]) -> None:
        winner = max(
            component,
            key=lambda index: (
                CREDENTIAL_RULE_PRIORITY.get(candidates[index].rule.id, 0),
                -(candidates[index].secret_end - candidates[index].secret_start),
                -index,
            ),
        )
        keep.add(winner)

    component: List[int] = []
    component_end = -1
    for index in ordered:
        candidate = candidates[index]
        if component and candidate.secret_start >= component_end:
            retain(component)
            component = []
            component_end = -1
        component.append(index)
        component_end = max(component_end, candidate.secret_end)
    if component:
        retain(component)
    return [candidate for index, candidate in enumerate(candidates) if index in keep]


# --- scanner -----------------------------------------------------------------
class Scanner:
    def __init__(
        self,
        categories: Optional[Sequence[str]] = None,
        min_entropy: float = 0.0,
        min_confidence: str = "low",
        redact_secrets: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_findings: int = DEFAULT_MAX_FINDINGS,
        require_suppression_reason: bool = False,
    ):
        self.categories = set(categories) if categories else None
        self.min_entropy = min_entropy
        self.min_confidence = min_confidence
        self.redact_secrets = redact_secrets
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_findings = max_findings
        self.require_suppression_reason = require_suppression_reason
        self.diagnostics: List[Diagnostic] = []
        self.suppressed_count = 0
        self.suppressed_findings: List[SuppressedFinding] = []
        self.filtered_count = 0
        self.files_considered = 0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.skipped_binary = 0
        self.skipped_links = 0
        self.findings_emitted = 0
        self.truncated = False
        self.halted = False
        self.scanned_paths: List[str] = []
        self.scanned_display_paths: List[str] = []
        self.compiled: List[CompiledPattern] = []
        for rule in RULES:
            for spec in rule.patterns:
                self.compiled.append(
                    CompiledPattern(rule, spec, re.compile(spec.pattern, re.IGNORECASE | re.MULTILINE))
                )

    @property
    def active_rules(self) -> Tuple[Rule, ...]:
        if not self.categories:
            return RULES
        return tuple(rule for rule in RULES if rule.category in self.categories)

    @property
    def has_errors(self) -> bool:
        return any(diagnostic.level == "error" for diagnostic in self.diagnostics)

    @property
    def stats(self) -> ScanStats:
        return ScanStats(
            files_considered=self.files_considered,
            files_scanned=self.files_scanned,
            bytes_scanned=self.bytes_scanned,
            skipped_binary=self.skipped_binary,
            skipped_links=self.skipped_links,
            filtered=self.filtered_count,
            suppressed=self.suppressed_count,
            complete=not self.has_errors,
            truncated=self.truncated,
        )

    def _reset_run(self) -> None:
        self.diagnostics = []
        self.suppressed_count = 0
        self.suppressed_findings = []
        self.filtered_count = 0
        self.files_considered = 0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.skipped_binary = 0
        self.skipped_links = 0
        self.findings_emitted = 0
        self.truncated = False
        self.halted = False
        self.scanned_paths = []
        self.scanned_display_paths = []

    def _diagnose(self, message: str, file: str = "", level: str = "error") -> None:
        self.diagnostics.append(Diagnostic(level=level, message=message, file=file))

    def _mark_limit(self, message: str, file: str = "", halt: bool = True) -> None:
        self.truncated = True
        self.halted = self.halted or halt
        self._diagnose(message, file)

    @staticmethod
    def should_scan(path: str) -> bool:
        name = os.path.basename(path)
        lower = name.lower()
        if name in ALWAYS_SCAN or lower == ".env" or lower.startswith(".env."):
            return True
        if lower.startswith("dockerfile"):
            return True
        return os.path.splitext(lower)[1] in SCAN_EXTENSIONS

    def _read_text(self, path: str, display_path: str) -> Optional[str]:
        try:
            size = os.path.getsize(path)
            if self.max_file_size and size > self.max_file_size:
                self._mark_limit(
                    "file exceeds max size set by --max-file-size "
                    f"({size} > {self.max_file_size} bytes)",
                    display_path,
                    halt=False,
                )
                return None
            if self.max_total_bytes and self.bytes_scanned + size > self.max_total_bytes:
                self._mark_limit(
                    "scan stopped before exceeding --max-total-bytes "
                    f"({self.bytes_scanned} + {size} > {self.max_total_bytes})",
                    display_path,
                )
                return None
            with open(path, "rb") as handle:
                limits: List[int] = []
                if self.max_file_size:
                    limits.append(self.max_file_size)
                if self.max_total_bytes:
                    limits.append(max(0, self.max_total_bytes - self.bytes_scanned))
                read_limit = min(limits) if limits else 0
                data = handle.read(read_limit + 1 if limits else -1)
            if self.max_file_size and len(data) > self.max_file_size:
                self._mark_limit(
                    "file exceeds max size set by --max-file-size after open "
                    f"({len(data)} > {self.max_file_size} bytes)",
                    display_path,
                    halt=False,
                )
                return None
            if self.max_total_bytes and self.bytes_scanned + len(data) > self.max_total_bytes:
                self._mark_limit(
                    "scan stopped after file growth would exceed --max-total-bytes "
                    f"({self.bytes_scanned} + {len(data)} > {self.max_total_bytes})",
                    display_path,
                )
                return None
        except OSError as exc:
            message = getattr(exc, "strerror", None) or exc.__class__.__name__
            self._diagnose(f"could not read file: {message}", display_path)
            return None

        self.bytes_scanned += len(data)

        try:
            if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                return data.decode("utf-16")
            if data.startswith(codecs.BOM_UTF8):
                return data.decode("utf-8-sig")
            if b"\x00" in data:
                self.skipped_binary += 1
                return None
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._diagnose(
                f"could not decode file as UTF-8/UTF-16 (byte {exc.start})", display_path
            )
            return None

    def _secret_spans(
        self, content: str, kind: str, patterns: Sequence[CompiledPattern]
    ) -> List[Tuple[int, int]]:
        spans: List[Tuple[int, int]] = []
        for compiled in patterns:
            group = compiled.spec.secret_group
            if not group or not compiled.spec.applies_to(kind):
                continue
            for match in compiled.regex.finditer(content):
                try:
                    spans.append(match.span(group))
                except (IndexError, ValueError):
                    continue
        merged = _merge_spans(spans)
        if not merged:
            return []
        starts, ends = _line_layout(content)
        protected_lines: List[Tuple[int, int]] = []
        for start, end in merged:
            if start >= end:
                continue
            first_line = max(0, bisect.bisect_right(starts, start) - 1)
            last_line = max(0, bisect.bisect_right(starts, end - 1) - 1)
            for line_index in range(first_line, min(last_line + 1, len(ends))):
                protected_lines.append((starts[line_index], ends[line_index]))
        # Safe output is a hard boundary: once a credential candidate appears
        # on a line, default reports reveal none of that source line.  This
        # remains safe across adjacent literals and language-specific escapes.
        return _merge_spans(protected_lines)

    def scan_file(self, path: str, display_path: Optional[str] = None) -> List[Finding]:
        display = _posix(display_path or path)
        if self.max_files and self.files_considered >= self.max_files:
            self._mark_limit(
                f"scan stopped after reaching --max-files ({self.max_files})",
                display,
            )
            return []
        self.files_considered += 1
        self.scanned_paths.append(os.path.abspath(path))
        self.scanned_display_paths.append(display)
        content = self._read_text(path, display)
        if content is None:
            return []
        self.files_scanned += 1
        kind = _file_kind(path)
        applicable = [item for item in self.compiled if item.spec.applies_to(kind)]
        secret_spans = self._secret_spans(content, kind, applicable)
        starts, ends = _line_layout(content)
        suppression_directives = _suppression_directives(content, kind)
        known_rule_ids = set(RULE_BY_ID)
        active_rule_ids = {rule.id for rule in self.active_rules}
        for directive_line, directives in suppression_directives.items():
            for directive in directives:
                unknown = sorted(directive.rule_ids - known_rule_ids)
                if unknown:
                    self._diagnose(
                        f"line {directive_line}: nosec references unknown rule ID(s): "
                        + ", ".join(unknown),
                        display,
                        level="warning",
                    )
        semantic_spans = (
            _python_semantic_rule_offsets(content) if kind == "python" else {}
        )
        if semantic_spans is None:
            self._diagnose(
                "could not tokenize Python for syntax-sensitive rules; "
                "Python call findings were not evaluated",
                display,
                level="warning",
            )
        candidates: List[_ScanCandidate] = []
        seen_ranges: Dict[str, List[Tuple[int, int]]] = {}

        for compiled in applicable:
            rule = compiled.rule
            if self.categories and rule.category not in self.categories:
                continue
            for match in compiled.regex.finditer(content):
                syntax_sensitive = rule.id in PYTHON_SEMANTIC_RULE_IDS
                semantic_end: Optional[int] = None
                suppression_match_end: Optional[int] = None
                if syntax_sensitive and semantic_spans is None:
                    continue
                if syntax_sensitive:
                    semantic_span = semantic_spans[rule.id].get(match.start())
                    if semantic_span is None:
                        continue
                    semantic_end, suppression_match_end = semantic_span
                match_start = match.start()
                match_end = semantic_end if semantic_end is not None else match.end()
                suppression_end = (
                    suppression_match_end
                    if suppression_match_end is not None
                    else match_end
                )
                ranges = seen_ranges.setdefault(rule.id, [])
                if not _claim_nonoverlapping_range(
                    ranges, match.start(), match.end()
                ):
                    continue

                line, column, line_start, line_end = _line_location(starts, ends, match_start)
                line_text = content[line_start:line_end]
                end_position = max(match_start, match_end - 1)
                end_line, end_column_base, _, _ = _line_location(starts, ends, end_position)
                suppression_end_position = max(match_start, suppression_end - 1)
                suppression_end_line, _, _, _ = _line_location(
                    starts, ends, suppression_end_position
                )
                suppression: Optional[_SuppressionDirective] = None
                for directive_line in range(line, suppression_end_line + 1):
                    line_index = directive_line - 1
                    matched_through_column = (
                        min(suppression_end, ends[line_index]) - starts[line_index]
                    )
                    suppression = next(
                        (
                            directive
                            for directive in suppression_directives.get(directive_line, [])
                            if directive.column >= matched_through_column
                            and rule.id.upper() in directive.rule_ids
                        ),
                        None,
                    )
                    if suppression is not None:
                        suppression.used_rule_ids.add(rule.id.upper())
                        break

                suppressed = suppression is not None
                suppression_justification = ""
                if suppression is not None:
                    if self.require_suppression_reason and not suppression.justification:
                        self._diagnose(
                            f"line {directive_line}: nosec for {rule.id} requires a justification",
                            display,
                        )
                        suppressed = False
                    elif suppression.justification:
                        if self.redact_secrets:
                            reason_spans = self._secret_spans(
                                suppression.justification,
                                kind,
                                applicable,
                            )
                            suppression_justification = _redact_range(
                                suppression.justification,
                                0,
                                len(suppression.justification),
                                reason_spans,
                            )
                        else:
                            suppression_justification = suppression.justification
                        suppression_justification = _safe_excerpt(
                            suppression_justification.strip()
                        )

                entropy_value = 0.0
                confidence = rule.confidence
                group = compiled.spec.secret_group
                if group:
                    secret = match.group(group).strip()
                    entropy_value = shannon_entropy(secret)
                    confidence = _credential_confidence(secret, entropy_value, confidence)
                    secret_start, secret_end = match.span(group)
                else:
                    secret_start, secret_end = match_start, match_end
                candidates.append(
                    _ScanCandidate(
                        rule=rule,
                        match_start=match_start,
                        match_end=match_end,
                        secret_start=secret_start,
                        secret_end=secret_end,
                        has_secret=bool(group),
                        confidence=confidence,
                        entropy=entropy_value,
                        suppressed=suppressed,
                        suppression_justification=suppression_justification,
                    )
                )

        for directive_line, directives in suppression_directives.items():
            for directive in directives:
                unused = sorted(
                    (directive.rule_ids & active_rule_ids) - directive.used_rule_ids
                )
                if unused:
                    self._diagnose(
                        f"line {directive_line}: nosec did not match an active finding for: "
                        + ", ".join(unused),
                        display,
                        level="warning",
                    )

        findings: List[Finding] = []
        for candidate in _cluster_credential_candidates(candidates):
            if (
                not candidate.suppressed
                and candidate.has_secret
                and candidate.entropy < self.min_entropy
            ):
                self.filtered_count += 1
                continue
            if (
                not candidate.suppressed
                and CONFIDENCE_ORDER[candidate.confidence]
                < CONFIDENCE_ORDER[self.min_confidence]
            ):
                self.filtered_count += 1
                continue
            rule = candidate.rule
            match_start = candidate.match_start
            match_end = candidate.match_end
            line, column, line_start, line_end = _line_location(starts, ends, match_start)
            line_text = content[line_start:line_end]
            end_position = max(match_start, match_end - 1)
            end_line, end_column_base, _, _ = _line_location(starts, ends, end_position)
            end_column = end_column_base + 1
            if self.redact_secrets:
                shown_match = _redact_range(
                    content, match_start, match_end, secret_spans
                )
                context = _redact_range(content, line_start, line_end, secret_spans)
            else:
                shown_match = content[match_start:match_end]
                context = line_text
            finding_fields = {
                "rule_id": rule.id,
                "category": rule.category,
                "severity": rule.severity,
                "description": rule.description,
                "file": display,
                "line": line,
                "column": column,
                "end_line": end_line,
                "end_column": end_column,
                "match": _safe_excerpt(shown_match),
                "context": _safe_excerpt(context.strip()),
                "confidence": candidate.confidence,
                "entropy": round(candidate.entropy, 2),
                "cwe": rule.cwe,
            }
            if (
                self.max_findings
                and self.findings_emitted + self.suppressed_count
                >= self.max_findings
            ):
                self._mark_limit(
                    f"scan stopped after reaching --max-findings ({self.max_findings})",
                    display,
                )
                break
            if candidate.suppressed:
                self.suppressed_findings.append(
                    SuppressedFinding(
                        **finding_fields,
                        justification=candidate.suppression_justification,
                    )
                )
                self.suppressed_count += 1
                continue
            findings.append(Finding(**finding_fields))
            self.findings_emitted += 1
        return findings

    def _default_base_dir(self, target_abs: str) -> str:
        cwd = os.path.abspath(os.getcwd())
        try:
            if os.path.normcase(os.path.commonpath([cwd, target_abs])) == os.path.normcase(cwd):
                return cwd
        except ValueError:
            pass
        return target_abs if os.path.isdir(target_abs) else os.path.dirname(target_abs)

    def scan_path(
        self,
        target: str,
        recursive: bool = False,
        excludes: Optional[Sequence[str]] = None,
        includes: Optional[Sequence[str]] = None,
        verbose: bool = False,
        base_dir: Optional[str] = None,
        force_file: bool = False,
    ) -> List[Finding]:
        self._reset_run()
        excludes = list(excludes or [])
        includes = list(includes or [])
        target_abs = os.path.abspath(target)
        base = os.path.abspath(base_dir) if base_dir else self._default_base_dir(target_abs)
        if not os.path.isdir(base):
            self._diagnose("base directory does not exist or is not a directory", _posix(base))
            return []
        if base_dir and not _contained(os.path.realpath(base), target_abs):
            self._diagnose("target is outside --base-dir", _posix(target_abs))
            return []

        def display_path(path: str) -> str:
            try:
                relative = os.path.relpath(path, base)
            except ValueError:
                relative = os.path.basename(path)
            if relative == ".." or relative.startswith(".." + os.sep):
                relative = os.path.basename(path)
            return _posix(relative)

        def eligible(path: str, display: str) -> bool:
            if _path_matches(display, excludes):
                return False
            if includes and not _path_matches(display, includes):
                return False
            return force_file or self.should_scan(path)

        if os.path.isfile(target_abs):
            display = display_path(target_abs)
            if _is_link_or_junction(target_abs):
                self.skipped_links += 1
                self._diagnose("refusing to scan a symlink or junction target", display)
                return []
            if eligible(target_abs, display):
                return self.scan_file(target_abs, display)
            return []

        if not os.path.isdir(target_abs):
            self._diagnose("target is not a regular file or directory", _posix(target))
            return []
        if _is_link_or_junction(target_abs):
            self.skipped_links += 1
            self._diagnose("refusing to scan a symlink or junction target", display_path(target_abs))
            return []

        root_real = os.path.realpath(target_abs)
        findings: List[Finding] = []

        def scan_candidate(path: str) -> bool:
            if self.halted:
                return False
            display = display_path(path)
            if _is_link_or_junction(path):
                self.skipped_links += 1
                return True
            if not _contained(root_real, path):
                self._diagnose("resolved path escapes scan root", display)
                return True
            if not eligible(path, display):
                return True
            findings.extend(self.scan_file(path, display))
            return not self.halted

        if not recursive:
            try:
                with os.scandir(target_abs) as entries:
                    for entry in sorted(entries, key=lambda item: item.name.casefold()):
                        if entry.is_file(follow_symlinks=False):
                            if not scan_candidate(entry.path):
                                break
                        elif entry.is_symlink() or _is_link_or_junction(entry.path):
                            self.skipped_links += 1
            except OSError as exc:
                message = getattr(exc, "strerror", None) or exc.__class__.__name__
                self._diagnose(f"could not list directory: {message}", display_path(target_abs))
            return findings

        def walk_error(exc: OSError) -> None:
            message = getattr(exc, "strerror", None) or exc.__class__.__name__
            filename = display_path(getattr(exc, "filename", target_abs) or target_abs)
            self._diagnose(f"could not traverse directory: {message}", filename)

        for root, dirs, files in os.walk(
            target_abs, topdown=True, followlinks=False, onerror=walk_error
        ):
            kept_dirs: List[str] = []
            for directory in sorted(dirs, key=str.casefold):
                path = os.path.join(root, directory)
                display = display_path(path) + "/"
                if directory in SKIP_DIRS or _path_matches(display, excludes):
                    continue
                if _is_link_or_junction(path):
                    self.skipped_links += 1
                    continue
                if not _contained(root_real, path):
                    self._diagnose("resolved directory escapes scan root", display.rstrip("/"))
                    continue
                kept_dirs.append(directory)
            dirs[:] = kept_dirs
            for filename in sorted(files, key=str.casefold):
                if not scan_candidate(os.path.join(root, filename)):
                    break
            if self.halted:
                break
        return findings


def scan(config: ScanConfig) -> ScanResult:
    """Scan source code without printing or writing a report.

    This is the stable programmatic boundary for callers that want to choose
    their own renderer, storage, or policy gate.
    """

    numeric_limits = {
        "min_entropy": config.min_entropy,
        "max_file_size": config.max_file_size,
        "max_files": config.max_files,
        "max_total_bytes": config.max_total_bytes,
        "max_findings": config.max_findings,
    }
    negative = [name for name, value in numeric_limits.items() if value < 0]
    if negative:
        raise ValueError(f"scan limits must be non-negative: {', '.join(negative)}")
    if config.min_confidence not in CONFIDENCE_ORDER:
        raise ValueError(f"unknown minimum confidence: {config.min_confidence}")
    known_categories = {rule.category for rule in RULES}
    unknown_categories = sorted(set(config.categories or ()) - known_categories)
    if unknown_categories:
        raise ValueError(f"unknown scan categories: {', '.join(unknown_categories)}")

    scanner = Scanner(
        categories=config.categories,
        min_entropy=config.min_entropy,
        min_confidence=config.min_confidence,
        redact_secrets=config.redact_secrets,
        max_file_size=config.max_file_size,
        max_files=config.max_files,
        max_total_bytes=config.max_total_bytes,
        max_findings=config.max_findings,
        require_suppression_reason=config.require_suppression_reason,
    )
    findings = scanner.scan_path(
        config.target,
        recursive=config.recursive,
        excludes=config.excludes,
        includes=config.includes,
        base_dir=config.base_dir,
        force_file=config.force_file,
    )
    return ScanResult(
        findings=findings,
        suppressions=list(scanner.suppressed_findings),
        diagnostics=list(scanner.diagnostics),
        stats=scanner.stats,
        rules=scanner.active_rules,
        scanned_paths=list(scanner.scanned_paths),
        scanned_display_paths=list(scanner.scanned_display_paths),
    )


# --- output ------------------------------------------------------------------
def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def _eprint(message: str) -> None:
    print(_strip_ansi(message), file=sys.stderr)


def _summary(
    findings: Sequence[Finding],
    diagnostics: Sequence[Diagnostic],
    suppressed: int,
    filtered: int,
    files_scanned: int,
    skipped_binary: int,
    skipped_links: int,
    files_considered: int = 0,
    bytes_scanned: int = 0,
    truncated: bool = False,
) -> Dict[str, object]:
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in SEVERITY_ORDER}
    scan_errors = sum(1 for diagnostic in diagnostics if diagnostic.level == "error")
    return {
        "total": len(findings),
        **counts,
        "scan_errors": scan_errors,
        "suppressed": suppressed,
        "filtered": filtered,
        "files_considered": files_considered,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "skipped_binary": skipped_binary,
        "skipped_links": skipped_links,
        "complete": scan_errors == 0,
        "truncated": truncated,
    }


def to_text(
    findings: Sequence[Finding],
    diagnostics: Sequence[Diagnostic] = (),
    suppressed: int = 0,
    filtered: int = 0,
    files_scanned: int = 0,
    skipped_binary: int = 0,
    skipped_links: int = 0,
    use_color: bool = False,
    *,
    suppressions: Sequence[SuppressedFinding] = (),
    files_considered: int = 0,
    bytes_scanned: int = 0,
    truncated: bool = False,
) -> str:
    sorted_findings = sorted(findings, key=lambda finding: finding.sort_key())
    lines: List[str] = []
    if not sorted_findings:
        lines.append(f"{Fore.GREEN if use_color else ''}{Style.BRIGHT if use_color else ''}No findings.")
    current = None
    for finding in sorted_findings:
        if finding.file != current:
            current = finding.file
            lines.extend(["", "=" * 78, finding.file, "=" * 78])
        color = SEVERITY_COLOR[finding.severity] if use_color else ""
        tag = f"[{finding.severity}]".ljust(9)
        extra = f" (entropy {finding.entropy}, {finding.confidence})" if finding.category == "credentials" else f" ({finding.confidence})"
        lines.append(
            f"{color}{tag} L{finding.line}:{finding.column} {finding.rule_id} - {finding.description}{extra}"
        )
        lines.append(f"{color}          {finding.context}")
    summary = _summary(
        findings,
        diagnostics,
        suppressed,
        filtered,
        files_scanned,
        skipped_binary,
        skipped_links,
        files_considered,
        bytes_scanned,
        truncated,
    )
    lines.extend(
        [
            "",
            "=" * 78,
            (
                f"SUMMARY: {summary['total']} finding(s) | HIGH {summary['HIGH']}  "
                f"MEDIUM {summary['MEDIUM']}  LOW {summary['LOW']}  INFO {summary['INFO']}  "
                f"ERRORS {summary['scan_errors']}  SUPPRESSED {summary['suppressed']}"
            ),
        ]
    )
    if suppressions:
        lines.append("SUPPRESSIONS:")
        for item in sorted(suppressions, key=lambda finding: finding.sort_key()):
            reason = item.justification or "no justification provided"
            lines.append(
                f"  [ACCEPTED] {item.file}:L{item.line}:{item.column} "
                f"{item.rule_id} -- {reason}"
            )
    if not summary["complete"] or summary["truncated"]:
        state = "TRUNCATED" if summary["truncated"] else "INCOMPLETE"
        lines.append(
            f"SCAN STATUS: {state}; do not treat this report as a clean scan."
        )
    if diagnostics:
        lines.append("SCAN DIAGNOSTICS:")
        for diagnostic in diagnostics:
            location = f" {diagnostic.file}:" if diagnostic.file else ""
            lines.append(f"  [{diagnostic.level.upper()}]{location} {diagnostic.message}")
    result = "\n".join(lines)
    return result if use_color else _strip_ansi(result)


def render_text(findings: Sequence[Finding]) -> None:
    print(to_text(findings, use_color=_COLOR_AVAILABLE and sys.stdout.isatty()))


def print_summary(findings: Sequence[Finding]) -> None:
    summary = _summary(findings, (), 0, 0, 0, 0, 0)
    print(
        f"SUMMARY: {summary['total']} finding(s) | HIGH {summary['HIGH']}  "
        f"MEDIUM {summary['MEDIUM']}  LOW {summary['LOW']}  INFO {summary['INFO']}"
    )


def to_json(
    findings: Sequence[Finding],
    diagnostics: Sequence[Diagnostic] = (),
    suppressed: int = 0,
    filtered: int = 0,
    files_scanned: int = 0,
    skipped_binary: int = 0,
    skipped_links: int = 0,
    *,
    suppressions: Sequence[SuppressedFinding] = (),
    files_considered: int = 0,
    bytes_scanned: int = 0,
    truncated: bool = False,
) -> str:
    return json.dumps(
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": _summary(
                findings,
                diagnostics,
                suppressed,
                filtered,
                files_scanned,
                skipped_binary,
                skipped_links,
                files_considered,
                bytes_scanned,
                truncated,
            ),
            "diagnostics": [asdict(diagnostic) for diagnostic in diagnostics],
            "findings": [asdict(finding) for finding in sorted(findings, key=lambda item: item.sort_key())],
            "suppressions": [
                asdict(finding)
                for finding in sorted(
                    suppressions, key=lambda item: item.sort_key()
                )
            ],
        },
        indent=2,
    )


def _sarif_rule(rule: Rule) -> Dict[str, object]:
    properties: Dict[str, object] = {
        "precision": rule.confidence,
        "security-severity": SARIF_SECURITY_SEVERITY[rule.severity],
        "tags": ["security", rule.category],
    }
    if rule.cwe:
        properties["tags"].append(f"external/cwe/cwe-{rule.cwe:03d}")
    descriptor: Dict[str, object] = {
        "id": rule.id,
        "name": rule.id.replace(".", "_"),
        "shortDescription": {"text": rule.description},
        "fullDescription": {"text": f"{rule.description}. Manual confirmation is required."},
        "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
        "properties": properties,
    }
    if rule.cwe:
        descriptor["helpUri"] = f"https://cwe.mitre.org/data/definitions/{rule.cwe}.html"
    return descriptor


def _sarif_result(
    finding: Finding,
    rule_index: Dict[str, int],
    suppressed: bool = False,
) -> Dict[str, object]:
    region: Dict[str, int] = {
        "startLine": finding.line,
        "startColumn": finding.column,
        "endLine": finding.end_line,
        "endColumn": finding.end_column,
    }
    result: Dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.description}: {finding.context}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(_posix(finding.file), safe="/")
                    },
                    "region": region,
                }
            }
        ],
        "properties": {
            "confidence": finding.confidence,
            "category": finding.category,
            "entropy": finding.entropy,
            "suppressed": suppressed,
        },
    }
    if suppressed:
        suppression: Dict[str, str] = {
            "kind": "inSource",
            "status": "accepted",
        }
        justification = getattr(finding, "justification", "")
        if justification:
            suppression["justification"] = justification
        result["suppressions"] = [suppression]
    return result


def to_sarif(
    findings: Sequence[Finding],
    diagnostics: Sequence[Diagnostic] = (),
    rules: Sequence[Rule] = RULES,
    *,
    suppressions: Sequence[SuppressedFinding] = (),
    files_considered: int = 0,
    files_scanned: int = 0,
    bytes_scanned: int = 0,
    truncated: bool = False,
) -> str:
    sorted_findings = sorted(findings, key=lambda item: item.sort_key())
    sorted_suppressions = sorted(
        suppressions, key=lambda item: item.sort_key()
    )
    rule_list = list(rules)
    rule_index = {rule.id: index for index, rule in enumerate(rule_list)}
    results = [
        _sarif_result(finding, rule_index) for finding in sorted_findings
    ]
    results.extend(
        _sarif_result(finding, rule_index, suppressed=True)
        for finding in sorted_suppressions
    )
    notifications = [
        {
            "level": "error" if diagnostic.level == "error" else "warning",
            "message": {
                "text": f"{diagnostic.file + ': ' if diagnostic.file else ''}{diagnostic.message}"
            },
        }
        for diagnostic in diagnostics
    ]
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": TOOL_VERSION,
                            "informationUri": TOOL_URI,
                            "rules": [_sarif_rule(rule) for rule in rule_list],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": not any(
                                diagnostic.level == "error" for diagnostic in diagnostics
                            ),
                            "toolExecutionNotifications": notifications,
                        }
                    ],
                    "columnKind": "unicodeCodePoints",
                    "properties": {
                        "schemaVersion": REPORT_SCHEMA_VERSION,
                        "scanComplete": not any(
                            diagnostic.level == "error" for diagnostic in diagnostics
                        ),
                        "truncated": truncated,
                        "filesConsidered": files_considered,
                        "filesScanned": files_scanned,
                        "bytesScanned": bytes_scanned,
                        "suppressedFindings": len(sorted_suppressions),
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )


# --- meta commands -----------------------------------------------------------
CATEGORY_FLAGS = {
    "credentials": "-c/--credentials",
    "sql_injection": "--sqli",
    "command_injection": "--cmd",
    "deserialization": "--deser",
    "weak_crypto": "--crypto",
    "path_traversal": "--path",
    "database_operations": "--db",
    "interesting_files": "--interesting",
}


def show_categories() -> None:
    print("Categories - stable rule IDs and filter flags:")
    for category, flag in CATEGORY_FLAGS.items():
        category_rules = [rule for rule in RULES if rule.category == category]
        severity = category_rules[0].severity if category_rules else "INFO"
        print(f"  [{severity:<6}] {category:<20} {flag}")
        for rule in category_rules:
            print(f"           - {rule.id}: {rule.description}")


def test_patterns() -> int:
    cases = (
        ('password = "SYNTH-SelfTest-A1b2C3d4"', "CREDENTIALS.PASSWORD"),
        ('query = "SELECT * FROM users WHERE id={}".format(user_id)', "SQL.FORMAT"),
        ("subprocess.run(build_command(user), shell=True)", "CMD.SUBPROCESS_SHELL"),
        ("pickle.loads(data)", "DESER.PICKLE"),
        ('MessageDigest.getInstance("MD5")', "CRYPTO.MD5"),
    )
    failures = 0
    print("Pattern self-test:")
    for index, (sample, expected_rule) in enumerate(cases, 1):
        with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8", delete=False) as handle:
            handle.write(sample)
            name = handle.name
        try:
            scanner = Scanner()
            actual = {finding.rule_id for finding in scanner.scan_file(name, "<sample>")}
        finally:
            os.unlink(name)
        passed = expected_rule in actual and not scanner.has_errors
        print(f"  {'PASS' if passed else 'FAIL'} case {index}: expected {expected_rule}")
        if not passed:
            failures += 1
    print(f"Self-test result: {len(cases) - failures}/{len(cases)} passed")
    return 0 if failures == 0 else 1


# --- CLI ---------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Source code security scanner v2.2.0 - regex-based secure review triage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnscan.py -r ./target-source/
  vulnscan.py -r --sqli --cmd ./target-source/
  vulnscan.py -r -c --min-confidence medium ./src/
  vulnscan.py -r . --base-dir . --format sarif -o out.sarif
  vulnscan.py -r ./src/ --fail-on high
  vulnscan.py -f File.java
  vulnscan.py --show-categories | --test-patterns

Suppress one rule only with a real comment, for example:
  password = load_fixture()  # nosec: CREDENTIALS.PASSWORD -- synthetic fixture
""",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    parser.add_argument("target", nargs="?", help="file or directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="recurse into subdirectories")
    parser.add_argument("-f", "--file", action="store_true", help="require target to be a single file")
    parser.add_argument("-v", "--verbose", action="store_true", help="write scanned file names to stderr")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("-o", "--output", help="write the selected report format to a file")
    parser.add_argument("--fail-on", choices=["info", "low", "medium", "high"], help="exit 1 for findings at/above this severity")
    parser.add_argument("--min-entropy", type=float, default=0.0, help="explicitly filter captured secrets below this entropy")
    parser.add_argument("--min-confidence", choices=["low", "medium", "high"], default="low", help="filter findings below this confidence")
    parser.add_argument("--no-redact", action="store_true", help="show matched secret values (unsafe for CI logs)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="normalized relative path glob to skip")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB", help="normalized relative file glob to include")
    parser.add_argument("--base-dir", help="base directory for repository-relative report paths")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE, metavar="BYTES", help="maximum source file size; 0 disables the limit")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, metavar="COUNT", help="maximum eligible files to inspect; 0 disables the limit")
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES, metavar="BYTES", help="maximum total source bytes to read; 0 disables the limit")
    parser.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS, metavar="COUNT", help="maximum active plus suppressed findings; 0 disables the limit")
    parser.add_argument("--require-suppression-reason", action="store_true", help="reject a matching nosec directive without '-- justification'")
    parser.add_argument("--fail-on-suppressed", action="store_true", help="exit 1 when one or more findings were suppressed")
    parser.add_argument("--best-effort", action="store_true", help="do not return exit 2 for operational scan errors")
    parser.add_argument("--show-categories", action="store_true", help="list stable rule IDs and exit")
    parser.add_argument("--test-patterns", action="store_true", help="run assertion-based smoke tests and exit")

    group = parser.add_argument_group("category filters (default: all)")
    group.add_argument("-c", "--credentials", action="store_true")
    group.add_argument("--sqli", action="store_true")
    group.add_argument("--cmd", action="store_true")
    group.add_argument("--deser", action="store_true")
    group.add_argument("--crypto", action="store_true")
    group.add_argument("--path", action="store_true")
    group.add_argument("--db", action="store_true")
    group.add_argument("--interesting", action="store_true")
    return parser


def selected_categories(args: argparse.Namespace) -> Optional[List[str]]:
    mapping = {
        "credentials": args.credentials,
        "sql_injection": args.sqli,
        "command_injection": args.cmd,
        "deserialization": args.deser,
        "weak_crypto": args.crypto,
        "path_traversal": args.path,
        "database_operations": args.db,
        "interesting_files": args.interesting,
    }
    selected = [category for category, enabled in mapping.items() if enabled]
    return selected or None


def _report_for(args: argparse.Namespace, result: ScanResult) -> str:
    if args.format == "json":
        return to_json(
            result.findings,
            result.diagnostics,
            result.stats.suppressed,
            result.stats.filtered,
            result.stats.files_scanned,
            result.stats.skipped_binary,
            result.stats.skipped_links,
            suppressions=result.suppressions,
            files_considered=result.stats.files_considered,
            bytes_scanned=result.stats.bytes_scanned,
            truncated=result.stats.truncated,
        )
    if args.format == "sarif":
        return to_sarif(
            result.findings,
            result.diagnostics,
            result.rules,
            suppressions=result.suppressions,
            files_considered=result.stats.files_considered,
            files_scanned=result.stats.files_scanned,
            bytes_scanned=result.stats.bytes_scanned,
            truncated=result.stats.truncated,
        )
    use_color = bool(
        _COLOR_AVAILABLE
        and not os.environ.get("NO_COLOR")
        and not args.output
        and sys.stdout.isatty()
    )
    return to_text(
        result.findings,
        result.diagnostics,
        result.stats.suppressed,
        result.stats.filtered,
        result.stats.files_scanned,
        result.stats.skipped_binary,
        result.stats.skipped_links,
        use_color,
        suppressions=result.suppressions,
        files_considered=result.stats.files_considered,
        bytes_scanned=result.stats.bytes_scanned,
        truncated=result.stats.truncated,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.show_categories:
        show_categories()
        return 0
    if args.test_patterns:
        return test_patterns()
    if not args.target:
        parser.error("a target file or directory is required")
    if args.min_entropy < 0:
        parser.error("--min-entropy must be non-negative")
    if args.max_file_size < 0:
        parser.error("--max-file-size must be non-negative")
    if args.max_files < 0:
        parser.error("--max-files must be non-negative")
    if args.max_total_bytes < 0:
        parser.error("--max-total-bytes must be non-negative")
    if args.max_findings < 0:
        parser.error("--max-findings must be non-negative")
    if not os.path.exists(args.target):
        _eprint(f"error: '{args.target}' does not exist")
        return 2
    if args.file and not os.path.isfile(args.target):
        _eprint("error: --file requires a regular file target")
        return 2
    output_abs: Optional[str] = None
    if args.output:
        output_abs = os.path.abspath(args.output)
        if _path_has_link_component(output_abs):
            _eprint(
                "error: could not write report: output path contains a symlink, "
                "junction, or reparse point"
            )
            return 2
        if os.path.isfile(args.target) and _same_file(args.target, output_abs):
            _eprint("error: could not write report: output path is the scan target")
            return 2
        if os.path.lexists(output_abs):
            if os.path.isdir(output_abs):
                reason = "output path is a directory"
            else:
                reason = "output path already exists; refusing to overwrite"
            _eprint(f"error: could not write report: {reason}")
            return 2

    categories = selected_categories(args)
    result = scan(
        ScanConfig(
            target=args.target,
            recursive=args.recursive,
            force_file=args.file,
            categories=tuple(categories) if categories else None,
            excludes=tuple(args.exclude),
            includes=tuple(args.include),
            base_dir=args.base_dir,
            min_entropy=args.min_entropy,
            min_confidence=args.min_confidence,
            redact_secrets=not args.no_redact,
            max_file_size=args.max_file_size,
            max_files=args.max_files,
            max_total_bytes=args.max_total_bytes,
            max_findings=args.max_findings,
            require_suppression_reason=args.require_suppression_reason,
        )
    )
    if args.verbose:
        for display_path in result.scanned_display_paths:
            _eprint(f"scanning: {display_path}")
    report = _report_for(args, result)

    for diagnostic in result.diagnostics:
        location = f"{diagnostic.file}: " if diagnostic.file else ""
        _eprint(f"{diagnostic.level}: {location}{diagnostic.message}")

    if args.output:
        if any(_same_file(args.output, path) for path in result.scanned_paths):
            _eprint("error: could not write report: output aliases a scanned input file")
            return 2
        write_error = _atomic_write_text(args.output, _strip_ansi(report))
        if write_error:
            _eprint(f"error: could not write report: {write_error}")
            return 2
        _eprint(f"wrote {len(result.findings)} finding(s) to {args.output}")
    else:
        print(report)

    if result.has_errors and not args.best_effort:
        return 2
    if args.fail_on_suppressed and result.suppressions:
        return 1
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(
            SEVERITY_ORDER[finding.severity] >= threshold
            for finding in result.findings
        ):
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
