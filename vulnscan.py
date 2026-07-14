#!/usr/bin/env python3
"""Source Code Security Scanner v2.1.

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
TOOL_VERSION = "2.1"
TOOL_URI = "https://github.com/Zhaoyi-Fan/source-code-security-scanner"
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024


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


def P(pattern: str, secret_group: Optional[str] = None, kinds: Sequence[str] = ()) -> PatternSpec:
    return PatternSpec(pattern=pattern, secret_group=secret_group, kinds=tuple(kinds))


CONFIG_KINDS = ("dotenv", "yaml", "config")
QUOTED_SECRET = r"(?P<quote>[\"'])(?P<secret>(?:\\.|[^\r\n\\])*?)(?P=quote)"


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
                r"\bsubprocess\s*\.\s*(?:call|run|Popen|check_call|check_output)\s*\(",
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
        (P(r"os\.system\s*\("),),
        "low",
    ),
    Rule(
        "DESER.PICKLE",
        "deserialization",
        "HIGH",
        "Python pickle deserialization",
        502,
        (P(r"pickle\.loads?\s*\("),),
    ),
    Rule(
        "DESER.YAML_LOAD",
        "deserialization",
        "HIGH",
        "yaml.load without a safe loader",
        502,
        (
            P(
                r"\byaml\s*\.\s*load\s*\(",
                kinds=("python",),
            ),
        ),
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
    r"\bnosec\s*:\s*([A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*)\b",
    re.IGNORECASE,
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PLACEHOLDER_RE = re.compile(
    r"^(?:change(?:me)?|changeme|password|passwd|secret|example|sample|dummy|test|testing|123456|qwerty|null|none|todo|replace[_-]?me)$",
    re.IGNORECASE,
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


def _safe_yaml_loader(value: ast.AST) -> bool:
    names = {"SafeLoader", "CSafeLoader", "FullLoader"}
    if isinstance(value, ast.Name):
        return value.id in names
    return (
        isinstance(value, ast.Attribute)
        and value.attr in names
        and isinstance(value.value, ast.Name)
        and value.value.id == "yaml"
    )


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
            "CMD.SUBPROCESS_SHELL": {},
            "DESER.YAML_LOAD": {},
        }
        subprocess_methods = {"call", "run", "Popen", "check_call", "check_output"}
        for index in range(max(0, len(tokens) - 3)):
            owner, dot, method, opening = tokens[index:index + 4]
            if (
                owner.type != tokenize.NAME
                or dot.string != "."
                or method.type != tokenize.NAME
                or opening.string != "("
            ):
                continue
            if owner.string not in {"subprocess", "yaml"}:
                continue
            if owner.string == "subprocess" and method.string not in subprocess_methods:
                continue
            if owner.string == "yaml" and method.string != "load":
                continue
            close_index = _token_call_end(tokens, index + 3)
            if close_index is None:
                continue
            arguments = _token_call_arguments(tokens, index + 3, close_index)
            start = _token_position(line_starts, owner.start)
            end = _token_position(line_starts, tokens[close_index].end)
            if owner.string == "subprocess":
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
            else:
                safe_loader = any(
                    len(argument) in {3, 5}
                    and argument[0].type == tokenize.NAME
                    and argument[0].string == "Loader"
                    and argument[1].string == "="
                    and (
                        (
                            len(argument) == 3
                            and argument[2].type == tokenize.NAME
                            and argument[2].string
                            in {"SafeLoader", "CSafeLoader", "FullLoader"}
                        )
                        or (
                            len(argument) == 5
                            and argument[2].string == "yaml"
                            and argument[3].string == "."
                            and argument[4].string
                            in {"SafeLoader", "CSafeLoader", "FullLoader"}
                        )
                    )
                    for argument in arguments
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
    """Index Python calls that require the two syntax-sensitive rules."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, TypeError, MemoryError):
        return _python_token_semantic_rule_offsets(content)

    line_starts, line_ends = _line_layout(content)
    offsets: Dict[str, Dict[int, Tuple[int, int]]] = {
        "CMD.SUBPROCESS_SHELL": {},
        "DESER.YAML_LOAD": {},
    }
    subprocess_methods = {"call", "run", "Popen", "check_call", "check_output"}
    try:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            owner = node.func.value
            if not isinstance(owner, ast.Name):
                continue
            offset = _ast_position(
                content,
                line_starts,
                line_ends,
                node.func.lineno,
                node.func.col_offset,
            )
            end_offset = _ast_position(
                content,
                line_starts,
                line_ends,
                getattr(node, "end_lineno", node.lineno),
                getattr(node, "end_col_offset", node.col_offset),
            )
            if owner.id == "subprocess" and node.func.attr in subprocess_methods:
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
                    suppression_end = _ast_position(
                        content,
                        line_starts,
                        line_ends,
                        getattr(shell_keyword.value, "end_lineno", shell_keyword.value.lineno),
                        getattr(
                            shell_keyword.value,
                            "end_col_offset",
                            shell_keyword.value.col_offset,
                        ),
                    )
                    offsets["CMD.SUBPROCESS_SHELL"][offset] = (
                        end_offset,
                        suppression_end,
                    )
            elif owner.id == "yaml" and node.func.attr == "load":
                safe = any(
                    keyword.arg == "Loader" and _safe_yaml_loader(keyword.value)
                    for keyword in node.keywords
                )
                if not safe:
                    offsets["DESER.YAML_LOAD"][offset] = (end_offset, end_offset)
    except (IndexError, UnicodeDecodeError, ValueError):
        # Fall back to conservative regex candidates rather than crashing or
        # silently exempting a syntax-sensitive call.
        return _python_token_semantic_rule_offsets(content)
    return offsets


def _ids_from_comment(comment: str) -> Set[str]:
    match = NOSEC_RE.search(comment)
    if not match:
        return set()
    return {part.strip().upper() for part in match.group(1).split(",") if part.strip()}


def _suppression_directives(
    content: str, kind: str, starts: Sequence[int], ends: Sequence[int]
) -> Dict[int, List[Tuple[int, Set[str]]]]:
    directives: Dict[int, List[Tuple[int, Set[str]]]] = {}
    # v2.1 enables suppressions only where the standard-library tokenizer can
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
            rule_ids = _ids_from_comment(token.string)
            if rule_ids:
                directives.setdefault(token.start[0], []).append(
                    (token.start[1], rule_ids)
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


def _credential_confidence(secret: str, entropy: float, default: str) -> str:
    stripped = secret.strip()
    if PLACEHOLDER_RE.fullmatch(stripped) or entropy < 3.0:
        return "low"
    if entropy >= 3.5:
        return "high"
    return default


# --- scanner -----------------------------------------------------------------
class Scanner:
    def __init__(
        self,
        categories: Optional[Sequence[str]] = None,
        min_entropy: float = 0.0,
        min_confidence: str = "low",
        redact_secrets: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ):
        self.categories = set(categories) if categories else None
        self.min_entropy = min_entropy
        self.min_confidence = min_confidence
        self.redact_secrets = redact_secrets
        self.max_file_size = max_file_size
        self.diagnostics: List[Diagnostic] = []
        self.suppressed_count = 0
        self.filtered_count = 0
        self.files_scanned = 0
        self.skipped_binary = 0
        self.skipped_links = 0
        self.scanned_paths: List[str] = []
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

    def _reset_run(self) -> None:
        self.diagnostics = []
        self.suppressed_count = 0
        self.filtered_count = 0
        self.files_scanned = 0
        self.skipped_binary = 0
        self.skipped_links = 0
        self.scanned_paths = []

    def _diagnose(self, message: str, file: str = "", level: str = "error") -> None:
        self.diagnostics.append(Diagnostic(level=level, message=message, file=file))

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
                self._diagnose(
                    f"file exceeds max size ({size} > {self.max_file_size} bytes)", display_path
                )
                return None
            with open(path, "rb") as handle:
                data = handle.read(self.max_file_size + 1 if self.max_file_size else -1)
            if self.max_file_size and len(data) > self.max_file_size:
                self._diagnose(
                    f"file exceeds max size after open ({len(data)} > {self.max_file_size} bytes)",
                    display_path,
                )
                return None
        except OSError as exc:
            message = getattr(exc, "strerror", None) or exc.__class__.__name__
            self._diagnose(f"could not read file: {message}", display_path)
            return None

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
        self.scanned_paths.append(os.path.abspath(path))
        content = self._read_text(path, display)
        if content is None:
            return []
        self.files_scanned += 1
        kind = _file_kind(path)
        applicable = [item for item in self.compiled if item.spec.applies_to(kind)]
        secret_spans = self._secret_spans(content, kind, applicable)
        starts, ends = _line_layout(content)
        suppression_directives = _suppression_directives(content, kind, starts, ends)
        semantic_spans = (
            _python_semantic_rule_offsets(content) if kind == "python" else {}
        )
        if semantic_spans is None:
            self._diagnose(
                "could not tokenize Python for syntax-sensitive rules; "
                "subprocess shell and YAML loader findings were not evaluated",
                display,
                level="warning",
            )
        findings: List[Finding] = []
        seen_ranges: Dict[str, List[Tuple[int, int]]] = {}

        for compiled in applicable:
            rule = compiled.rule
            if self.categories and rule.category not in self.categories:
                continue
            for match in compiled.regex.finditer(content):
                syntax_sensitive = rule.id in {
                    "CMD.SUBPROCESS_SHELL",
                    "DESER.YAML_LOAD",
                }
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
                suppressed = False
                for directive_line in range(line, suppression_end_line + 1):
                    line_index = directive_line - 1
                    matched_through_column = (
                        min(suppression_end, ends[line_index]) - starts[line_index]
                    )
                    if any(
                        comment_column >= matched_through_column
                        and rule.id.upper() in rule_ids
                        for comment_column, rule_ids in suppression_directives.get(
                            directive_line, []
                        )
                    ):
                        suppressed = True
                        break
                if suppressed:
                    self.suppressed_count += 1
                    continue

                entropy = 0.0
                confidence = rule.confidence
                group = compiled.spec.secret_group
                if group:
                    secret = match.group(group).strip()
                    entropy_value = shannon_entropy(secret)
                    entropy = round(entropy_value, 2)
                    if entropy_value < self.min_entropy:
                        self.filtered_count += 1
                        continue
                    confidence = _credential_confidence(secret, entropy_value, confidence)
                if CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[self.min_confidence]:
                    self.filtered_count += 1
                    continue

                end_column = end_column_base + 1
                if self.redact_secrets:
                    shown_match = _redact_range(
                        content, match_start, match_end, secret_spans
                    )
                    context = _redact_range(content, line_start, line_end, secret_spans)
                else:
                    shown_match = content[match_start:match_end]
                    context = line_text
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        file=display,
                        line=line,
                        column=column,
                        end_line=end_line,
                        end_column=end_column,
                        match=_safe_excerpt(shown_match),
                        context=_safe_excerpt(context.strip()),
                        confidence=confidence,
                        entropy=entropy,
                        cwe=rule.cwe,
                    )
                )
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
                if verbose:
                    _eprint(f"scanning: {display}")
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

        def scan_candidate(path: str) -> None:
            display = display_path(path)
            if _is_link_or_junction(path):
                self.skipped_links += 1
                return
            if not _contained(root_real, path):
                self._diagnose("resolved path escapes scan root", display)
                return
            if not eligible(path, display):
                return
            if verbose:
                _eprint(f"scanning: {display}")
            findings.extend(self.scan_file(path, display))

        if not recursive:
            try:
                with os.scandir(target_abs) as entries:
                    for entry in entries:
                        if entry.is_file(follow_symlinks=False):
                            scan_candidate(entry.path)
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
            for directory in dirs:
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
            for filename in files:
                scan_candidate(os.path.join(root, filename))
        return findings


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
) -> Dict[str, int]:
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in SEVERITY_ORDER}
    return {
        "total": len(findings),
        **counts,
        "scan_errors": sum(1 for diagnostic in diagnostics if diagnostic.level == "error"),
        "suppressed": suppressed,
        "filtered": filtered,
        "files_scanned": files_scanned,
        "skipped_binary": skipped_binary,
        "skipped_links": skipped_links,
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
        findings, diagnostics, suppressed, filtered, files_scanned, skipped_binary, skipped_links
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
) -> str:
    return json.dumps(
        {
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
            ),
            "diagnostics": [asdict(diagnostic) for diagnostic in diagnostics],
            "findings": [asdict(finding) for finding in sorted(findings, key=lambda item: item.sort_key())],
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


def to_sarif(
    findings: Sequence[Finding],
    diagnostics: Sequence[Diagnostic] = (),
    rules: Sequence[Rule] = RULES,
) -> str:
    sorted_findings = sorted(findings, key=lambda item: item.sort_key())
    rule_list = list(rules)
    rule_index = {rule.id: index for index, rule in enumerate(rule_list)}
    results: List[Dict[str, object]] = []
    for finding in sorted_findings:
        region: Dict[str, int] = {
            "startLine": finding.line,
            "startColumn": finding.column,
            "endLine": finding.end_line,
            "endColumn": finding.end_column,
        }
        results.append(
            {
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
                },
            }
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
        prog="vulnscan.py",
        description="Source code security scanner v2.1 - regex-based secure review triage.",
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
  password = load_fixture()  # nosec: CREDENTIALS.PASSWORD
""",
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


def _report_for(args: argparse.Namespace, scanner: Scanner, findings: Sequence[Finding]) -> str:
    if args.format == "json":
        return to_json(
            findings,
            scanner.diagnostics,
            scanner.suppressed_count,
            scanner.filtered_count,
            scanner.files_scanned,
            scanner.skipped_binary,
            scanner.skipped_links,
        )
    if args.format == "sarif":
        return to_sarif(findings, scanner.diagnostics, scanner.active_rules)
    use_color = bool(
        _COLOR_AVAILABLE
        and not os.environ.get("NO_COLOR")
        and not args.output
        and sys.stdout.isatty()
    )
    return to_text(
        findings,
        scanner.diagnostics,
        scanner.suppressed_count,
        scanner.filtered_count,
        scanner.files_scanned,
        scanner.skipped_binary,
        scanner.skipped_links,
        use_color,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
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

    scanner = Scanner(
        categories=selected_categories(args),
        min_entropy=args.min_entropy,
        min_confidence=args.min_confidence,
        redact_secrets=not args.no_redact,
        max_file_size=args.max_file_size,
    )
    findings = scanner.scan_path(
        args.target,
        recursive=args.recursive,
        excludes=args.exclude,
        includes=args.include,
        verbose=args.verbose,
        base_dir=args.base_dir,
        force_file=args.file,
    )
    report = _report_for(args, scanner, findings)

    for diagnostic in scanner.diagnostics:
        location = f"{diagnostic.file}: " if diagnostic.file else ""
        _eprint(f"{diagnostic.level}: {location}{diagnostic.message}")

    if args.output:
        if any(_same_file(args.output, path) for path in scanner.scanned_paths):
            _eprint("error: could not write report: output aliases a scanned input file")
            return 2
        write_error = _atomic_write_text(args.output, _strip_ansi(report))
        if write_error:
            _eprint(f"error: could not write report: {write_error}")
            return 2
        _eprint(f"wrote {len(findings)} finding(s) to {args.output}")
    else:
        print(report)

    if scanner.has_errors and not args.best_effort:
        return 2
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
