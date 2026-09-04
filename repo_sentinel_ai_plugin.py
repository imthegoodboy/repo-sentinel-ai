"""Read-only GitHub repository auditor for RepoSentinel AI.

The tool downloads an authorized repository snapshot from GitHub, inventories
every archive member, and statically inspects supported text files. Public
repositories work without a credential. A user-managed GitHub credential adds
their repository picker and private-repository access. Repository code is never
executed. Responses are deliberately bounded so large repositories do not
overflow Anna's tool or model context limits.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import time
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


TOOL_ID = "tool-dev-repo-sentinel-ai"
TOOL_METHOD = "repository.audit"
STATUS_METHOD = "github.connection_status"
REPOSITORIES_METHOD = "github.repositories"
VERSION = "1.0.0"

MAX_ARCHIVE_BYTES = 25_000_000
MAX_UNCOMPRESSED_BYTES = 80_000_000
MAX_ARCHIVE_FILES = 10_000
MAX_SINGLE_FILE_BYTES = 750_000
MAX_TEXT_BYTES = 35_000_000
MAX_FINDINGS = 120
MAX_RETURNED_FINDINGS = 40
NETWORK_TIMEOUT_SECONDS = 25

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".conf", ".cpp", ".cs", ".css", ".env", ".go", ".h",
    ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".kt",
    ".kts", ".lua", ".mjs", ".php", ".properties", ".py", ".rb", ".rs",
    ".hcl", ".key", ".pem", ".ps1", ".sh", ".sql", ".svelte", ".swift",
    ".tf", ".toml", ".ts", ".tsx", ".vue",
    ".xml", ".yaml", ".yml",
}
SPECIAL_TEXT_FILES = {
    ".dockerignore", ".env", ".gitignore", "dockerfile", "gemfile", "go.mod", "go.sum",
    "makefile", "package-lock.json", "package.json", "pnpm-lock.yaml", "poetry.lock",
    "pyproject.toml", "requirements.txt", "security.md", "yarn.lock",
}
EXCLUDED_DIRS = {
    ".git", ".hg", ".idea", ".next", ".nuxt", ".svn", ".turbo", ".venv",
    "__pycache__", "bower_components", "build", "coverage", "dist", "node_modules",
    "target", "vendor", "venv",
}
GENERATED_SUFFIXES = (".bundle.js", ".min.css", ".min.js", ".map")
GENERATED_MIRROR_DIRS = {"bundle"}

LANGUAGES = {
    ".c": "C", ".cc": "C++", ".cpp": "C++", ".cs": "C#", ".css": "CSS",
    ".go": "Go", ".h": "C/C++", ".hpp": "C++", ".html": "HTML",
    ".java": "Java", ".js": "JavaScript", ".jsx": "JavaScript",
    ".kt": "Kotlin", ".kts": "Kotlin", ".lua": "Lua", ".mjs": "JavaScript",
    ".php": "PHP", ".py": "Python", ".rb": "Ruby", ".rs": "Rust",
    ".sh": "Shell", ".sql": "SQL", ".svelte": "Svelte", ".swift": "Swift",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".vue": "Vue",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    explanation: str
    recommendation: str
    confidence: str = "medium"
    extensions: tuple[str, ...] = ()
    redact: bool = False


RULES = (
    Rule(
        "secret.private-key", "Private key material committed", "critical", "Secrets",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "A private-key header is present in a tracked file and could grant unauthorized access.",
        "Revoke and rotate the key, remove it from history, and load replacements from a secret manager.",
        "high", redact=True,
    ),
    Rule(
        "secret.github-token", "GitHub access token pattern", "critical", "Secrets",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"),
        "The line contains a value shaped like a GitHub credential.",
        "Revoke the token immediately, purge it from repository history, and use a secret store.",
        "high", redact=True,
    ),
    Rule(
        "secret.aws-key", "AWS access-key pattern", "critical", "Secrets",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "The line contains a value shaped like an AWS access key identifier.",
        "Disable and rotate the credential, review access logs, and move credentials to workload identity or a secret store.",
        "high", redact=True,
    ),
    Rule(
        "crypto.tls-disabled", "TLS certificate verification disabled", "high", "Transport",
        re.compile(r"(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE|InsecureSkipVerify\s*:\s*true)"),
        "Disabling certificate verification allows an attacker to impersonate the remote service.",
        "Restore certificate validation and configure the correct trusted CA instead of bypassing TLS checks.",
        "high",
    ),
    Rule(
        "auth.jwt-no-verification", "JWT signature verification disabled", "critical", "Authentication",
        re.compile(r"(?:verify_signature[\"']?\s*[:=]\s*False|algorithms?\s*[:=]\s*[\"']none[\"']|verify\s*:\s*false)"),
        "A token may be accepted without proving who signed it.",
        "Require signature verification, pin allowed algorithms, and validate issuer, audience, and expiry.",
        "medium", extensions=(".py", ".js", ".ts", ".jsx", ".tsx"),
    ),
    Rule(
        "code.python-shell", "Shell command execution enabled", "high", "Command execution",
        re.compile(r"(?:subprocess\.(?:run|call|Popen)|check_(?:call|output))\s*\([^\n]*shell\s*=\s*True"),
        "Commands executed through a shell may become injectable when any argument is influenced by external input.",
        "Pass an argument array with shell disabled and validate every externally controlled value.",
        "high", extensions=(".py",),
    ),
    Rule(
        "code.os-system", "Direct operating-system command execution", "high", "Command execution",
        re.compile(r"\bos\.system\s*\("),
        "Direct shell execution is difficult to make safe when values are constructed dynamically.",
        "Replace it with a subprocess argument array and a strict allowlist of commands and arguments.",
        "medium", extensions=(".py",),
    ),
    Rule(
        "code.node-shell", "Node.js shell command execution", "high", "Command execution",
        re.compile(r"(?:child_process\s*\.\s*)?(?:exec|execSync)\s*\("),
        "Shell command execution can become injectable when command text includes externally controlled values.",
        "Prefer spawn or execFile with an argument array, disable shell parsing, and validate every external value.",
        "medium", extensions=(".js", ".jsx", ".mjs", ".ts", ".tsx"),
    ),
    Rule(
        "code.powershell-expression", "Dynamic PowerShell expression execution", "high", "Command execution",
        re.compile(r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE),
        "Dynamic PowerShell evaluation can execute untrusted command text.",
        "Replace expression evaluation with direct cmdlet calls and validate arguments against a strict allowlist.",
        "high", extensions=(".ps1",),
    ),
    Rule(
        "code.dynamic-eval", "Dynamic code evaluation", "high", "Code execution",
        re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        "Dynamic evaluation can turn untrusted strings into executable code.",
        "Use a parser or an explicit command map; never evaluate user-controlled text.",
        "medium", extensions=(".py", ".js", ".ts", ".jsx", ".tsx"),
    ),
    Rule(
        "serialization.pickle", "Unsafe Python deserialization", "high", "Deserialization",
        re.compile(r"\b(?:pickle|dill)\.loads?\s*\("),
        "Pickle-compatible payloads can execute code while being deserialized.",
        "Use JSON or another non-executable format and validate the resulting schema.",
        "high", extensions=(".py",),
    ),
    Rule(
        "serialization.yaml-load", "Potentially unsafe YAML loading", "high", "Deserialization",
        re.compile(r"\byaml\.load\s*\((?![^\n]*(?:SafeLoader|safe_load))"),
        "A permissive YAML loader can construct attacker-controlled objects.",
        "Use yaml.safe_load or explicitly select a safe loader.",
        "medium", extensions=(".py",),
    ),
    Rule(
        "web.raw-html", "Raw HTML injection surface", "medium", "Cross-site scripting",
        re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\s*=)"),
        "This API bypasses normal output escaping and becomes exploitable if the value contains untrusted content.",
        "Prefer text rendering. If HTML is required, sanitize it with a maintained allowlist-based sanitizer.",
        "medium", extensions=(".js", ".jsx", ".ts", ".tsx", ".vue", ".html"),
    ),
    Rule(
        "web.document-write", "Document.write usage", "medium", "Cross-site scripting",
        re.compile(r"\bdocument\.write(?:ln)?\s*\("),
        "Writing strings directly into the document can create an injection sink and disrupt page parsing.",
        "Use DOM APIs that preserve text escaping and avoid injecting raw markup.",
        "high", extensions=(".js", ".jsx", ".ts", ".tsx", ".html"),
    ),
    Rule(
        "database.sql-interpolation", "SQL built with string interpolation", "high", "Injection",
        re.compile(r"(?:execute|query)\s*\(\s*(?:f[\"']|`[^`]*\$\{|[\"'][^\"']*%[s(])", re.IGNORECASE),
        "Values appear to be interpolated into a database query instead of bound as parameters.",
        "Use the database driver's parameterized-query API and keep SQL structure separate from values.",
        "medium", extensions=(".py", ".js", ".ts", ".rb", ".php", ".java"),
    ),
    Rule(
        "crypto.weak-hash", "Weak cryptographic hash", "medium", "Cryptography",
        re.compile(r"(?:createHash\s*\(\s*[\"'](?:md5|sha1)[\"']|hashlib\.(?:md5|sha1)\s*\()", re.IGNORECASE),
        "MD5 and SHA-1 are unsuitable for passwords, signatures, and collision-resistant security decisions.",
        "Use a modern password KDF for passwords or SHA-256/stronger where a general-purpose hash is appropriate.",
        "high", extensions=(".py", ".js", ".ts", ".jsx", ".tsx"),
    ),
    Rule(
        "config.debug-enabled", "Production debug mode may be enabled", "medium", "Configuration",
        re.compile(r"(?:\bDEBUG\s*=\s*True\b|\bdebug\s*:\s*true\b|app\.run\([^\n]*debug\s*=\s*True)"),
        "Debug mode can expose stack traces, internal state, or development-only behavior.",
        "Make debug mode environment-specific and default it to disabled outside local development.",
        "medium", extensions=(".py", ".yaml", ".yml", ".json", ".toml"),
    ),
    Rule(
        "cors.wildcard", "Wildcard CORS policy", "medium", "Authorization boundary",
        re.compile(r"(?:Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']|allow_origins\s*=\s*\[[\"']\*[\"']\])", re.IGNORECASE),
        "A wildcard origin allows any website to read responses that do not require credentials.",
        "Restrict allowed origins to the known frontend domains and review whether credentials are enabled.",
        "medium",
    ),
    Rule(
        "cloud.iam-wildcard-action", "Wildcard cloud permission", "high", "Cloud authorization",
        re.compile(r"(?:[\"']Action[\"']|\bAction)\s*[:=]\s*[\"']\*[\"']", re.IGNORECASE),
        "A wildcard action can grant substantially more cloud access than the workload requires.",
        "Replace the wildcard with the smallest required action set and verify the resource scope.",
        "high", extensions=(".json", ".tf", ".hcl", ".yaml", ".yml"),
    ),
)


MANIFEST = {
    "name": TOOL_ID,
    "display_name": "RepoSentinel Read-only Auditor",
    "version": VERSION,
    "description": "Downloads and statically audits bounded GitHub repository snapshots without executing repository code.",
    "author": "RepoSentinel AI",
    "credentials": [
        {
            "name": "GITHUB_TOKEN",
            "display_name": "GitHub connection",
            "description": "Optional fine-grained GitHub token. Grant read-only Metadata and Contents access only to repositories you want RepoSentinel to audit.",
            "required": False,
            "sensitive": True,
        }
    ],
    "tools": [
        {
            "name": TOOL_METHOD,
            "description": "Audit an authorized GitHub repository snapshot and return a bounded evidence report. Public repositories work without a GitHub connection.",
            "parameters": [
                {"name": "url", "type": "string", "description": "GitHub repository URL or owner/repository.", "required": True},
                {"name": "branch", "type": "string", "description": "Optional branch or tag. Defaults to the repository default branch.", "required": False},
            ],
        },
        {
            "name": STATUS_METHOD,
            "description": "Check whether the current Anna user has connected GitHub for RepoSentinel. Never returns a credential.",
            "parameters": [],
        },
        {
            "name": REPOSITORIES_METHOD,
            "description": "List up to 200 repositories visible to the user's connected GitHub account for selection in RepoSentinel. Never returns repository contents or a credential.",
            "parameters": [],
        },
    ],
}


class AuditError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def parse_github_repository(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        owner, repo = raw.split("/", 1)
    else:
        try:
            parsed = urlparse(raw)
        except ValueError as exc:
            raise AuditError("INVALID_REPOSITORY", "Enter a valid GitHub repository URL.") from exc
        host = (parsed.hostname or "").lower().removeprefix("www.")
        parts = [part for part in parsed.path.split("/") if part]
        if host != "github.com" or len(parts) < 2:
            raise AuditError("INVALID_REPOSITORY", "Enter a github.com owner/repository URL.")
        owner, repo = parts[0], parts[1]
    repo = repo.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
        raise AuditError("INVALID_REPOSITORY", "The GitHub owner or repository name is invalid.")
    return owner, repo


def _github_token(credentials: dict[str, Any] | None) -> str:
    value = str((credentials or {}).get("GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
    return value


def _github_headers(token: str = "", accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {
        "Accept": accept,
        "User-Agent": "RepoSentinel-Anna/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request_json(url: str, token: str = "") -> Any:
    request = Request(url, headers=_github_headers(token))
    with urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed GitHub origin
        return json.loads(response.read(2_000_000).decode("utf-8"))


def _download_bounded(url: str, token: str = "") -> bytes:
    request = Request(url, headers=_github_headers(token, "application/vnd.github+json"))
    with urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed GitHub origin
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(256_000)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise AuditError("REPOSITORY_TOO_LARGE", f"The compressed repository exceeds the {MAX_ARCHIVE_BYTES // 1_000_000} MB scan limit.")
            chunks.append(chunk)
        return b"".join(chunks)


def _safe_relative_path(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    parts = path.parts[1:] if len(path.parts) > 1 else path.parts
    if not parts:
        return None
    return "/".join(parts)


def _is_supported(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix.lower() in SOURCE_EXTENSIONS or pure.name.lower() in SPECIAL_TEXT_FILES


def _excluded_reason(path: str) -> str | None:
    parts = {part.lower() for part in PurePosixPath(path).parts[:-1]}
    if parts & EXCLUDED_DIRS:
        return "dependency or build output"
    lowered = path.lower()
    if lowered.endswith(GENERATED_SUFFIXES):
        return "generated or minified"
    return None


def _language(path: str) -> str:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower(), "Configuration")


def _redact(text: str) -> str:
    compact = text.strip().replace("\t", "  ")[:220]
    for rule in RULES:
        if rule.redact:
            compact = rule.pattern.sub("[REDACTED CREDENTIAL]", compact)
    return compact


def _finding(rule: Rule, path: str, line_number: int, line: str) -> dict[str, Any]:
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{path}:{line_number}".encode()).hexdigest()[:16]
    return {
        "id": f"finding-{fingerprint}", "ruleId": rule.rule_id, "title": rule.title,
        "severity": rule.severity, "category": rule.category, "path": path, "line": line_number,
        "snippet": _redact(line), "explanation": rule.explanation, "recommendation": rule.recommendation,
        "confidence": rule.confidence, "verification": "Pattern confirmed; exploitability requires contextual review.",
        "fingerprint": fingerprint,
    }


def _scan_text(path: str, text: str) -> list[dict[str, Any]]:
    suffix = PurePosixPath(path).suffix.lower()
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith(("// example", "# example")):
            continue
        for rule in RULES:
            if rule.extensions and suffix not in rule.extensions:
                continue
            if rule.pattern.search(line):
                findings.append(_finding(rule, path, line_number, line))
                if len(findings) >= MAX_FINDINGS:
                    return findings
    return findings


def _is_generated_mirror(path: str) -> bool:
    return bool({part.lower() for part in PurePosixPath(path).parts[:-1]} & GENERATED_MIRROR_DIRS)


def _collapse_generated_duplicates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group an exact generated-bundle mirror under its single authored location.

    Identical patterns in two authored files remain separate. We collapse only
    when one authored occurrence has one or more exact generated mirrors.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        key = (str(finding.get("ruleId") or ""), str(finding.get("snippet") or ""))
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)

    collapsed: list[dict[str, Any]] = []
    for key in order:
        matches = grouped[key]
        authored = [item for item in matches if not _is_generated_mirror(str(item.get("path") or ""))]
        generated = [item for item in matches if _is_generated_mirror(str(item.get("path") or ""))]
        if len(authored) == 1 and generated:
            primary = dict(authored[0])
            primary["relatedLocations"] = [
                {"path": str(item.get("path") or ""), "line": max(1, int(item.get("line") or 1))}
                for item in generated
            ]
            primary["totalOccurrences"] = 1 + len(generated)
            collapsed.append(primary)
        else:
            for item in matches:
                normalized = dict(item)
                normalized["relatedLocations"] = []
                normalized["totalOccurrences"] = 1
                collapsed.append(normalized)
    return collapsed


def _framework_hints(path: str, text: str) -> set[str]:
    hints: set[str] = set()
    lowered = text.lower()
    if path.endswith("package.json"):
        for dependency, label in {"react": "React", "next": "Next.js", "express": "Express", "fastify": "Fastify", "vue": "Vue", "svelte": "Svelte"}.items():
            if f'"{dependency}"' in lowered:
                hints.add(label)
    if path.endswith(("requirements.txt", "pyproject.toml")):
        for dependency, label in {"django": "Django", "flask": "Flask", "fastapi": "FastAPI"}.items():
            if dependency in lowered:
                hints.add(label)
    if path.endswith("go.mod"):
        hints.add("Go modules")
    return hints


def audit_archive(repository: dict[str, Any], archive: bytes, branch: str, commit_sha: str = "") -> dict[str, Any]:
    started = time.monotonic()
    try:
        zipped = zipfile.ZipFile(io.BytesIO(archive))
    except (zipfile.BadZipFile, OSError) as exc:
        raise AuditError("INVALID_ARCHIVE", "GitHub returned an unreadable repository archive.") from exc

    infos = [info for info in zipped.infolist() if not info.is_dir()]
    if len(infos) > MAX_ARCHIVE_FILES:
        raise AuditError("REPOSITORY_TOO_LARGE", f"The repository contains more than {MAX_ARCHIVE_FILES:,} files.")
    uncompressed = sum(max(0, info.file_size) for info in infos)
    if uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise AuditError("REPOSITORY_TOO_LARGE", f"The extracted repository exceeds the {MAX_UNCOMPRESSED_BYTES // 1_000_000} MB scan limit.")

    excluded = Counter()
    language_files = Counter()
    language_lines = Counter()
    findings: list[dict[str, Any]] = []
    manifests: list[str] = []
    entry_points: list[str] = []
    security_files: list[str] = []
    top_directories = Counter()
    framework_hints: set[str] = set()
    all_paths: set[str] = set()
    scanned_files = text_bytes = total_lines = tests = source_files = 0
    truncated = False

    for info in infos:
        path = _safe_relative_path(info.filename)
        if not path:
            excluded["unsafe archive path"] += 1
            continue
        all_paths.add(path.lower())
        top_directories[path.split("/", 1)[0]] += 1
        reason = _excluded_reason(path)
        if reason:
            excluded[reason] += 1
            continue
        if not _is_supported(path):
            excluded["unsupported or binary"] += 1
            continue
        if info.file_size > MAX_SINGLE_FILE_BYTES:
            excluded["individual file over limit"] += 1
            continue
        if text_bytes + info.file_size > MAX_TEXT_BYTES:
            excluded["repository text budget reached"] += 1
            truncated = True
            continue
        try:
            raw = zipped.read(info)
        except (RuntimeError, zipfile.BadZipFile):
            excluded["unreadable archive member"] += 1
            continue
        if b"\x00" in raw[:8192]:
            excluded["unsupported or binary"] += 1
            continue
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            excluded["non UTF-8 text"] += 1
            continue

        scanned_files += 1
        text_bytes += len(raw)
        line_count = text.count("\n") + (1 if text else 0)
        total_lines += line_count
        language = _language(path)
        language_files[language] += 1
        language_lines[language] += line_count
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in LANGUAGES:
            source_files += 1
        lower_path = path.lower()
        base = PurePosixPath(lower_path).name
        if base in SPECIAL_TEXT_FILES or base in {"composer.json", "cargo.toml"}:
            manifests.append(path)
        if base.startswith("test_") or "/test" in lower_path or ".test." in lower_path or ".spec." in lower_path:
            tests += 1
        if base in {"main.py", "app.py", "server.py", "index.js", "index.ts", "main.go", "main.rs"} or lower_path.startswith(("src/main", "app/")):
            if len(entry_points) < 20:
                entry_points.append(path)
        if re.search(r"(?:^|/)(?:auth|security|permission|access|session|oauth|jwt)[^/]*", lower_path):
            if len(security_files) < 20:
                security_files.append(path)
        framework_hints.update(_framework_hints(path, text))

        if len(findings) < MAX_FINDINGS:
            findings.extend(_scan_text(path, text)[: MAX_FINDINGS - len(findings)])
        if base == ".env" or (lower_path.endswith("/.env") and not lower_path.endswith((".env.example", ".env.sample"))):
            synthetic = Rule(
                "secret.env-file", "Environment file committed", "high", "Secrets", re.compile(".*"),
                "A tracked .env file commonly contains deployment credentials or private configuration.",
                "Remove it from version control, rotate any real credentials, and commit only a documented example file.",
                "high", redact=True,
            )
            findings.append(_finding(synthetic, path, 1, "[contents intentionally not displayed]"))

    package_manifests = [path for path in manifests if path.lower().endswith("package.json")]
    lock_names = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "go.sum"}
    if package_manifests and not any(PurePosixPath(path).name in lock_names for path in all_paths):
        findings.append({
            "id": "finding-lockfile-missing", "ruleId": "supply-chain.no-lockfile", "title": "Dependency lockfile not detected",
            "severity": "low", "category": "Supply chain", "path": package_manifests[0], "line": 1, "snippet": "package.json",
            "explanation": "Without a committed lockfile, repeated installs may resolve different dependency versions.",
            "recommendation": "Generate and commit the package manager's lockfile and use reproducible installs in CI.",
            "confidence": "high", "verification": "Repository-level inventory check.", "fingerprint": "lockfile-missing",
        })

    findings = _collapse_generated_duplicates(findings)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = sorted(findings, key=lambda item: (severity_rank.get(item["severity"], 9), item["path"], item["line"]))
    severity_counts = Counter(item["severity"] for item in findings)
    penalty = min(100, severity_counts["critical"] * 26 + severity_counts["high"] * 14 + severity_counts["medium"] * 6 + severity_counts["low"] * 2)
    score = max(0, 100 - penalty)
    coverage_denominator = max(1, len(infos))
    languages = [
        {"name": name, "files": language_files[name], "lines": language_lines[name], "percent": round(language_lines[name] * 100 / max(1, total_lines), 1)}
        for name in sorted(language_lines, key=language_lines.get, reverse=True)
    ][:10]

    owner = str(repository.get("owner") or "")
    name = str(repository.get("name") or "")
    return {
        "ok": True,
        "repository": {
            "owner": owner, "name": name, "fullName": f"{owner}/{name}", "url": f"https://github.com/{owner}/{name}",
            "description": str(repository.get("description") or "")[:280], "defaultBranch": str(repository.get("default_branch") or branch),
            "branch": branch, "commitSha": commit_sha[:12], "stars": int(repository.get("stargazers_count") or 0),
            "isFork": bool(repository.get("fork")), "private": bool(repository.get("private")),
            "accessMode": str(repository.get("access_mode") or "public"),
            "scannedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "health": {
            "score": score, "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
            "severityCounts": {level: severity_counts[level] for level in ("critical", "high", "medium", "low")},
        },
        "stats": {
            "filesDiscovered": len(infos), "filesScanned": scanned_files, "filesExcluded": sum(excluded.values()),
            "uncompressedBytes": uncompressed, "textBytesScanned": text_bytes, "linesScanned": total_lines,
            "sourceFiles": source_files, "testFiles": tests, "findingCandidates": len(findings),
            "durationMs": round((time.monotonic() - started) * 1000), "languages": languages,
        },
        "coverage": {
            "archiveInventoryPercent": 100, "supportedScanPercent": round(scanned_files * 100 / coverage_denominator, 1),
            "returnedFindingCount": min(len(findings), MAX_RETURNED_FINDINGS), "totalFindingCount": len(findings),
            "truncated": truncated or len(findings) > MAX_RETURNED_FINDINGS,
            "excluded": [{"reason": reason, "count": count} for reason, count in excluded.most_common()],
        },
        "architecture": {
            "frameworkHints": sorted(framework_hints), "manifests": sorted(manifests)[:30], "entryPoints": sorted(set(entry_points))[:20],
            "securityFiles": sorted(set(security_files))[:20], "topDirectories": [name for name, _ in top_directories.most_common(12)],
        },
        "findings": findings[:MAX_RETURNED_FINDINGS],
        "limits": {
            "archiveBytes": MAX_ARCHIVE_BYTES, "uncompressedBytes": MAX_UNCOMPRESSED_BYTES, "archiveFiles": MAX_ARCHIVE_FILES,
            "singleFileBytes": MAX_SINGLE_FILE_BYTES, "textBytes": MAX_TEXT_BYTES, "returnedFindings": MAX_RETURNED_FINDINGS,
            "repositoryCodeExecuted": False,
        },
    }


def github_connection_status(credentials: dict[str, Any] | None = None) -> dict[str, Any]:
    token = _github_token(credentials)
    if not token:
        return {"ok": True, "connected": False, "account": None}
    try:
        user = _request_json("https://api.github.com/user", token)
    except HTTPError as exc:
        if exc.code == 401:
            return {"ok": True, "connected": False, "account": None, "needsReconnect": True}
        if exc.code == 403:
            raise AuditError("GITHUB_FORBIDDEN", "GitHub refused the connection check. Review the credential's repository access or SSO authorization.") from exc
        raise AuditError("GITHUB_ERROR", f"GitHub returned HTTP {exc.code} while checking the connection.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AuditError("NETWORK_ERROR", "GitHub could not be reached while checking the connection.") from exc
    return {
        "ok": True,
        "connected": True,
        "account": {
            "login": str(user.get("login") or ""),
            "name": str(user.get("name") or "")[:120],
            "avatarUrl": str(user.get("avatar_url") or ""),
        },
    }


def list_github_repositories(credentials: dict[str, Any] | None = None) -> dict[str, Any]:
    token = _github_token(credentials)
    if not token:
        return {"ok": True, "connected": False, "repositories": []}
    repositories: list[dict[str, Any]] = []
    try:
        for page in (1, 2):
            batch = _request_json(
                f"https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&sort=updated&direction=desc&per_page=100&page={page}",
                token,
            )
            if not isinstance(batch, list):
                raise AuditError("GITHUB_RESPONSE", "GitHub returned an unexpected repository list.")
            for repository in batch:
                owner = repository.get("owner") or {}
                repositories.append({
                    "id": str(repository.get("id") or ""),
                    "name": str(repository.get("name") or "")[:120],
                    "fullName": str(repository.get("full_name") or "")[:240],
                    "owner": str(owner.get("login") or "")[:120],
                    "url": str(repository.get("html_url") or ""),
                    "description": str(repository.get("description") or "")[:280],
                    "private": bool(repository.get("private")),
                    "archived": bool(repository.get("archived")),
                    "defaultBranch": str(repository.get("default_branch") or "main")[:160],
                    "language": str(repository.get("language") or "")[:80],
                    "updatedAt": str(repository.get("updated_at") or ""),
                    "stars": int(repository.get("stargazers_count") or 0),
                })
            if len(batch) < 100:
                break
    except HTTPError as exc:
        if exc.code == 401:
            return {"ok": True, "connected": False, "repositories": [], "needsReconnect": True}
        if exc.code == 403:
            raise AuditError("GITHUB_FORBIDDEN", "GitHub refused the repository list. Review the credential's repository access or SSO authorization.") from exc
        raise AuditError("GITHUB_ERROR", f"GitHub returned HTTP {exc.code} while listing repositories.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AuditError("NETWORK_ERROR", "GitHub could not be reached while listing repositories.") from exc
    return {"ok": True, "connected": True, "repositories": repositories, "truncated": len(repositories) >= 200}


def audit_repository(args: dict[str, Any], credentials: dict[str, Any] | None = None) -> dict[str, Any]:
    owner, repo = parse_github_repository(str(args.get("url") or ""))
    token = _github_token(credentials)
    branch_arg = str(args.get("branch") or "").strip()
    if branch_arg and (len(branch_arg) > 160 or re.search(r"[\x00-\x1f]", branch_arg)):
        raise AuditError("INVALID_BRANCH", "The branch or tag name is invalid.")
    api_base = f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}"
    try:
        metadata = _request_json(api_base, token)
    except HTTPError as exc:
        if exc.code == 404:
            raise AuditError("NOT_FOUND", "The repository was not found or is not available to the connected GitHub account.") from exc
        if exc.code == 403:
            raise AuditError("GITHUB_RATE_LIMIT", "GitHub temporarily refused the anonymous request. Please retry later.") from exc
        raise AuditError("GITHUB_ERROR", f"GitHub returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AuditError("NETWORK_ERROR", "GitHub could not be reached within the scan timeout.") from exc

    if bool(metadata.get("private")) and not token:
        raise AuditError("PRIVATE_REPOSITORY", "Connect GitHub in Anna to audit a private repository.")
    branch = branch_arg or str(metadata.get("default_branch") or "main")
    commit_sha = ""
    try:
        commit = _request_json(f"{api_base}/commits/{quote(branch, safe='')}", token)
        commit_sha = str(commit.get("sha") or "")
    except Exception:
        commit_sha = ""

    archive_url = (
        f"{api_base}/zipball/{quote(branch, safe='')}"
        if token
        else f"https://codeload.github.com/{quote(owner)}/{quote(repo)}/zip/{quote(branch, safe='')}"
    )
    try:
        archive = _download_bounded(archive_url, token)
    except HTTPError as exc:
        if exc.code == 404:
            raise AuditError("BRANCH_NOT_FOUND", "That branch or tag was not found.") from exc
        raise AuditError("DOWNLOAD_ERROR", f"GitHub archive download returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AuditError("NETWORK_ERROR", "The repository archive could not be downloaded within the timeout.") from exc

    repository = {
        "owner": owner, "name": repo, "description": metadata.get("description"), "default_branch": metadata.get("default_branch"),
        "stargazers_count": metadata.get("stargazers_count"), "fork": metadata.get("fork"),
        "private": bool(metadata.get("private")), "access_mode": "connected" if token else "public",
    }
    return audit_archive(repository, archive, branch, commit_sha)


def invoke(method: str, args: dict[str, Any], credentials: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        if method == TOOL_METHOD:
            data = audit_repository(args, credentials)
        elif method == STATUS_METHOD:
            data = github_connection_status(credentials)
        elif method == REPOSITORIES_METHOD:
            data = list_github_repositories(credentials)
        else:
            return {"success": False, "error": f"unknown method: {method}"}
        return {"success": True, "data": data}
    except AuditError as exc:
        return {"success": True, "data": {"ok": False, "code": exc.code, "message": exc.message}}
    except Exception as exc:
        return {"success": True, "data": {"ok": False, "code": "AUDIT_ERROR", "message": f"Audit failed safely: {type(exc).__name__}."}}


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}
    if method == "initialize":
        offered = str(params.get("protocolVersion") or "1.1")
        result = {
            "protocolVersion": offered if offered in {"1.1", "2.0"} else "2.0",
            "serverInfo": {"name": MANIFEST["display_name"], "version": VERSION},
            "client_capabilities": {}, "capabilities": {},
        }
    elif method == "describe":
        result = MANIFEST
    elif method == "health":
        result = {"status": "healthy", "version": VERSION}
    elif method == "invoke":
        credentials = (params.get("context") or {}).get("credentials") or {}
        result = invoke(str(params.get("tool") or ""), params.get("arguments") or {}, credentials)
    elif method == "shutdown":
        result = {"ok": True}
    else:
        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise TypeError("request must be an object")
            response = handle_request(request)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
