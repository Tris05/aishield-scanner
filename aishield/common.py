from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.1"

_EVIDENCE_REDACTORS = (
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|authorization)\s*[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_./+=:-]{8,}[\"']?"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
)


def redact_evidence(value: str) -> str:
    """Best-effort redaction for evidence written into report artifacts; never a substitute for secret hygiene."""
    text = str(value or "")
    text = _EVIDENCE_REDACTORS[0].sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _EVIDENCE_REDACTORS[1].sub("[REDACTED_AWS_KEY]", text)
    text = _EVIDENCE_REDACTORS[2].sub("[REDACTED_TOKEN]", text)
    text = _EVIDENCE_REDACTORS[3].sub("[REDACTED_PRIVATE_KEY]", text)
    return text[:1000]


def reports_dir() -> Path:
    value = Path(os.environ.get("AISECURITY_REPORT_DIR", "aishield-reports"))
    value.mkdir(parents=True, exist_ok=True)
    return value


def stable_id(scanner: str, path: str, line: int | None, title: str) -> str:
    raw = f"{scanner}|{path}|{line or 0}|{title}".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:20]


def finding(*, scanner: str, category: str, title: str, description: str,
            severity: str = "medium", confidence: str = "medium",
            path: str = "", line: int | None = None, evidence: str = "",
            recommendation: str = "Review the evidence and apply the documented security control.",
            references: list[str] | None = None, rule_id: str = "",
            vulnerability_id: str = "", package: str = "",
            installed_version: str = "", fixed_version: str = "", cwe: str = "") -> dict[str, Any]:
    """Create a versioned, redacted, normalized finding used by every scanner module."""
    sev = severity.lower()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        sev = "medium"
    conf = confidence.lower()
    if conf not in {"high", "medium", "low"}:
        conf = "medium"
    relpath = str(path or "").replace("\\", "/")
    if relpath:
        candidate = Path(relpath)
        if candidate.is_absolute():
            try:
                relpath = candidate.resolve().relative_to(repo_root()).as_posix()
            except (ValueError, OSError, RuntimeError):
                relpath = candidate.name
    safe_evidence = redact_evidence(evidence)
    combined = " ".join((str(rule_id), str(title), safe_evidence))
    if not vulnerability_id:
        match = re.search(r"\b(?:CVE-\d{4}-\d{3,}|GHSA-[0-9a-z-]+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", combined, re.I)
        vulnerability_id = match.group(0).upper() if match else ""
    if not cwe:
        match = re.search(r"\bCWE-\d+\b", combined, re.I)
        cwe = match.group(0).upper() if match else ""
    if not package:
        match = re.search(r"(?:package|pkg(?:name)?)\s*[=:]\s*['\"]?([A-Za-z0-9_.@/+:-]+)", safe_evidence, re.I)
        package = match.group(1) if match else ""
    if not installed_version:
        match = re.search(r"(?:installed|version)\s*[=:]\s*['\"]?([^; ,]+)", safe_evidence, re.I)
        installed_version = match.group(1) if match else ""
    if not fixed_version:
        match = re.search(r"(?:fixed|fixed_versions)\s*[=:]\s*['\"]?([^; ,]+)", safe_evidence, re.I)
        if match and match.group(1).lower() not in {"not", "unknown", "none"}:
            fixed_version = match.group(1)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": stable_id(scanner, relpath, line, title),
        "scanner": scanner,
        "source_scanners": [scanner],
        "category": category,
        "rule_id": rule_id or scanner,
        "vulnerability_id": vulnerability_id,
        "cwe": cwe,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "title": title,
        "description": description,
        "severity": sev,
        "confidence": conf,
        "path": relpath,
        "line": line,
        "evidence": safe_evidence,
        "recommendation": recommendation,
        "references": references or [],
        "verified": False,
    }


def write_stage(name: str, findings: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> Path:
    payload = {"schema_version": SCHEMA_VERSION, "stage": name, "metadata": metadata or {}, "findings": findings}
    out = reports_dir() / f"{name}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default



def get_inventory(root: Path | None = None) -> dict[str, Any]:
    """Reuse inventory.json created by stage 0; refresh only when missing."""
    root = root or repo_root()
    cached = read_json(reports_dir() / "ai-inventory.json", None)
    if isinstance(cached, dict) and isinstance(cached.get("files"), list):
        return cached
    from .inventory import scan_tree
    return scan_tree(root)


def repo_root() -> Path:
    raw = Path(os.environ.get("AISECURITY_REPO", os.environ.get("CI_PROJECT_DIR", "."))).resolve()
    if not raw.is_dir():
        raise RuntimeError(f"Repository directory does not exist: {raw}")
    return raw


def relative_to_repo(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path.name
