"""Bounded, non-executing privacy-indicator and train/test overlap checks for text datasets.

This is a lightweight triage module, not a privacy/compliance certification. It never writes
raw dataset values into reports. Non-text/unsupported formats are inventoried but not loaded.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from .common import finding, get_inventory, repo_root, write_stage

MAX_FILE_BYTES = max(1024, min(100 * 1024 * 1024, int(os.getenv("AISECURITY_MAX_DATASET_FILE_BYTES", str(20 * 1024 * 1024)))))
MAX_TOTAL_BYTES = max(MAX_FILE_BYTES, min(500 * 1024 * 1024, int(os.getenv("AISECURITY_MAX_DATASET_TOTAL_BYTES", str(100 * 1024 * 1024)))))
MAX_ROWS_PER_FILE = max(1, min(50_000, int(os.getenv("AISECURITY_MAX_DATASET_ROWS", "5000"))))
MAX_CELLS_PER_FILE = max(100, min(2_000_000, int(os.getenv("AISECURITY_MAX_DATASET_CELLS", "100000"))))
MAX_VALUE_CHARS = 20_000
SUPPORTED_TEXT_DATA = {".csv", ".tsv", ".jsonl", ".ndjson"}

SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    "email_like": re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    "12_digit_identifier_like": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "PAN_like_identifier": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.I),
    "US_SSN_like_identifier": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "known_token_shape": re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9]{20,})\b"),
}
SENSITIVE_HEADER = re.compile(r"(?i)(email|e_mail|phone|mobile|ssn|aadhaar|aadhar|passport|national_id|tax_id|pan_number|credit_card|card_number|date_of_birth|dob)")
TRAIN_NAME = re.compile(r"(^|[/_.-])(train|training)([/_.-]|$)", re.I)
TEST_NAME = re.compile(r"(^|[/_.-])(test|testing|valid|validation|eval|evaluation)([/_.-]|$)", re.I)


def string_values(value: Any) -> Iterator[str]:
    """Yield string leaves from parsed JSON without retaining or reporting source values."""
    if isinstance(value, str):
        yield value[:MAX_VALUE_CHARS]
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_values(child)


def inspect_values(values: list[str]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for value in values:
        for category, pattern in SENSITIVE_PATTERNS.items():
            counts[category] += len(pattern.findall(value))
    return +counts


def row_fingerprint(record: Any) -> str:
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def _records(path: Path, suffix: str) -> Iterator[tuple[Any, list[str]]]:
    """Yield a parsed record and its string values. Caller enforces file/row/cell budgets."""
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            headers = [str(x)[:256] for x in (reader.fieldnames or [])]
            yield {"__headers__": headers}, headers
            for row in reader:
                clean = {str(k)[:256]: (v or "")[:MAX_VALUE_CHARS] for k, v in row.items() if k is not None}
                yield clean, [str(v) for v in clean.values()]
    else:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    # One malformed line is yielded as non-content so caller reports parsing issues.
                    yield {"__invalid_jsonl__": True}, []
                    continue
                yield value, list(string_values(value))


def run() -> None:
    root = repo_root()
    inv = get_inventory(root)
    findings = []
    total_bytes = 0
    files_scanned = 0
    rows_scanned = 0
    skipped_files: list[str] = []
    malformed_files: list[str] = []
    per_file_hashes: dict[str, set[str]] = {}
    per_file_row_counts: dict[str, int] = {}

    for entry in inv.get("data_artifacts", []):
        rel = str(entry.get("path", ""))
        suffix = Path(rel).suffix.lower()
        path = root / rel
        try:
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
                skipped_files.append(rel)
                continue
            size = path.stat().st_size
        except OSError:
            skipped_files.append(rel)
            continue

        if suffix not in SUPPORTED_TEXT_DATA:
            skipped_files.append(rel)
            continue
        if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
            skipped_files.append(rel)
            continue

        value_counts: Counter[str] = Counter()
        sensitive_headers: set[str] = set()
        seen_hashes: set[str] = set()
        malformed = False
        file_rows = 0
        cells = 0
        try:
            for record, values in _records(path, suffix):
                file_rows += 1
                rows_scanned += 1
                cells += len(values)
                if file_rows > MAX_ROWS_PER_FILE or cells > MAX_CELLS_PER_FILE:
                    skipped_files.append(rel)
                    break
                if record.get("__invalid_jsonl__") if isinstance(record, dict) else False:
                    malformed = True
                    continue
                if isinstance(record, dict) and "__headers__" in record:
                    for header in values:
                        if SENSITIVE_HEADER.search(header):
                            sensitive_headers.add(header[:80])
                    # Header record isn't data; don't count as a potential training example.
                    continue
                value_counts.update(inspect_values(values))
                seen_hashes.add(row_fingerprint(record))
        except (OSError, csv.Error, UnicodeError):
            malformed = True
            skipped_files.append(rel)
            continue
        total_bytes += size
        files_scanned += 1
        per_file_hashes[rel] = seen_hashes
        per_file_row_counts[rel] = max(0, file_rows - (1 if suffix in {".csv", ".tsv"} else 0))
        if malformed:
            malformed_files.append(rel)
        total_sensitive = sum(value_counts.values())
        if total_sensitive:
            high_risk = value_counts.get("known_token_shape", 0) > 0
            findings.append(finding(
                scanner="dataset-security", category="secret-exposure" if high_risk else "dataset-privacy",
                rule_id="structured-data-sensitive-patterns", title="Potential sensitive identifiers or token patterns found in a dataset",
                description="Bounded content inspection found identifier/token-shaped values in a structured dataset. These patterns can be false positives; no raw values are included in this report.",
                severity="high" if high_risk else "medium", confidence="medium", path=rel,
                evidence="Pattern counts only: " + ", ".join(f"{key}={count}" for key, count in sorted(value_counts.items()) if count),
                recommendation="Verify whether the dataset legitimately contains these fields, minimize or tokenize sensitive data, restrict access and logs, and keep raw samples out of reports. Do not treat regex matching as a regulatory conclusion.",
            ))
        elif sensitive_headers:
            findings.append(finding(
                scanner="dataset-security", category="dataset-privacy", rule_id="sensitive-column-names",
                title="Dataset schema includes potentially sensitive field names",
                description="Column names suggest personal or regulated identifiers; content patterns were not detected in the bounded sample. This does not prove the data is non-sensitive.",
                severity="info", confidence="low", path=rel,
                evidence=f"Sensitive-looking column-name count={len(sensitive_headers)}; raw values and column names omitted.",
                recommendation="Confirm lawful basis and purpose, minimize collected columns, document retention and access controls, and verify with an approved data-governance process.",
            ))

    # Compare exact row hashes only for conventionally named train and test/validation files.
    train_sets = {path: hashes for path, hashes in per_file_hashes.items() if TRAIN_NAME.search(path)}
    test_sets = {path: hashes for path, hashes in per_file_hashes.items() if TEST_NAME.search(path)}
    for train_path, train_hashes in train_sets.items():
        for test_path, test_hashes in test_sets.items():
            overlap = len(train_hashes & test_hashes)
            if overlap:
                findings.append(finding(
                    scanner="dataset-security", category="dataset-integrity", rule_id="train-test-exact-row-overlap",
                    title="Exact duplicate rows detected across train and test/validation files",
                    description="A bounded exact-row hash comparison found overlap between conventionally named data splits. Some overlap can be intentional, but it can cause evaluation leakage.",
                    severity="medium", confidence="medium", path=test_path,
                    evidence=f"train_file={train_path}; unique_overlapping_row_hashes={overlap}; train_rows_sampled={per_file_row_counts.get(train_path, 0)}; test_rows_sampled={per_file_row_counts.get(test_path, 0)}",
                    recommendation="Review split construction, deduplicate by a stable entity/group key where appropriate, and split before augmentation or near-duplicate generation. This check cannot detect semantic or near-duplicate leakage.",
                ))

    if skipped_files:
        findings.append(finding(
            scanner="dataset-security", category="coverage", rule_id="dataset-content-scan-limits",
            title="Some dataset files were inventoried but not content-scanned",
            description="Unsupported formats, unsafe paths, or configured size/row/cell limits prevented full content inspection. The files remain listed in the AI inventory; no clean-data conclusion can be drawn for them.",
            severity="low", confidence="high", evidence=f"skipped_file_count={len(set(skipped_files))}; supported_formats={','.join(sorted(SUPPORTED_TEXT_DATA))}",
            recommendation="Use an approved, format-aware scanner in a resource-bounded isolated job for unsupported formats such as Parquet, NumPy arrays or audio/images. Increase limits only after capacity review.",
        ))
    if malformed_files:
        findings.append(finding(
            scanner="dataset-security", category="coverage", rule_id="malformed-structured-dataset",
            title="Malformed structured dataset records encountered",
            description="One or more bounded CSV/TSV/JSONL inputs could not be fully parsed. Remaining content was not interpreted as a clean result.",
            severity="low", confidence="high", evidence=f"malformed_file_count={len(set(malformed_files))}",
            recommendation="Validate dataset schema/encoding/record format with the project's data-validation suite; avoid logging raw records.",
        ))
    write_stage("dataset-security", findings, {
        "files_scanned": files_scanned, "data_artifacts_detected": len(inv.get("data_artifacts", [])),
        "rows_scanned": rows_scanned, "bytes_scanned": total_bytes,
        "skipped_file_count": len(set(skipped_files)), "malformed_file_count": len(set(malformed_files)),
        "supported_formats": sorted(SUPPORTED_TEXT_DATA), "raw_values_written_to_report": False,
        "limits": {"file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "rows_per_file": MAX_ROWS_PER_FILE, "cells_per_file": MAX_CELLS_PER_FILE},
        "note": "Bounded heuristic scan only; not a privacy/compliance certification or a complete leakage test.",
    })
    print(f"Dataset security: scanned {files_scanned}/{len(inv.get('data_artifacts', []))} file(s); {len(findings)} finding(s)")


if __name__ == "__main__":
    run()
