from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .common import reports_dir, read_json

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
VULN_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{3,}|GHSA-[0-9a-z-]+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)
PACKAGE_RE = re.compile(r"(?:package|pkg(?:name)?)\s*[=:]\s*['\"]?([A-Za-z0-9_.@/+:-]+)", re.I)


def _artifact_paths(directory: Path) -> list[str]:
    """List every current and expected report artifact, including raw scanner outputs."""
    paths = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    paths.update({"report.json", "report.md", "report.sarif", "artifact-manifest.json"})
    return sorted(paths)



def _integrate_external_dast(directory: Path, pipeline_stages: list[dict], execution_summary: dict) -> None:
    """Merge the ZAP/DAST job execution state into the unified report status.
    
    Always runs when dast-security.json exists (file produced by ai-security:dast job).
    The AISECURITY_ENABLE_DAST env var only controls whether absence of the file is flagged.
    """
    report_path = directory / "dast-security.json"
    status_path = directory / "zap-status.json"
    dast_enabled = os.getenv("AISECURITY_ENABLE_DAST", "false").lower() == "true"

    # If DAST was not enabled AND the file doesn't exist, nothing to do.
    if not dast_enabled and not report_path.exists():
        return

    incomplete_reason = None
    dast_payload = read_json(report_path, {})
    if not isinstance(dast_payload, dict) or not isinstance(dast_payload.get("findings"), list):
        if dast_enabled:
            incomplete_reason = "DAST was enabled but dast-security.json is missing or invalid."
        dast_meta = {}
    else:
        dast_meta = dast_payload.get("metadata", {})
        if not isinstance(dast_meta, dict):
            dast_meta = {}
        if str(dast_meta.get("status", "unknown")).lower() not in {"completed"}:
            incomplete_reason = f"DAST did not complete successfully (status={dast_meta.get('status', 'unknown')})."
        elif any(isinstance(item, dict) and item.get("category") == "coverage" for item in dast_payload.get("findings", [])):
            incomplete_reason = "DAST emitted a coverage/error finding; inspect dast-security.json."

    zap_status = read_json(status_path, {})
    if isinstance(zap_status, dict) and zap_status:
        if str(zap_status.get("status", "unknown")).lower() != "completed" or zap_status.get("exit_code") != 0:
            incomplete_reason = incomplete_reason or "ZAP status report indicates an operational error."

    stage_entry = {
        "module": "dast",
        "status": "failed" if incomplete_reason else "completed",
        "scan_status": "incomplete" if incomplete_reason else "completed",
        "exit_code": (zap_status.get("exit_code") if isinstance(zap_status, dict) else None),
        "note": incomplete_reason or "OWASP ZAP Baseline passive scan completed.",
        "capabilities": ["api-web-dast", "passive-http-scanning"],
    }
    if not any(str(item.get("module", "")) == "dast" for item in pipeline_stages if isinstance(item, dict)):
        pipeline_stages.append(stage_entry)

    if incomplete_reason:
        incomplete = execution_summary.setdefault("incomplete_stages", [])
        if not any(isinstance(item, dict) and item.get("module") == "dast" for item in incomplete):
            incomplete.append({"module": "dast", "process_status": "failed", "scan_status": "incomplete", "reason": incomplete_reason})
        execution_summary["status"] = "incomplete"
        execution_summary["stage_count"] = max(int(execution_summary.get("stage_count", 0) or 0), len(pipeline_stages))


def _integrate_redteam_garak(directory: Path, pipeline_stages: list[dict], execution_summary: dict) -> None:
    """Ensure garak/custom red-team results appear in execution status when redteam.json exists."""
    report_path = directory / "redteam.json"
    if not report_path.exists():
        return
    payload = read_json(report_path, {})
    if not isinstance(payload, dict):
        return
    meta = payload.get("metadata", {}) or {}
    status = str(meta.get("status", "unknown")).lower()
    engine = str(meta.get("engine", "custom"))
    # Map redteam statuses to scan statuses
    scan_ok = status in {"completed", "findings"}
    scan_skip = status in {"skipped", "not_applicable"}
    scan_status = "completed" if scan_ok else ("skipped" if scan_skip else "incomplete")
    stage_entry = {
        "module": "redteam",
        "status": "completed" if scan_ok else status,
        "scan_status": scan_status,
        "capabilities": ["llm-runtime-security", "prompt-injection", "canary-disclosure"],
        "engine": engine,
        "note": str(meta.get("reason", "")) or f"Red-team engine: {engine}",
    }
    # Only add if not already present from pipeline.py
    if not any(str(x.get("module", "")) == "redteam" for x in pipeline_stages if isinstance(x, dict)):
        pipeline_stages.append(stage_entry)
    if scan_status == "incomplete":
        incomplete = execution_summary.setdefault("incomplete_stages", [])
        if not any(isinstance(x, dict) and x.get("module") == "redteam" for x in incomplete):
            incomplete.append({"module": "redteam", "process_status": status, "scan_status": "incomplete"})
        execution_summary["status"] = "incomplete"



def _finding_key(item: dict[str, Any]) -> tuple[Any, ...]:
    text = " ".join((str(item.get("rule_id", "")), str(item.get("title", "")), str(item.get("evidence", ""))))
    vuln_match = VULN_ID_RE.search(text)
    if vuln_match:
        package_match = PACKAGE_RE.search(str(item.get("evidence", "")))
        package = package_match.group(1).lower() if package_match else ""
        return ("vulnerability", vuln_match.group(0).upper(), package, str(item.get("path", "")))
    # If multiple tools emit the same source-level rule at the same location, retain one finding
    # while preserving every contributing scanner in source_scanners.
    if item.get("path") and item.get("line") and item.get("category") in {
        "sast", "secure-coding", "llm-application-security", "agent-tool-security"
    }:
        return ("source-location", item.get("category"), item.get("path"), item.get("line"), item.get("title"))
    return ("tool-finding", item.get("id"), item.get("scanner"), item.get("path"), item.get("line"))


def normalize_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate cross-tool equivalents without discarding source provenance."""
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for original in items:
        item = dict(original)
        item.setdefault("source_scanners", [str(item.get("scanner", "unknown"))])
        key = _finding_key(item)
        if key not in merged:
            merged[key] = item
            continue
        existing = merged[key]
        sources = set(existing.get("source_scanners", [])) | set(item.get("source_scanners", []))
        if item.get("scanner"):
            sources.add(str(item["scanner"]))
        existing["source_scanners"] = sorted(sources)
        existing["references"] = sorted(set(existing.get("references", [])) | set(item.get("references", [])))
        # Preserve the most severe rating across tools; do not downgrade confidence.
        old_sev = str(existing.get("severity", "medium")).lower()
        new_sev = str(item.get("severity", "medium")).lower()
        if SEVERITY_ORDER.get(new_sev, 3) > SEVERITY_ORDER.get(old_sev, 3):
            existing["severity"] = new_sev
        old_conf = str(existing.get("confidence", "medium")).lower()
        new_conf = str(item.get("confidence", "medium")).lower()
        if CONFIDENCE_ORDER.get(new_conf, 2) > CONFIDENCE_ORDER.get(old_conf, 2):
            existing["confidence"] = new_conf
        for field in ("evidence", "recommendation", "description"):
            if not existing.get(field) and item.get(field):
                existing[field] = item[field]
    return list(merged.values())


def load_findings() -> tuple[list[dict], list[dict]]:
    directory = reports_dir()
    all_findings: list[dict] = []
    stages: list[dict] = []
    excluded = {
        "report.json", "report.sarif", "report.md", "coverage-matrix.json", "pipeline-status.json",
        "ai-inventory.json", "scan-metadata.json",
    }
    # Always load dast-security.json and redteam.json when present — they are never excluded.
    # The findings they contain (from ZAP / garak / custom red-team) are part of the
    # unified report regardless of which env vars were set during the scan.
    for path in sorted(directory.glob("*.json")):
        if path.name in excluded or path.name.endswith("-raw.json") or path.name.startswith("modelscan-") or path.name == "osv-scanner.json":
            continue
        payload = read_json(path, {})
        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            continue
        stages.append({"stage": payload.get("stage", path.stem), "metadata": payload.get("metadata", {})})
        all_findings.extend(item for item in payload["findings"] if isinstance(item, dict))
    return normalize_findings(all_findings), stages


def make_sarif(findings: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for item in findings:
        rule_id = str(item.get("rule_id") or item.get("scanner") or "aishield")
        rules[rule_id] = {"id": rule_id, "shortDescription": {"text": str(item.get("title", "AI security finding"))[:200]}, "help": {"text": str(item.get("recommendation", "Review finding."))[:1000]}}
        level = SARIF_LEVEL.get(str(item.get("severity", "medium")).lower(), "warning")
        locations = []
        path = str(item.get("path", ""))
        if path:
            physical = {"artifactLocation": {"uri": path}}
            if item.get("line"):
                physical["region"] = {"startLine": max(1, int(item["line"]))}
            locations = [{"physicalLocation": physical}]
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(item.get("title", "AI security finding")) + ": " + str(item.get("description", ""))[:500]},
            "locations": locations,
            "partialFingerprints": {"aishield/v1": str(item.get("id", ""))},
            "properties": {"severity": item.get("severity"), "confidence": item.get("confidence"), "category": item.get("category"), "recommendation": item.get("recommendation"), "evidence": item.get("evidence"), "source_scanners": item.get("source_scanners", [item.get("scanner")])},
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "AIShield", "informationUri": "https://gitlab.com/", "semanticVersion": "0.1.0", "rules": list(rules.values())}}, "results": results}]}


def run() -> int:
    directory = reports_dir()
    findings, stages = load_findings()
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity", "medium")).lower(), 3), str(item.get("path", "")), int(item.get("line") or 0)))
    counts = Counter(str(item.get("severity", "medium")).lower() for item in findings)
    coverage = read_json(directory / "coverage-matrix.json", {})
    pipeline_status = read_json(directory / "pipeline-status.json", {})
    pipeline_stages = pipeline_status.get("stages", []) if isinstance(pipeline_status, dict) else []
    execution_summary = pipeline_status.get("execution_summary", {}) if isinstance(pipeline_status, dict) else {}
    if not isinstance(execution_summary, dict) or not execution_summary:
        execution_summary = {"status": "not_available", "stage_count": len(pipeline_stages),
                             "incomplete_stages": [], "optional_stages_skipped": [],
                             "note": "Run AIShield through aishield.pipeline to produce authoritative scanner execution status."}
    _integrate_external_dast(directory, pipeline_stages, execution_summary)
    _integrate_redteam_garak(directory, pipeline_stages, execution_summary)
    artifact_paths = _artifact_paths(directory)
    summary = {
        "schema_version": "1.2", "product": "AIShield", "status": execution_summary.get("status", "not_available"),
        "execution_summary": execution_summary,
        "finding_count": len(findings), "counts": dict(counts), "stages": stages,
        "findings": findings, "coverage": coverage.get("categories", []) if isinstance(coverage, dict) else [],
        "pipeline_status": pipeline_stages,
        "artifacts": artifact_paths,
        "coverage_note": "Static and bounded checks cannot guarantee detection of every vulnerability. Check coverage-matrix.json for categories that are conditional or not implemented.",
    }
    (directory / "report.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (directory / "report.sarif").write_text(json.dumps(make_sarif(findings), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = ["# AIShield security report", "", f"- Findings after deduplication: **{len(findings)}**", f"- Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']} | Info: {counts['info']}", "", "## Scan execution", "", f"- Operational status: **{str(execution_summary.get('status', 'not_available')).upper()}**", f"- Scanner stages recorded: {execution_summary.get('stage_count', len(pipeline_stages))}"]
    incomplete_stages = execution_summary.get("incomplete_stages", [])
    skipped_stages = execution_summary.get("optional_stages_skipped", [])
    if incomplete_stages:
        lines.extend(["", "The assessment is incomplete. Do not interpret missing scanner results as a clean scan:"])
        for item in incomplete_stages:
            lines.append(f"- `{item.get('module', 'unknown')}` — process: `{item.get('process_status', 'unknown')}`, scan: `{item.get('scan_status', 'unknown')}`")
    if skipped_stages:
        lines.extend(["", "Optional checks not run:"])
        for item in skipped_stages:
            lines.append(f"- `{item.get('module', 'unknown')}` — {item.get('reason', 'Optional stage not enabled.')}")
    if pipeline_stages:
        lines.extend(["", "| Stage | Process status | Scan status | Duration (s) |", "|---|---|---|---:|"])
        for item in pipeline_stages:
            lines.append(f"| {item.get('module', 'unknown')} | {item.get('status', 'unknown')} | {item.get('scan_status', 'unknown')} | {item.get('duration_seconds', '—')} |")
    lines.extend(["", "## Coverage matrix", "", "Coverage status is not a guarantee of detection. See `coverage-matrix.json` for limitations."])
    categories = coverage.get("categories", []) if isinstance(coverage, dict) else []
    if categories:
        lines.extend(["", "| Category | Status | Checks |", "|---|---|---|"])
        for category in categories:
            lines.append(f"| {category.get('id', 'unknown')} | {category.get('status', 'unknown')} (execution: {category.get('execution_status', 'not_available')}) | {', '.join(category.get('scanners', [])) or 'None integrated'} |")
    lines.extend(["", "## Generated artifacts", "", "The JSON report is uploaded to the AIShield Dashboard; local GitLab artifacts remain available for troubleshooting."])
    for artifact in artifact_paths:
        lines.append(f"- `{artifact}`")
    lines.extend(["", "## Findings"])
    if not findings:
        lines.append("No findings were emitted by the stages that ran. Review scanner statuses and coverage limitations; an empty report is not proof of security.")
    for item in findings:
        location = f"`{item.get('path')}`" if item.get("path") else "repository-wide"
        if item.get("line"):
            location += f":{item['line']}"
        evidence = str(item.get("evidence", "") or "not available").replace("`", "\\`")[:300]
        sources = ", ".join(item.get("source_scanners", [item.get("scanner", "unknown")]))
        lines.extend(["", f"### [{str(item.get('severity', 'medium')).upper()}] {item.get('title', 'Finding')}", f"- Location: {location}", f"- Scanner(s): `{sources}` | Confidence: `{item.get('confidence')}` | Category: `{item.get('category')}`", str(item.get("description", "")), f"- Evidence: `{evidence}`", f"- Recommended action: {item.get('recommendation', 'Review the finding.')}"])
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Machine-readable inventory of every emitted stage report and raw artifact.
    manifest_entries = []
    for artifact in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "artifact-manifest.json"):
        manifest_entries.append({
            "path": artifact.relative_to(directory).as_posix(),
            "size_bytes": artifact.stat().st_size,
        })
    manifest_entries.append({"path": "artifact-manifest.json", "size_bytes": None, "note": "This manifest describes itself; size omitted to avoid a self-referential value."})
    (directory / "artifact-manifest.json").write_text(
        json.dumps({"schema_version": "1.0", "artifact_count": len(manifest_entries), "files": manifest_entries}, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"AIShield report: {len(findings)} unique findings; {dict(counts)}")
    execution_state = str(execution_summary.get("status", "not_available")).upper()
    print(f"Scan execution: {execution_state}; {len(incomplete_stages)} incomplete stage(s), {len(skipped_stages)} optional stage(s) skipped.")

    threshold = os.getenv("AISECURITY_FAIL_ON", "none").lower()
    if threshold not in {"critical", "high", "medium", "low", "info", "none"}:
        # Fail-open is the default for the scan/report workflow. Organizations can
        # explicitly opt into severity enforcement with AISECURITY_FAIL_ON.
        threshold = "none"
    failing = 0 if threshold == "none" else SEVERITY_ORDER.get(threshold, 4)
    violations = [item for item in findings if SEVERITY_ORDER.get(str(item.get("severity", "medium")).lower(), 3) >= failing] if failing else []
    fail_coverage = os.getenv("AISECURITY_FAIL_ON_COVERAGE", "false").lower() == "true"
    coverage_findings = [item for item in findings if item.get("category") == "coverage"] if fail_coverage else []
    execution_incomplete = str(execution_summary.get("status", "not_available")).lower() == "incomplete"
    if violations or coverage_findings or (fail_coverage and execution_incomplete):
        if violations:
            print(f"Policy gate failed: {len(violations)} finding(s) at or above {threshold}.")
        if coverage_findings or (fail_coverage and execution_incomplete):
            print(
                "Coverage gate failed: "
                f"{len(coverage_findings)} coverage finding(s); "
                f"execution status={execution_summary.get('status', 'not_available')}. "
                "This gate is opt-in via AISECURITY_FAIL_ON_COVERAGE=true."
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
