"""AIShield scanner orchestration with bounded parallel execution and explicit coverage status."""
from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .common import finding, repo_root, reports_dir, write_stage
from .config import load_config

# Load .config from target repository (or fallback to component .config)
try:
    load_config(repo_root(), verbose=True)
except Exception:
    load_config(None, verbose=False)


GENERATED_REPORT_FILES = {
    "scan-metadata.json", "ai-inventory.json", "inventory.json", "sbom.json", "dependencies.json",
    "freshness.json", "static-analysis.json", "secrets.json", "infrastructure.json",
    "model-security.json", "dataset-security.json", "llm-security.json", "mcp-security.json",
    "redteam.json", "orchestration.json", "stage-health.json", "pipeline-status.json",
    "coverage-matrix.json", "report.json", "report.sarif", "report.md", "sbom.cdx.json",
    "model-artifacts.json", "osv-scanner.json", "artifact-manifest.json",
}


def _clear_previous_run_artifacts(out_dir: Path) -> None:
    """Prevent stale reports from a previous scan being mistaken for this run's results."""
    for name in GENERATED_REPORT_FILES:
        (out_dir / name).unlink(missing_ok=True)
    for pattern in ("stage-error-*.json", "modelscan-*.json", "*-raw.json"):
        for path in out_dir.glob(pattern):
            if path.is_file() and not path.is_symlink():
                path.unlink(missing_ok=True)


# Metadata and inventory run first. Remaining independent scanners consume the cached inventory
# and write separate stage files, so they can safely run concurrently.
PREPARE_STAGES = ("metadata", "inventory")
SCAN_STAGES = (
    "sbom",
    "dependencies",
    "freshness",
    "static_analysis",
    "secrets_scan",
    "infrastructure_scan",
    "model_security",
    "dataset_security",
    "llm_security",
    "mcp_security",
    "redteam",
)
STAGE_TIMEOUT = max(30, min(7200, int(os.getenv("AISECURITY_STAGE_TIMEOUT_SECONDS", "1800"))))
MAX_WORKERS = max(1, min(8, int(os.getenv("AISECURITY_MAX_PARALLEL_SCANNERS", "4"))))

# Maps scanner modules to the security areas they contribute evidence to. This is a coverage
# inventory, not a claim that any static scanner can find every vulnerability in a category.
STAGE_REPORT_FILES = {
    "inventory": "inventory.json", "sbom": "sbom.json", "dependencies": "dependencies.json",
    "freshness": "freshness.json", "static_analysis": "static-analysis.json",
    "secrets_scan": "secrets.json", "infrastructure_scan": "infrastructure.json",
    "model_security": "model-security.json", "dataset_security": "dataset-security.json",
    "llm_security": "llm-security.json", "mcp_security": "mcp-security.json", "redteam": "redteam.json",
}

STAGE_CAPABILITIES: dict[str, list[str]] = {
    "metadata": ["scan-metadata", "provenance-context"],
    "inventory": ["technology-detection", "ai-asset-detection"],
    "sbom": ["sbom", "software-inventory"],
    "dependencies": ["dependency-cves", "lockfile-analysis"],
    "freshness": ["dependency-freshness"],
    "static_analysis": ["sast", "python-security", "secure-coding"],
    "secrets_scan": ["secrets", "credential-exposure"],
    "infrastructure_scan": ["os-and-package-cves", "iac-misconfiguration", "license-indicators"],
    "model_security": ["unsafe-model-artifacts", "model-file-integrity"],
    "dataset_security": ["dataset-privacy", "dataset-integrity", "data-leakage-indicators"],
    "llm_security": ["llm-application-static-review", "unsafe-llm-output-handling"],
    "mcp_security": ["agent-tools", "mcp-security"],
    "redteam": ["authorized-llm-runtime-tests", "prompt-injection-and-canary-tests"],
}


def _run_module(name: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", f"aishield.{name}"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=STAGE_TIMEOUT,
        )
        if proc.stdout:
            print(f"\n===== AIShield stage: {name} (stdout) =====\n{proc.stdout.rstrip()}", flush=True)
        if proc.stderr:
            print(f"\n===== AIShield stage: {name} (stderr) =====\n{proc.stderr.rstrip()}", file=sys.stderr, flush=True)
        outcome: dict[str, Any] = {
            "module": name,
            "status": "completed" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "capabilities": STAGE_CAPABILITIES.get(name, []),
        }
        if proc.returncode != 0:
            write_stage(
                f"stage-error-{name}",
                [finding(
                    scanner="pipeline", category="coverage", rule_id=f"stage-exit-{name}",
                    title=f"Stage did not complete: {name}",
                    description="The scanner module exited non-zero. Its missing results must not be interpreted as a clean scan.",
                    severity="low", confidence="high", evidence=f"exit_code={proc.returncode}",
                    recommendation="Review the stage log, fix the scanner error, and rerun the scan.",
                )],
                outcome,
            )
        return outcome
    except subprocess.TimeoutExpired:
        outcome = {
            "module": name, "status": "timeout", "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 3),
            "capabilities": STAGE_CAPABILITIES.get(name, []),
        }
        write_stage(
            f"stage-error-{name}",
            [finding(
                scanner="pipeline", category="coverage", rule_id=f"stage-timeout-{name}",
                title=f"Stage timed out: {name}",
                description="The scanner exceeded its configured timeout; scan coverage is incomplete.",
                severity="low", confidence="high", evidence=f"timeout_seconds={STAGE_TIMEOUT}",
                recommendation="Review repository size and runner capacity. Increase timeouts only with resource limits in place.",
            )], outcome,
        )
        return outcome
    except OSError as exc:
        outcome = {
            "module": name, "status": "execution_error", "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 3),
            "error_type": type(exc).__name__,
            "capabilities": STAGE_CAPABILITIES.get(name, []),
        }
        write_stage(
            f"stage-error-{name}",
            [finding(
                scanner="pipeline", category="coverage", rule_id=f"stage-exec-{name}",
                title=f"Stage could not execute: {name}",
                description="The scanner process could not be started; coverage is incomplete.",
                severity="low", confidence="high", evidence=type(exc).__name__,
                recommendation="Check the engine image, Python module, executable and runtime permissions.",
            )], outcome,
        )
        return outcome


def _enrich_scan_status(outcomes: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    """Read stage metadata to distinguish a completed process from complete scan coverage."""
    incomplete_values = {"tool_missing", "incomplete", "timeout", "execution_error", "configuration_error", "provider_error", "error", "unsupported", "report_unparsed", "target_rejected", "partial"}
    issues: list[dict[str, Any]] = []
    for outcome in outcomes:
        module = str(outcome.get("module", ""))
        filename = STAGE_REPORT_FILES.get(module)
        if not filename:
            outcome.setdefault("scan_status", outcome.get("status", "unknown"))
            continue
        try:
            payload = json.loads((out_dir / filename).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            outcome["scan_status"] = "missing_stage_report"
            issues.append(finding(
                scanner="pipeline", category="coverage", rule_id=f"missing-report-{module}",
                title=f"Scanner report missing: {module}",
                description="The scanner process exited successfully but did not produce its expected report. Its results cannot be treated as a clean scan.",
                severity="low", confidence="high", evidence=f"expected_report={filename}",
                recommendation="Check the scanner's output path and report-writing code, then rerun the scan.",
            ))
            continue
        metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        declared = str(metadata.get("status", "")).lower() if isinstance(metadata, dict) else ""
        if declared in {"skipped", "blocked_by_consent", "mcp_not_detected"}:
            outcome["scan_status"] = "skipped" if declared != "mcp_not_detected" else "not_applicable"
            if isinstance(metadata, dict) and metadata.get("reason"):
                outcome["skip_reason"] = str(metadata["reason"])
        elif declared in incomplete_values:
            outcome["scan_status"] = "incomplete"
        elif any(isinstance(item, dict) and item.get("category") == "coverage" for item in findings):
            outcome["scan_status"] = "coverage_gap"
        elif declared in {"mcp_detected", "completed", "proposal_created", "disabled"}:
            outcome["scan_status"] = "completed"
        else:
            outcome["scan_status"] = "completed"
    return issues


def _execution_summary(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize operational scan completeness independently from vulnerability severity."""
    incomplete_scan_states = {
        "failed", "timeout", "execution_error", "orchestrator_error", "missing_stage_report",
        "invalid_stage_report", "incomplete", "coverage_gap", "tool_missing", "configuration_error",
        "provider_error", "error", "unsupported", "report_unparsed", "target_rejected", "partial",
    }
    optional_modules = {"freshness", "redteam"}
    incomplete_stages = [
        {"module": x.get("module", "unknown"), "process_status": x.get("status", "unknown"),
         "scan_status": x.get("scan_status", "unknown")}
        for x in outcomes
        if x.get("scan_status") in incomplete_scan_states or x.get("status") not in {"completed"}
    ]
    optional_stages_skipped = [
        {"module": x.get("module", "unknown"), "reason": str(x.get("skip_reason", "Optional stage was not enabled or was blocked by its opt-in requirements."))}
        for x in outcomes if x.get("scan_status") == "skipped" and x.get("module") in optional_modules
    ]
    return {
        "status": "incomplete" if incomplete_stages else "completed",
        "stage_count": len(outcomes),
        "incomplete_stages": incomplete_stages,
        "optional_stages_skipped": optional_stages_skipped,
    }



def _coverage_matrix(inventory: dict[str, Any] | None, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    by_module = {str(x.get("module")): x for x in outcomes}
    inv = inventory or {}
    llm_detected = bool(inv.get("architecture_types") and any(
        x in inv.get("architecture_types", [])
        for x in ("llm_application", "rag_or_vector_retrieval", "tool_using_or_agentic_ai", "mcp_enabled_tool_server")
    ))
    models_detected = bool(inv.get("model_artifacts"))
    datasets_detected = bool(inv.get("data_artifacts"))
    redteam_enabled = os.getenv("AISECURITY_AUTHORIZED", "false").lower() == "true"
    dast_enabled = os.getenv("AISECURITY_ENABLE_DAST", "false").lower() == "true"

    entries = [
        {"id": "dependency-cves", "status": "partial", "scanners": ["OSV-Scanner", "pip-audit", "Trivy", "npm audit (opt-in)"], "note": "Coverage depends on supported manifests, lockfiles, scanner availability and registry/database access."},
        {"id": "container-and-os-cves", "status": "partial", "scanners": ["Trivy filesystem scan", "CI engine-image scan"], "note": "The component repository's deployment image is not automatically built and dynamically scanned by this source-repository stage."},
        {"id": "sast-and-python-security", "status": "partial", "scanners": ["Semgrep", "Bandit", "AIShield heuristics"], "note": "Static analysis is not proof of exploitability or complete data-flow coverage."},
        {"id": "secrets", "status": "partial", "scanners": ["Gitleaks", "detect-secrets", "Trivy"], "note": "Secret values are redacted; scanner availability and excluded paths affect coverage."},
        {"id": "iac-and-ci-misconfiguration", "status": "partial", "scanners": ["Trivy misconfiguration"], "note": "Not every provider-specific policy or CI configuration rule is covered."},
        {"id": "unsafe-model-artifacts", "status": "conditional" if models_detected else "not_applicable", "scanners": ["ModelScan", "file hashing/metadata"], "note": "Only supported formats and bounded artifact sizes are inspected; unknown binary formats are not proven safe."},
        {"id": "dataset-privacy-and-integrity", "status": "conditional" if datasets_detected else "not_applicable", "scanners": ["AIShield bounded dataset checks"], "note": "Heuristic pattern checks do not establish regulatory compliance and cannot detect every semantic or near-duplicate leak."},
        {"id": "llm-prompt-injection-and-jailbreak", "status": ("conditional" if llm_detected and redteam_enabled else "static-only" if llm_detected else "not_detected"), "scanners": ["AIShield static checks", "opt-in authorized red team"], "note": "Runtime prompt-injection/jailbreak tests run only when explicitly authorized and a valid target is configured."},
        {"id": "rag-agent-tools-and-mcp", "status": "partial" if llm_detected else "not_detected", "scanners": ["AIShield LLM heuristics", "MCP static checks"], "note": "Static heuristics do not prove authorization, tenant isolation, retrieval ACLs or tool execution safety."},
        {"id": "ai-data-leakage-and-misuse", "status": "partial", "scanners": ["dataset pattern checks", "opt-in red-team canary tests"], "note": "No universal AI misuse classifier; runtime coverage requires a controlled test endpoint and synthetic canaries."},
        {"id": "api-and-web-dast", "status": ("conditional" if dast_enabled else "disabled"), "scanners": ["OWASP ZAP Baseline passive scan (separate opt-in job)"], "note": "Opt-in passive DAST runs in a separate job and publishes its own normalized report. It requires an explicitly allowlisted running web/API target, does not perform active attacks, and does not prove complete API coverage."},
        {"id": "license-and-provenance", "status": "partial", "scanners": ["Trivy license indicators", "CycloneDX SBOM", "scan metadata"], "note": "Policy-specific license review and signed provenance/attestation verification are not complete in Phase 2."},
    ]
    for entry in entries:
        relevant = [by_module[x] for x in {
            "dependency-cves": ["dependencies", "infrastructure_scan"],
            "container-and-os-cves": ["infrastructure_scan", "sbom"],
            "sast-and-python-security": ["static_analysis"],
            "secrets": ["secrets_scan", "infrastructure_scan"],
            "iac-and-ci-misconfiguration": ["infrastructure_scan"],
            "unsafe-model-artifacts": ["model_security"],
            "dataset-privacy-and-integrity": ["dataset_security"],
            "llm-prompt-injection-and-jailbreak": ["llm_security", "redteam"],
            "rag-agent-tools-and-mcp": ["llm_security", "mcp_security"],
            "ai-data-leakage-and-misuse": ["dataset_security", "redteam"],
            "api-and-web-dast": [],
            "license-and-provenance": ["sbom", "infrastructure_scan", "metadata"],
        }[entry["id"]] if x in by_module]
        entry["stage_status"] = {x["module"]: x.get("scan_status", x.get("status", "unknown")) for x in relevant}
    return {
        "schema_version": "1.0",
        "note": "Coverage describes implemented checks and known limits; it is not a guarantee that all vulnerabilities in a category will be detected.",
        "categories": entries,
    }


def main() -> int:
    out_dir = reports_dir()
    _clear_previous_run_artifacts(out_dir)
    outcomes: list[dict[str, Any]] = []

    for module in PREPARE_STAGES:
        outcome = _run_module(module)
        outcomes.append(outcome)

    inventory_path = out_dir / "ai-inventory.json"
    inventory = None
    try:
        loaded = json.loads(inventory_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            inventory = loaded
    except (OSError, json.JSONDecodeError):
        pass

    # Inventory is ready before the independent scanners start. Parallelism is bounded to avoid
    # resource exhaustion on large repos; every module has its own timeout and result file.
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="aishield-scan") as pool:
        future_map = {pool.submit(_run_module, module): module for module in SCAN_STAGES}
        scan_outcomes: dict[str, dict[str, Any]] = {}
        for future in concurrent.futures.as_completed(future_map):
            module = future_map[future]
            try:
                scan_outcomes[module] = future.result()
            except Exception as exc:  # Defensive guard: one unexpected worker must not erase other results.
                scan_outcomes[module] = {
                    "module": module, "status": "orchestrator_error", "exit_code": None,
                    "error_type": type(exc).__name__, "capabilities": STAGE_CAPABILITIES.get(module, []),
                }
                write_stage(
                    f"stage-error-{module}",
                    [finding(scanner="pipeline", category="coverage", rule_id=f"orchestrator-error-{module}",
                        title=f"Orchestrator error in stage: {module}",
                        description="An unexpected orchestration error prevented the stage result from being collected.",
                        severity="low", confidence="high", evidence=type(exc).__name__,
                        recommendation="Inspect the job logs and rerun after fixing the orchestration error.")],
                    scan_outcomes[module],
                )
        outcomes.extend(scan_outcomes[x] for x in SCAN_STAGES)

    _enrich_scan_status(outcomes, out_dir)
    coverage = _coverage_matrix(inventory, outcomes)
    execution_summary = _execution_summary(outcomes)
    status_payload = {
        "schema_version": "1.0",
        "max_parallel_scanners": MAX_WORKERS,
        "stage_timeout_seconds": STAGE_TIMEOUT,
        "stages": outcomes,
        "execution_summary": execution_summary,
        "coverage_summary": {x["id"]: x["status"] for x in coverage["categories"]},
    }
    (out_dir / "pipeline-status.json").write_text(json.dumps(status_payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "coverage-matrix.json").write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    write_stage("orchestration", [], status_payload)

    # Generate the user-facing report once. Findings do not fail the job unless an explicit policy is configured.
    final_report = subprocess.run([sys.executable, "-m", "aishield.report"], text=True, check=False)
    return final_report.returncode


if __name__ == "__main__":
    sys.exit(main())
