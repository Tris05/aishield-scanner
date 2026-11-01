from __future__ import annotations
import json, os, shutil, subprocess
from pathlib import Path
from .common import finding, get_inventory, repo_root, reports_dir, write_stage

TIMEOUT = int(os.getenv("AISECURITY_TOOL_TIMEOUT", "900"))


def main() -> None:
    root = repo_root()
    inv = get_inventory(root)
    out = (reports_dir() / "sbom.cdx.json").resolve()
    if not shutil.which("trivy"):
        write_stage("sbom", [finding(scanner="sbom", category="coverage", title="SBOM generation unavailable", description="CycloneDX SBOM generation was not performed because Trivy is unavailable.", severity="low", confidence="high", recommendation="Use the published AIShield engine image with Trivy installed.")], {"status": "tool_missing"})
        return
    skip_args = []
    for ignored in (".git", "node_modules", ".venv", "venv", "aishield-reports", ".scannerwork", ".terraform"):
        skip_args.extend(["--skip-dirs", ignored])
    cmd = ["trivy", "fs", "--format", "cyclonedx", "--output", str(out), "--no-progress", *skip_args, str(root)]
    try:
        proc = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        write_stage("sbom", [finding(scanner="sbom", category="coverage", title="SBOM generation timed out", description="Trivy did not finish generating the CycloneDX SBOM within the configured timeout.", severity="low", confidence="high", recommendation="Review repository size and runner resources.")], {"status": "timeout"})
        return
    try:
        payload = json.loads(out.read_text(encoding="utf-8"))
        valid = isinstance(payload, dict) and payload.get("bomFormat") == "CycloneDX"
    except (OSError, json.JSONDecodeError):
        payload = {}
        valid = False
    findings = []
    if proc.returncode != 0 or not valid:
        findings.append(finding(scanner="sbom", category="coverage", title="CycloneDX SBOM generation failed", description="Trivy did not produce a valid CycloneDX SBOM; software inventory coverage is incomplete.", severity="low", confidence="high", evidence=(proc.stderr or proc.stdout)[-500:], recommendation="Inspect Trivy logs and verify supported manifests; rerun the SBOM stage."))
    write_stage("sbom", findings, {"status": "completed" if valid and proc.returncode == 0 else "incomplete", "path": "aishield-reports/sbom.cdx.json" if valid else None, "format": "CycloneDX", "components": len(payload.get("components", [])) if isinstance(payload, dict) else 0, "inventory_file_count": inv.get("file_count", 0)})
    print(f"SBOM generation: valid={valid}; components={len(payload.get('components', [])) if isinstance(payload, dict) else 0}")

if __name__ == "__main__":
    main()
