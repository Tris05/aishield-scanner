from __future__ import annotations
import json, os, shutil, subprocess, tempfile
from pathlib import Path
from .common import finding, repo_root, reports_dir, write_stage
from .common import get_inventory

SEVERITY_MAP={"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","UNKNOWN":"low"}
TIMEOUT=int(os.getenv("AISECURITY_TOOL_TIMEOUT","900"))


def run() -> None:
    root=repo_root(); inv=get_inventory(root); findings=[]; status={}
    if not shutil.which("trivy"):
        findings.append(finding(scanner="trivy",category="coverage",title="Trivy is unavailable",description="Filesystem vulnerability, secret and infrastructure-configuration scans were not performed by Trivy.",severity="low",confidence="high",recommendation="Use the published AIShield engine image with Trivy installed, or mark this stage as not tested."))
        write_stage("infrastructure",findings,{"status":"tool_missing"}); return
    raw_fd, raw_name = tempfile.mkstemp(prefix="aishield-trivy-", suffix=".json")
    os.close(raw_fd)
    outfile=Path(raw_name)
    skip_args=[]
    for ignored in (".git", "node_modules", ".venv", "venv", "aishield-reports", ".scannerwork", ".terraform"):
        skip_args.extend(["--skip-dirs", ignored])
    # Create a CycloneDX SBOM from discovered manifests. The separate sbom stage owns its own report.
    cmd=["trivy","fs","--scanners","vuln,misconfig,secret,license","--format","json","--output",str(outfile),"--no-progress",*skip_args,str(root)]
    try:
        proc=subprocess.run(cmd,cwd=root,text=True,capture_output=True,timeout=TIMEOUT,check=False)
        try:
            payload=json.loads(outfile.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError):
            payload={}
        finally:
            outfile.unlink(missing_ok=True)
        valid_payload = isinstance(payload, dict) and ("Results" in payload)
        result_entries = payload.get("Results") or [] if isinstance(payload, dict) else []
        if not isinstance(result_entries, list):
            result_entries = []
            valid_payload = False
        status={"exit_code":proc.returncode,"results_sections":len(result_entries),"valid_json_payload":valid_payload}
        if not valid_payload:
            findings.append(finding(scanner="trivy",category="coverage",title="Trivy output missing or invalid",description="Trivy did not produce the expected JSON results structure; absence of findings cannot be interpreted as a clean scan.",severity="low",confidence="high",evidence=(proc.stderr or proc.stdout)[-700:],recommendation="Check the pinned Trivy version, database access and CLI output format, then rerun the scan."))
        for result in result_entries:
            if not isinstance(result, dict):
                continue
            target=str(result.get("Target","")); result_type=str(result.get("Type",""))
            for vuln in result.get("Vulnerabilities",[]) or []:
                if not isinstance(vuln,dict): continue
                sev=SEVERITY_MAP.get(str(vuln.get("Severity","UNKNOWN")).upper(),"medium")
                findings.append(finding(scanner="trivy",category="dependency",rule_id=str(vuln.get("VulnerabilityID","trivy-vuln")),
                    title=f"{vuln.get('VulnerabilityID','Vulnerability')} in {vuln.get('PkgName','dependency')}",description=str(vuln.get("Description") or "Trivy reported a package vulnerability."),severity=sev,confidence="high",path=target,
                    evidence=f"package={vuln.get('PkgName')}; installed={vuln.get('InstalledVersion')}; fixed={vuln.get('FixedVersion') or 'not reported'}; target_type={result_type}",recommendation=(f"Upgrade to a compatible version at or above {vuln.get('FixedVersion')} if validated; assess compatibility and transitive dependency constraints." if vuln.get("FixedVersion") else "Review the advisory and vendor guidance; no fixed version was reported."),references=[str(vuln.get("PrimaryURL"))] if vuln.get("PrimaryURL") else []))
            for mis in result.get("Misconfigurations",[]) or []:
                if not isinstance(mis,dict): continue
                sev=SEVERITY_MAP.get(str(mis.get("Severity","UNKNOWN")).upper(),"medium")
                findings.append(finding(scanner="trivy-config",category="infrastructure-configuration",rule_id=str(mis.get("ID","trivy-misconfig")),
                    title=str(mis.get("Title") or mis.get("ID") or "Infrastructure misconfiguration"),description=str(mis.get("Message") or "Trivy reported a configuration problem."),severity=sev,confidence="high",path=target,
                    line=(mis.get("CauseMetadata") or {}).get("StartLine"),evidence=f"type={result_type}; resolution={mis.get('Resolution','')}",recommendation=str(mis.get("Resolution") or "Apply the relevant secure configuration rule and verify the deployment."),references=[str(mis.get("PrimaryURL"))] if mis.get("PrimaryURL") else []))
            for secret in result.get("Secrets",[]) or []:
                if not isinstance(secret,dict): continue
                sev=SEVERITY_MAP.get(str(secret.get("Severity","HIGH")).upper(),"high")
                findings.append(finding(scanner="trivy-secret",category="secrets",rule_id=str(secret.get("RuleID","trivy-secret")),
                    title=str(secret.get("Title") or "Potential secret detected"),description="Trivy reported a possible secret. The secret value is intentionally excluded from the AIShield report.",severity=sev,confidence="medium",path=target,
                    line=secret.get("StartLine"),evidence="Secret value redacted",recommendation="Validate without copying the value into logs, rotate if real, remove from source/history, and move it to managed secrets."))
            forbidden={x.strip().lower() for x in os.getenv("AISECURITY_FORBIDDEN_LICENSES","").split(",") if x.strip()}
            for lic in result.get("Licenses",[]) or []:
                if not isinstance(lic,dict): continue
                lname=str(lic.get("Name") or lic.get("License") or "unknown")
                if forbidden and any(blocked in lname.lower() for blocked in forbidden):
                    findings.append(finding(scanner="trivy-license",category="license-compliance",rule_id="license-policy",title=f"Dependency license matches forbidden policy: {lname}",description="The detected dependency license matches an operator-specified forbidden-license pattern.",severity="medium",confidence="medium",path=target,evidence=f"package={lic.get('PkgName','unknown')}; license={lname}",recommendation="Review legal/compliance requirements and replace or explicitly approve the dependency through your organization’s license policy."))
        if proc.returncode not in (0,1):
            findings.append(finding(scanner="trivy",category="coverage",title="Trivy scan did not complete cleanly",description="Trivy returned a non-standard status. Results may be incomplete.",severity="low",confidence="high",evidence=(proc.stderr or proc.stdout)[-700:],recommendation="Check the Trivy database update, supported file type and available network access."))
    except subprocess.TimeoutExpired:
        outfile.unlink(missing_ok=True)
        status={"status":"timeout"}
        findings.append(finding(scanner="trivy",category="coverage",title="Trivy scan timed out",description="Trivy exceeded the configured scan timeout.",severity="low",confidence="high",recommendation="Review repository size and runner capacity; tune limits for known repository workloads."))
    except OSError as exc:
        outfile.unlink(missing_ok=True)
        status={"status":"execution_error"}
        findings.append(finding(scanner="trivy",category="coverage",title="Trivy could not execute",description="The scanner process could not be started; scan coverage is incomplete.",severity="low",confidence="high",evidence=type(exc).__name__,recommendation="Verify the engine image, executable permissions, and runner environment."))
    write_stage("infrastructure",findings,{"status":status,"tools":["trivy fs vulnerability scanning","Trivy misconfiguration scanning","Trivy secret scanning"],"inventory_file_count":inv.get("file_count",0)})
    print(f"Infrastructure scan: {len(findings)} finding(s)")

if __name__=="__main__": run()
