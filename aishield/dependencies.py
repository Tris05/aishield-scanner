from __future__ import annotations
import json, os, shutil, subprocess, tempfile
from pathlib import Path
from typing import Any
from .common import finding, get_inventory, repo_root, reports_dir, write_stage
from .inventory import scan_tree

MAX_MANIFESTS = max(1, min(200, int(os.getenv("AISECURITY_MAX_MANIFESTS", "30"))))
TIMEOUT = int(os.getenv("AISECURITY_TOOL_TIMEOUT", "900"))


def run_cmd(args: list[str], cwd: Path, timeout: int = TIMEOUT) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False,
                           env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"})
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""), f"Timed out after {timeout}s"
    except OSError as exc:
        return 127, "", f"Could not execute scanner: {exc}"


def normalize_pip_audit(payload: Any, relpath: str) -> list[dict[str, Any]]:
    out = []
    deps = payload.get("dependencies", []) if isinstance(payload, dict) else []
    for dep in deps:
        if not isinstance(dep, dict): continue
        for vuln in dep.get("vulns", []) or []:
            if not isinstance(vuln, dict): continue
            aliases = vuln.get("aliases", []) or []
            vid = next((x for x in aliases if str(x).startswith("CVE-")), None) or vuln.get("id", "UNKNOWN")
            fixes = vuln.get("fix_versions", []) or []
            out.append(finding(scanner="pip-audit", category="dependency", rule_id=str(vuln.get("id", vid)),
                title=f"Vulnerable Python dependency: {dep.get('name', 'unknown')} ({vid})",
                description=str(vuln.get("description") or "Known vulnerability reported for this dependency."),
                severity="medium", confidence="high", path=relpath,
                evidence=f"Package={dep.get('name')} version={dep.get('version')} advisory={vuln.get('id')} fixed_versions={', '.join(map(str, fixes)) or 'not provided'}",
                recommendation=(f"Upgrade {dep.get('name')} to a compatible fixed version: {', '.join(map(str, fixes))}." if fixes else "Review the upstream advisory and apply a vendor-supported mitigation; no fix version was reported."),
                references=[f"https://osv.dev/vulnerability/{vuln.get('id')}"],
            ))
    return out


def normalize_osv(payload: Any) -> list[dict[str, Any]]:
    out=[]
    results=payload.get("results",[]) if isinstance(payload,dict) else []
    for result in results if isinstance(results,list) else []:
        if not isinstance(result,dict): continue
        source=result.get("source",{}) or {}
        source_path=str(source.get("path", ""))
        for pkg in result.get("packages",[]) or []:
            if not isinstance(pkg,dict): continue
            meta=pkg.get("package",{}) or {}
            name=str(meta.get("name","unknown")); version=str(meta.get("version","unknown")); ecosystem=str(meta.get("ecosystem","unknown"))
            for vuln in pkg.get("vulnerabilities",[]) or []:
                if not isinstance(vuln,dict): continue
                vid=str(vuln.get("id","OSV-UNKNOWN"))
                aliases=vuln.get("aliases",[]) or []
                cve=next((str(x) for x in aliases if str(x).startswith("CVE-")),vid)
                refs=[str(r.get("url")) for r in (vuln.get("references",[]) or []) if isinstance(r,dict) and r.get("url")]
                db_severity = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
                if db_severity not in {"critical", "high", "medium", "low"}:
                    # Unknown CVSS is not silently labelled critical/high; Trivy/npm scanners may add a scored duplicate.
                    db_severity = "medium"
                out.append(finding(scanner="osv-scanner",category="dependency",rule_id=vid,title=f"Known vulnerability in {name}: {cve}",
                    description=str(vuln.get("summary") or vuln.get("details") or "OSV reports a vulnerability affecting this package version.")[:1000],severity=db_severity,confidence="high",path=source_path,
                    evidence=f"package={name}; ecosystem={ecosystem}; version={version}; advisory={vid}; aliases={','.join(map(str,aliases))}",
                    recommendation="Upgrade to a non-affected compatible version identified in the advisory; verify transitive constraints and rerun the scan.",references=refs or [f"https://osv.dev/vulnerability/{vid}"]))
    return out


def run() -> None:
    root = repo_root()
    from .common import get_inventory
    inv = get_inventory(root)
    findings: list[dict[str, Any]] = []
    tool_status: dict[str, Any] = {}

    # OSV-Scanner extracts packages from lockfiles/manifests; unlike installing target requirements,
    # this default path does not invoke a target repository's package build scripts.
    if shutil.which("osv-scanner"):
        rc, stdout, stderr = run_cmd(["osv-scanner", "scan", "source", "-r", str(root), "--format", "json"], root)
        try: payload = json.loads(stdout or "{}")
        except json.JSONDecodeError: payload = {}
        parsed_osv = isinstance(payload,dict) and isinstance(payload.get("results"),list)
        osv_findings = normalize_osv(payload) if parsed_osv else []
        findings.extend(osv_findings)
        tool_status["osv-scanner"] = {"exit_code": rc, "parsed_results": parsed_osv, "findings":len(osv_findings)}
        if not parsed_osv:
            findings.append(finding(scanner="osv-scanner", category="coverage", title="OSV-Scanner output could not be parsed", description="OSV-Scanner did not produce the expected JSON results array; no clean dependency conclusion can be drawn.", severity="low", confidence="high", evidence=(stderr or stdout)[-500:], recommendation="Check the pinned scanner version and output format, then rerun."))
        if rc not in (0,1):
            findings.append(finding(scanner="osv-scanner", category="coverage", title="OSV-Scanner did not complete", description="OSV-Scanner returned an error; dependency coverage is incomplete.", severity="low", confidence="high", evidence=(stderr or stdout)[-800:], recommendation="Resolve scanner/database errors and rerun."))
    else:
        findings.append(finding(scanner="dependencies", category="coverage", title="OSV-Scanner is unavailable", description="Static dependency scanning was not completed by OSV-Scanner.", severity="low", confidence="high", evidence="osv-scanner executable not found", recommendation="Use the official AIShield engine image with pinned scanner binaries."))

    # npm audit is opt-in because it sends package metadata to the npm registry.
    # It runs from a temporary directory containing only package.json + lockfile, never the project tree.
    package_locks = [x for x in inv.get("lockfiles", []) if x.endswith(("package-lock.json", "npm-shrinkwrap.json"))]
    npm_audit_enabled = os.getenv("AISECURITY_ENABLE_NPM_AUDIT", "false").lower() == "true"
    if package_locks and not npm_audit_enabled:
        tool_status["npm-audit"] = {"status": "skipped_opt_in_required", "lockfiles_detected": len(package_locks)}
    elif package_locks and not shutil.which("npm"):
        findings.append(finding(scanner="dependencies", category="coverage", title="npm is unavailable for JavaScript dependency audit", description="A package-lock file exists and npm audit was explicitly enabled, but npm was not found.", severity="low", confidence="high", evidence="npm executable not found", recommendation="Use the published AIShield engine or install the expected pinned Node.js/npm toolchain."))
    elif package_locks:
        for rel in package_locks[:MAX_MANIFESTS]:
            lock_path = root / rel
            lock_dir = lock_path.parent.resolve()
            package_path = lock_dir / "package.json"
            if not lock_dir.is_relative_to(root.resolve()) or lock_path.is_symlink() or not lock_path.is_file():
                findings.append(finding(scanner="npm-audit", category="coverage", title="Unsafe npm lockfile path rejected", description="The lockfile path escaped the repository root, was a symlink, or was not a regular file.", severity="low", confidence="high", path=rel, recommendation="Review repository checkout integrity and retry."))
                continue
            if not package_path.is_file() or package_path.is_symlink():
                findings.append(finding(scanner="npm-audit", category="coverage", title="npm audit skipped because package.json is missing or unsafe", description="npm audit expects a regular package.json alongside the lockfile.", severity="low", confidence="high", path=rel, recommendation="Add a valid package manifest or rely on OSV/Trivy coverage for this lockfile."))
                continue
            if lock_path.stat().st_size > 15 * 1024 * 1024 or package_path.stat().st_size > 2 * 1024 * 1024:
                findings.append(finding(scanner="npm-audit", category="coverage", title="npm audit input exceeded size limit", description="The manifest or lockfile exceeded the bounded copy size and was not sent to the npm registry.", severity="low", confidence="high", path=rel, recommendation="Review manifest size and use OSV/Trivy or scan this project with an approved custom workflow."))
                continue
            lock_name = lock_path.name
            with tempfile.TemporaryDirectory(prefix="aishield-npm-audit-") as tmp:
                tmp_path = Path(tmp)
                shutil.copyfile(package_path, tmp_path / "package.json")
                shutil.copyfile(lock_path, tmp_path / lock_name)
                audit_env = {k: v for k, v in os.environ.items() if not k.upper().startswith("NPM_CONFIG_") and k not in {"NODE_OPTIONS"}}
                audit_env.update({"npm_config_registry": "https://registry.npmjs.org/", "npm_config_userconfig": os.devnull,
                                  "npm_config_globalconfig": os.devnull, "npm_config_audit": "true", "npm_config_fund": "false",
                                  "npm_config_ignore_scripts": "true", "CI": "true"})
                try:
                    p = subprocess.run(["npm", "audit", "--json", "--package-lock-only"], cwd=tmp_path, env=audit_env,
                                       text=True, capture_output=True, timeout=TIMEOUT, check=False)
                    rc, stdout, stderr = p.returncode, p.stdout, p.stderr
                except subprocess.TimeoutExpired:
                    rc, stdout, stderr = 124, "", "timeout"
                except OSError as exc:
                    rc, stdout, stderr = 127, "", type(exc).__name__
            try: payload = json.loads(stdout or "{}")
            except json.JSONDecodeError: payload = {}
            npm_payload_valid = isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), dict)
            vulns = payload.get("vulnerabilities", {}) if isinstance(payload, dict) else {}
            if isinstance(vulns, dict):
                for name, v in vulns.items():
                    if not isinstance(v, dict): continue
                    sev = str(v.get("severity", "medium")).lower()
                    findings.append(finding(scanner="npm-audit", category="dependency", rule_id=f"npm:{name}", title=f"Vulnerable npm dependency: {name}",
                        description="npm audit reported an advisory for this dependency.", severity=sev if sev in {"critical", "high", "medium", "low"} else "medium", confidence="high", path=rel,
                        evidence=f"severity={sev}; direct={v.get('isDirect')}; range={v.get('range')}; fixAvailable={v.get('fixAvailable')}",
                        recommendation="Review the advisory and update to a compatible, non-vulnerable release; inspect breaking changes before accepting."))
            tool_status[f"npm-audit:{rel}"] = {"exit_code": rc, "vulnerability_groups": len(vulns) if isinstance(vulns, dict) else 0, "registry": "https://registry.npmjs.org/"}
            if rc not in (0, 1) or not npm_payload_valid or (isinstance(payload, dict) and "error" in payload):
                findings.append(finding(scanner="npm-audit", category="coverage", title=f"npm audit could not complete: {rel}", description="npm audit did not produce a valid advisory payload; dependency status is unknown. Raw tool output is not saved to the report.", severity="low", confidence="high", path=rel, evidence=f"exit_code={rc}; error_type={stderr if stderr in {'timeout'} else 'see CI log'}", recommendation="Check registry connectivity and lockfile correctness, then rerun in the isolated temporary input directory."))
        if len(package_locks) > MAX_MANIFESTS:
            findings.append(finding(scanner="dependencies", category="coverage", title="npm lockfile scan limit reached", description="Only the first configured maximum number of npm lockfiles were scanned.", severity="low", confidence="high", evidence=f"detected={len(package_locks)}; max={MAX_MANIFESTS}", recommendation="Review unscanned lockfiles and increase AISECURITY_MAX_MANIFESTS only when runner capacity permits."))

    # pip-audit requirement resolution is optional because resolving untrusted distributions may exercise build backends.
    # Prefer OSV's static manifest/lockfile extraction for public, untrusted repositories.
    if os.getenv("AISECURITY_ENABLE_PIP_AUDIT_RESOLUTION", "false").lower() == "true" and shutil.which("pip-audit"):
        manifests = [e["path"] for e in inv.get("files",[]) if e.get("name","").lower().startswith("requirements") and e.get("name","").lower().endswith(".txt")][:MAX_MANIFESTS]
        for rel in manifests:
            rc, stdout, stderr = run_cmd(["pip-audit", "-r", rel, "--format", "json"], root)
            try: payload = json.loads(stdout or "{}")
            except json.JSONDecodeError: payload = {}
            findings.extend(normalize_pip_audit(payload, rel))
            tool_status[f"pip-audit:{rel}"] = {"exit_code": rc, "explicitly_enabled": True}
            if rc not in (0, 1): findings.append(finding(scanner="pip-audit",category="coverage",title=f"pip-audit could not complete: {rel}",description="Optional pip-audit dependency resolution failed; result is inconclusive.",severity="low",confidence="high",path=rel,evidence=(stderr or stdout)[-600:],recommendation="Use only inside a disposable, network-restricted sandbox after reviewing dependency-resolution risks."))
    elif os.getenv("AISECURITY_ENABLE_PIP_AUDIT_RESOLUTION", "false").lower() == "true":
        findings.append(finding(scanner="pip-audit",category="coverage",title="pip-audit resolution requested but tool unavailable",description="The optional dependency-resolution mode was explicitly enabled, but pip-audit was not found.",severity="low",confidence="high",recommendation="Use the published AIShield engine image or disable this optional mode after review."))
    write_stage("dependencies", findings, {"tools": tool_status, "lockfiles": inv.get("lockfiles", []), "default_dependency_mode":"static lockfile/manifest extraction; no target package install"})
    print(f"Dependency scan: {len(findings)} findings")

if __name__ == "__main__": run()
