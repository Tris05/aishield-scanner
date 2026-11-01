from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from .common import finding, get_inventory, repo_root, reports_dir, write_stage
from .inventory import scan_tree

PATTERNS = [
 ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
 ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
 ("generic-api-token", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{20,}"), "high"),
 ("high-entropy-secret-assignment", re.compile(r"(?i)\b(?:password|secret|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"), "medium"),
]
TEXT_EXTS={".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".yaml",".yml",".toml",".json",".md",".txt",".sh",".tf",".sql",".ini",".cfg",".env",".properties"}

# Exclude generated/vendor directories from all secret-scanner backends.
EXCLUDED_DIRS={".git", ".venv", "venv", "node_modules", ".next", "dist", "build", "aishield-reports"}
EXCLUDE_PATH_REGEX = r"(?i)(^|[\\/])(?:\.git|\.venv|venv|node_modules|\.next|dist|build|aishield-reports)([\\/]|$)"

def is_excluded_path(value: str) -> bool:
    normalized = str(value).replace("\\", "/").strip("/")
    parts = [part.lower() for part in normalized.split("/") if part]
    return any(part in EXCLUDED_DIRS for part in parts)


def run() -> None:
    root=repo_root(); inv=get_inventory(root); findings=[]; scanned=0
    max_bytes=int(os.getenv("AISECURITY_MAX_TEXT_FILE_BYTES", str(2*1024*1024)))
    for ent in inv.get("files",[]):
        rel_path = str(ent.get("path", ""))
        if is_excluded_path(rel_path): continue
        if (ent.get("suffix") not in TEXT_EXTS and str(ent.get("name", "")).lower() != "dockerfile") or ent.get("size",0)>max_bytes: continue
        p=root/rel_path
        try: text=p.read_text(encoding="utf-8",errors="ignore")
        except OSError: continue
        scanned+=1
        for lineno,line in enumerate(text.splitlines(),1):
            for rule,rx,sev in PATTERNS:
                match=rx.search(line)
                if not match: continue
                # Do not put the captured credential into findings/logs.
                findings.append(finding(scanner="secret-patterns",category="secrets",rule_id=rule,title=f"Possible secret detected ({rule})",description="A secret-like pattern matched. This is heuristic and must be verified without copying the secret into issue trackers.",severity=sev,confidence="medium" if rule!="high-entropy-secret-assignment" else "low",path=ent["path"],line=lineno,evidence=f"{line[:match.start()]}[REDACTED]{line[match.end():]}"[:500],recommendation="Remove the secret from source, rotate it if real, use a secret manager/masked CI variable, and scan repository history where permitted."))
                break
    tools={}
    if shutil.which("gitleaks"):
        raw_fd, raw_name = tempfile.mkstemp(prefix="aishield-gitleaks-", suffix=".json")
        os.close(raw_fd)
        raw_path=Path(raw_name)
        config_path = None
        try:
            # Extend Gitleaks' built-in rules while excluding generated/vendor directories.
            cfg_fd, cfg_name = tempfile.mkstemp(prefix="aishield-gitleaks-", suffix=".toml")
            os.close(cfg_fd)
            config_path = Path(cfg_name)
            config_path.write_text(
                "[extend]\nuseDefault = true\n\n"
                "[[allowlists]]\ndescription = \"Exclude generated and vendored paths\"\n"
                f"paths = ['{EXCLUDE_PATH_REGEX}']\n",
                encoding="utf-8",
            )
            p=subprocess.run(["gitleaks","dir",str(root),"--config",str(config_path),"--report-format","json","--report-path",str(raw_path),"--redact","100","--no-banner"],cwd=root,text=True,encoding="utf-8",errors="replace",capture_output=True,timeout=int(os.getenv("AISECURITY_TOOL_TIMEOUT","900")),check=False)
            try: items=json.loads(raw_path.read_text(encoding="utf-8"))
            except (OSError,json.JSONDecodeError): items=[]
            finally: raw_path.unlink(missing_ok=True)
            if config_path is not None: config_path.unlink(missing_ok=True)
            for item in items if isinstance(items,list) else []:
                if not isinstance(item,dict): continue
                findings.append(finding(scanner="gitleaks",category="secrets",rule_id=str(item.get("RuleID","gitleaks")),title=f"Potential secret detected ({item.get('RuleID','rule')})",description="Gitleaks reported a possible secret. The secret value is intentionally excluded.",severity="high",confidence="high",path=str(item.get("File","")),line=item.get("StartLine"),evidence="Secret value redacted",recommendation="Validate without exposing the value, rotate if real, remove it from repository/history where applicable, and use managed secrets."))
            tools["gitleaks"]={"exit_code":p.returncode,"findings":len(items) if isinstance(items,list) else None,"raw_report_persisted":False}
            if p.returncode not in (0,1):
                findings.append(finding(scanner="gitleaks",category="coverage",title="Gitleaks scan did not complete cleanly",description="Gitleaks returned a non-standard status; results may be incomplete.",severity="low",confidence="high",evidence=(p.stderr or p.stdout)[-600:],recommendation="Review raw scanner logs and retry."))
        except (OSError,subprocess.TimeoutExpired) as exc:
            tools["gitleaks_error"]=type(exc).__name__
            findings.append(finding(scanner="gitleaks",category="coverage",title="Gitleaks did not complete",description="Secret scanning by Gitleaks failed; regex fallback results are not equivalent coverage.",severity="low",confidence="high",evidence=type(exc).__name__,recommendation="Use the pinned AIShield engine and inspect tool logs."))
    else:
        findings.append(finding(scanner="secrets",category="coverage",title="Gitleaks is unavailable",description="The required high-signal secret scanner did not run. Regex fallback is incomplete.",severity="low",confidence="high",recommendation="Use the published AIShield engine image or explicitly accept the coverage gap."))
    if shutil.which("detect-secrets"):
        try:
            p=subprocess.run(["detect-secrets","scan","--all-files","--exclude-files",EXCLUDE_PATH_REGEX],cwd=root,text=True,encoding="utf-8",errors="replace",capture_output=True,timeout=int(os.getenv("AISECURITY_TOOL_TIMEOUT","900")),check=False)
            try: raw=json.loads(p.stdout or "{}")
            except json.JSONDecodeError: raw={}
            results=raw.get("results",{}) if isinstance(raw,dict) else {}
            tools["detect-secrets"]={"exit_code":p.returncode,"files_with_findings":len(results) if isinstance(results,dict) else 0}
            for rel,items in results.items() if isinstance(results,dict) else []:
                for item in items if isinstance(items,list) else []:
                    findings.append(finding(scanner="detect-secrets",category="secrets",rule_id=str(item.get("type","secret")),title="Potential secret detected by detect-secrets",description="detect-secrets reported a potential secret. Values are intentionally omitted.",severity="high",confidence="medium",path=rel,line=item.get("line_number"),evidence="Secret value redacted",recommendation="Validate without exposing the value, rotate if real, and remove from source/history if needed."))
            if p.returncode not in (0, 1):
                findings.append(finding(scanner="detect-secrets",category="coverage",title="detect-secrets returned an error",description="The secondary secret scanner returned a non-standard exit code; results may be incomplete.",severity="low",confidence="high",evidence=f"exit_code={p.returncode}",recommendation="Review detect-secrets output and rerun."))
        except (OSError,subprocess.TimeoutExpired) as exc:
            tools["detect-secrets_error"]=type(exc).__name__
            findings.append(finding(scanner="detect-secrets",category="coverage",title="detect-secrets did not complete",description="The secondary secret scanner failed; fallback and Gitleaks findings may still be available.",severity="low",confidence="high",evidence=type(exc).__name__,recommendation="Review scanner installation/configuration and rerun."))
    else:
        findings.append(finding(scanner="secrets",category="coverage",title="detect-secrets is unavailable",description="The secondary entropy/secret detector did not run.",severity="low",confidence="high",recommendation="Use the published AIShield engine image or explicitly accept the coverage gap."))
    write_stage("secrets",findings,{"text_files_scanned":scanned,"tools":tools,"secret_values_redacted":True})
    print(f"Secret scan: {len(findings)} findings")

if __name__ == "__main__": run()
