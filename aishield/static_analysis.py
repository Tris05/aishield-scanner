from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from .common import finding, get_inventory, repo_root, reports_dir, write_stage
from .inventory import scan_tree

TIMEOUT = int(os.getenv("AISECURITY_TOOL_TIMEOUT", "900"))


def run_cmd(args: list[str], cwd: Path, timeout: int = TIMEOUT) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8",errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)


def run() -> None:
    root = repo_root(); inv = get_inventory(root); findings=[]; tools={}
    report_dir = reports_dir()
    if shutil.which("semgrep"):
        rules = Path(os.getenv("AISECURITY_RULES_FILE", "/opt/aishield/rules/ai-security.yml"))
        if not rules.exists(): rules = Path(__file__).resolve().parent.parent / "rules" / "ai-security.yml"
        if rules.exists():
            raw_fd, raw_name = tempfile.mkstemp(prefix="aishield-semgrep-", suffix=".json")
            os.close(raw_fd)
            outfile = Path(raw_name)
            semgrep_cmd = ["semgrep", "scan", "--config", str(rules), "--json", "--output", str(outfile)]
            for excluded in (".git", "node_modules", ".venv", "venv", "aishield-reports", ".terraform"):
                semgrep_cmd.extend(["--exclude", excluded])
            rc, stdout, stderr = run_cmd([*semgrep_cmd, str(root)], root)
            payload={}
            try: payload=json.loads(outfile.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                try: payload=json.loads(stdout or "{}")
                except json.JSONDecodeError: payload={}
            finally: outfile.unlink(missing_ok=True)
            for item in payload.get("results", []) if isinstance(payload,dict) else []:
                extra=item.get("extra",{}) or {}; sev=str(extra.get("severity","WARNING")).lower()
                sevmap={"error":"high","warning":"medium","info":"low"}
                findings.append(finding(scanner="semgrep", category="sast", rule_id=item.get("check_id","semgrep"),
                    title=extra.get("message") or item.get("check_id","Static analysis finding"),
                    description=extra.get("message") or "Semgrep reported a matching custom security rule.",
                    severity=sevmap.get(sev, "medium"), confidence="high", path=item.get("path",""),
                    line=(item.get("start",{}) or {}).get("line"), evidence="Source snippet omitted from reports; review the finding at the listed location.",
                    recommendation="Review the data flow and replace the unsafe API/pattern with a constrained, validated alternative."))
            tools["semgrep"]={"exit_code":rc,"results":len(payload.get("results",[])) if isinstance(payload,dict) else None,"rules":str(rules)}
            if rc not in (0, 1): findings.append(finding(scanner="semgrep", category="coverage", title="Semgrep scan incomplete", description="Semgrep returned an error; raw tool output is not copied into report artifacts because it may contain source context.", severity="low", confidence="high", evidence=f"exit_code={rc}", recommendation="Review the job logs in a trusted environment, correct scanner setup/ruleset errors, and rerun."))
        else:
            findings.append(finding(scanner="semgrep", category="coverage", title="AIShield Semgrep ruleset missing", description="The configured local AI security ruleset was not found.", severity="low", confidence="high", recommendation="Rebuild the engine with rules/ai-security.yml installed."))
    else:
        findings.append(finding(scanner="static-analysis", category="coverage", title="Semgrep is unavailable", description="The static-analysis CLI was not found.", severity="low", confidence="high", recommendation="Use the AIShield engine image built with its pinned requirements."))

    py_files=[e["path"] for e in inv.get("files",[]) if e.get("suffix")==".py" and not e["path"].startswith((".git/","node_modules/"))]
    if py_files and shutil.which("bandit"):
        raw_fd, raw_name = tempfile.mkstemp(prefix="aishield-bandit-", suffix=".json")
        os.close(raw_fd)
        outfile=Path(raw_name)
        rc,stdout,stderr=run_cmd(["bandit","-r",str(root),"-f","json","-o",str(outfile),"-x", ".git,node_modules,.venv,venv,build,dist,aishield-reports,.terraform"],root)
        payload={}
        try: payload=json.loads(outfile.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError):
            try: payload=json.loads(stdout or "{}")
            except json.JSONDecodeError: payload={}
        finally: outfile.unlink(missing_ok=True)
        for item in payload.get("results",[]) if isinstance(payload,dict) else []:
            sev=str(item.get("issue_severity","MEDIUM")).lower()
            mapping={"high":"high","medium":"medium","low":"low"}
            findings.append(finding(scanner="bandit", category="sast", rule_id=item.get("test_id","bandit"), title=item.get("issue_text","Python security issue"),
                description=item.get("issue_text","Bandit reported a Python security pattern."), severity=mapping.get(sev,"medium"), confidence=str(item.get("issue_confidence","MEDIUM")).lower(),
                path=item.get("filename",""),line=item.get("line_number"), evidence="Source snippet omitted from reports; review the finding at the listed location.", recommendation="Review the specific API and use a safer alternative or document a narrowly scoped false-positive suppression."))
        tools["bandit"]={"exit_code":rc,"results":len(payload.get("results",[])) if isinstance(payload,dict) else None}
        if rc not in (0,1): findings.append(finding(scanner="bandit", category="coverage", title="Bandit scan incomplete", description="Bandit did not complete successfully; raw tool output is not copied into report artifacts.", severity="low", confidence="high", evidence=f"exit_code={rc}", recommendation="Review job logs in a trusted environment, fix the scanner configuration, and rerun."))
    elif py_files:
        findings.append(finding(scanner="static-analysis", category="coverage", title="Bandit is unavailable", description="Python files exist but Bandit did not run.", severity="low", confidence="high", recommendation="Use the AIShield engine image or install its pinned requirements."))

    # Deterministic supplementary rules for common AI-app hazards. These are indicators, not proof of exploitability.
    text_exts={".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".ipynb",".yaml",".yml",".toml",".json",".md",".txt",".sh",".tf",".sql",".ini",".cfg"}
    patterns=[
      (re.compile(r"\bverify\s*=\s*False\b"),"TLS certificate verification disabled","high","Avoid disabling TLS certificate verification; configure a trusted CA bundle instead."),
      (re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]{0,400}\bshell\s*=\s*True",re.I),"Shell execution enabled in subprocess call","high","Prefer argument arrays with shell=False and validate any user-controlled arguments."),
      (re.compile(r"\beval\s*\("),"Dynamic eval() usage","high","Avoid evaluating data as code. Use a safe parser or a constrained, explicit dispatch map."),
      (re.compile(r"\bexec\s*\("),"Dynamic exec() usage","high","Avoid dynamically executing strings. Replace with explicit operations and strict input validation."),
      (re.compile(r"\bpickle\.(?:load|loads)\s*\("),"Pickle deserialization detected","high","Never load pickle data from an untrusted source. Prefer safer formats and integrity/provenance checks."),
      (re.compile(r"\btorch\.load\s*\("),"PyTorch model loading pattern requires review","medium","Prefer weights_only=True where supported and appropriate, pin trusted artifacts, and never load untrusted checkpoints."),
      (re.compile(r"\brequests\.(?:get|post|put|delete)\s*\([^\n]{0,300}\bverify\s*=\s*False",re.I),"HTTP client disables TLS verification","high","Keep TLS verification enabled and configure a trusted CA bundle."),
      (re.compile(r"\bos\.system\s*\("),"OS command constructed through os.system","high","Use subprocess with an argument list and shell=False; avoid passing untrusted values to commands."),
    ]
    for ent in inv.get("files",[]):
        if not ent.get("is_text_candidate") or (ent.get("suffix") not in text_exts and str(ent.get("name", "")).lower() != "dockerfile"): continue
        p=root/ent["path"]
        try: lines=p.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError: continue
        for lineno,line in enumerate(lines,1):
            if len(line)>4000: continue
            for rx,title,sev,rec in patterns:
                if rx.search(line):
                    findings.append(finding(scanner="ai-security-rules",category="ai-code-security",rule_id=rx.pattern,title=title,
                        description="A static pattern matched a potentially unsafe operation. Context and reachability require review.",severity=sev,confidence="low" if title.startswith("PyTorch") else "medium",
                        path=ent["path"],line=lineno,evidence="A bounded source line matched the rule; source text is intentionally omitted from reports.",recommendation=rec))
    write_stage("static-analysis", findings, {"tools":tools,"python_file_count":len(py_files),"supplementary_rules":"heuristic; review before treating as confirmed"})
    print(f"Static analysis: {len(findings)} findings")

if __name__ == "__main__": run()
