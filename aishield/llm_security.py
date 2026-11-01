from __future__ import annotations
import re
from pathlib import Path
from .common import finding, get_inventory, repo_root, write_stage
from .inventory import scan_tree

RULES = [
 (re.compile(r"\b(?:eval|exec)\s*\([^\n]*(?:response|completion|llm|model_output|generated_text)", re.I), "LLM output may flow into dynamic code execution", "high", "medium", "Constrain the flow: treat model output as untrusted data, use a strict schema, and never execute generated text."),
 (re.compile(r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\([^\n]*(?:response|completion|llm|model_output|generated_text)", re.I), "LLM output may influence an operating-system command", "critical", "low", "Do not construct shell commands from model output. Use a fixed, allowlisted tool interface with typed arguments and authorization."),
 (re.compile(r"\b(?:allow_dangerous_deserialization|trust_remote_code)\s*=\s*True", re.I), "Dangerous deserialization or remote model code explicitly enabled", "high", "medium", "Disable unless essential, pin and review the source, isolate execution, and document why the trust boundary is acceptable."),
 (re.compile(r"\b(?:api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "Possible hardcoded credential assignment", "high", "low", "Move credentials to a secret manager or masked CI variable. Rotate any real credential that was committed."),
 (re.compile(r"\b(?:enable|allow)[_-]?(?:shell|terminal|python|code)[_-]?(?:tool|execution)?\s*[:=]\s*(?:True|true)", re.I), "Code execution capability may be enabled", "high", "low", "Constrain tools with explicit allowlists, least privilege, per-action authorization, timeouts and audit logs."),
]
TEXT_EXTS={".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".ipynb",".yaml",".yml",".toml",".json",".md",".txt",".sh",".tf",".sql",".ini",".cfg"}


def run() -> None:
    root=repo_root(); inv=get_inventory(root); findings=[]; total=0
    ai_type=inv.get("ai_type","unknown")
    dynamic_markers=("openai","anthropic","google.genai","generativeai","langchain","llama_index","llama-index","transformers","inference")
    for ent in inv.get("files",[]):
        if not ent.get("is_text_candidate") or ent.get("suffix") not in TEXT_EXTS: continue
        p=root/ent["path"]
        try: lines=p.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError: continue
        joined="\n".join(lines).lower(); has_llm=any(x in joined for x in dynamic_markers)
        for i,line in enumerate(lines,1):
            if len(line)>4000: continue
            for rx,title,sev,conf,rec in RULES:
                if rx.search(line):
                    # Secret candidates are owned by the secret scanner; report a lightweight indicator only.
                    if "credential assignment" in title and any(x in line.lower() for x in ("example", "placeholder", "changeme", "your_", "test_")): continue
                    findings.append(finding(scanner="llm-security-static",category="llm-application-security" if has_llm or ai_type=="llm_application" else "secure-coding",title=title,description="Heuristic static indicator. This is not a confirmed exploit; validate control flow and trust boundaries.",severity=sev,confidence=conf,path=ent["path"],line=i,evidence=line.strip(),recommendation=rec,references=["https://genai.owasp.org/llm-top-10/"]))
                    total+=1
    if ai_type=="llm_application":
        # Architecture detection is a coverage aid, not a vulnerability finding.
        findings.append(finding(scanner="llm-security-static",category="llm-runtime-coverage",title="LLM application detected; runtime security tests are separate",description="AIShield found LLM/framework indicators. Static analysis does not establish resistance to prompt injection, data leakage, unsafe tool calls or RAG authorization bypass.",severity="info",confidence="high",evidence=str(inv.get("detected_markers",{})),recommendation="Run the opt-in authorized red-team stage against a test deployment with synthetic canary data and a documented test contract."))
    write_stage("llm-security",findings,{"ai_type":ai_type,"heuristic_matches":total,"runtime_tests_run":False})
    print(f"LLM security static stage: {len(findings)} findings; type={ai_type}")

if __name__ == "__main__": run()
