from __future__ import annotations
import hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
from .common import finding, get_inventory, repo_root, reports_dir, write_stage
from .inventory import scan_tree

MAX_ARTIFACTS = max(1, min(1000, int(os.getenv("AISECURITY_MAX_MODEL_ARTIFACTS", "100"))))
TIMEOUT = int(os.getenv("AISECURITY_TOOL_TIMEOUT", "900"))


def run() -> None:
    root=repo_root(); inv=get_inventory(root); findings=[]; scanned=0; skipped=[]
    artifacts=inv.get("model_artifacts",[])[:MAX_ARTIFACTS]
    manifest=[]
    hash_budget=int(os.getenv("AISECURITY_MAX_TOTAL_MODEL_HASH_BYTES", str(4*1024*1024*1024)))
    hashed_bytes=0
    model_card_present=any((root/p).is_file() for p in ("MODEL_CARD.md","model-card.md","model_card.md"))
    if len(inv.get("model_artifacts",[]))>MAX_ARTIFACTS:
        findings.append(finding(scanner="model-security",category="coverage",title="Model artifact scan limit reached",description="Only the first configured maximum number of model artifacts were considered.",severity="low",confidence="high",evidence=f"detected={len(inv['model_artifacts'])}; max={MAX_ARTIFACTS}",recommendation="Review inventory.json and raise the limit for trusted repositories if resources permit."))
    for art in artifacts:
        rel=art["path"]; path=root/rel; size=art.get("size",0)
        if size > int(os.getenv("AISECURITY_MAX_SINGLE_ARTIFACT_BYTES", str(2*1024*1024*1024))):
            skipped.append(rel)
            manifest.append({"path":rel,"format":Path(rel).suffix.lower().lstrip("."),"size_bytes":size,"sha256":None,"hash_status":"single_artifact_size_limit","model_card_present":model_card_present})
            findings.append(finding(scanner="model-security",category="coverage",title="Model artifact exceeded scan-size limit",description="Artifact inspection was skipped because the file exceeded the configured safety limit.",severity="low",confidence="high",path=rel,evidence=f"bytes={size}",recommendation="Scan this artifact in a separately provisioned isolated environment."))
            continue
        suffix=path.suffix.lower()
        artifact_meta={"path":rel,"format":suffix.lstrip("."),"size_bytes":size,"sha256":None,"hash_status":"not_hashed","model_card_present":model_card_present}
        if size <= hash_budget - hashed_bytes:
            digest=hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024*1024), b""):
                        digest.update(chunk)
                artifact_meta["sha256"]=digest.hexdigest(); artifact_meta["hash_status"]="complete"; hashed_bytes += size
            except OSError:
                artifact_meta["hash_status"]="read_error"
        else:
            artifact_meta["hash_status"]="total_hash_budget_exceeded"
        manifest.append(artifact_meta)
        if suffix in {".pkl", ".pickle", ".joblib"}:
            findings.append(finding(scanner="model-security",category="model-artifact",title="Python pickle-based model artifact detected",description="Pickle-family artifacts can execute code during deserialization if malicious. Format presence is a risk indicator, not proof of malicious content.",severity="medium",confidence="high",path=rel,evidence=f"format={suffix}; size={size}; sha256={'computed' if artifact_meta['sha256'] else 'not computed'}",recommendation="Never load this file from an untrusted source. Verify provenance and checksum; prefer safer formats such as safetensors or ONNX when appropriate."))
        if not model_card_present:
            findings.append(finding(scanner="model-security",category="model-provenance",title="Model card or provenance documentation not found at repository root",description="No common root-level model card was found; model identity, intended use and provenance may be undocumented.",severity="low",confidence="medium",path=rel,evidence="No MODEL_CARD.md/model-card.md/model_card.md at root",recommendation="Document source, framework/version, model revision, checksum, training-data lineage, intended use and limitations."))
        import importlib.util
        pickle_family = suffix in {".pkl", ".pickle", ".joblib"}
        hdf5_family = suffix in {".h5", ".hdf5"} and importlib.util.find_spec("h5py") is not None
        supported_for_modelscan = pickle_family or hdf5_family
        if shutil.which("modelscan") and supported_for_modelscan:
            raw_fd, raw_name = tempfile.mkstemp(prefix="aishield-modelscan-", suffix=".json")
            os.close(raw_fd)
            outfile=Path(raw_name)
            try:
                p=subprocess.run(["modelscan","-p",str(path),"-r","json","-o",str(outfile)],cwd=root,text=True,capture_output=True,timeout=TIMEOUT,check=False)
                try: payload=json.loads(outfile.read_text(encoding="utf-8"))
                except (OSError,json.JSONDecodeError):
                    try: payload=json.loads(p.stdout or "{}")
                    except json.JSONDecodeError: payload={}
                finally: outfile.unlink(missing_ok=True)
                # ModelScan's JSON schema varies by version. Check both detailed issue arrays and summary counts.
                serialized=json.dumps(payload,ensure_ascii=False)
                summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
                issue_count = 0
                if isinstance(summary, dict):
                    try: issue_count = int(summary.get("total_issues", summary.get("totalIssues", 0)) or 0)
                    except (TypeError, ValueError): issue_count = 0
                issue_payload = isinstance(payload, dict) and bool(payload.get("issues") or payload.get("findings") or issue_count > 0)
                if issue_payload:
                    findings.append(finding(scanner="modelscan",category="model-artifact",title="ModelScan reported unsafe model serialization indicators",description="ModelScan produced one or more artifact findings. Detailed scanner output is not persisted to report artifacts; review the pipeline logs and rerun in an isolated environment if details are required.",severity="high",confidence="high",path=rel,evidence=f"ModelScan reported issues; summary_count={issue_count if issue_count else 'not provided'}",recommendation="Do not deserialize the artifact until the ModelScan findings are triaged; re-export from a trusted source if necessary."))
                scanned+=1
                if p.returncode not in (0,1):
                    findings.append(finding(scanner="modelscan",category="coverage",title="ModelScan could not fully inspect an artifact",description="The scanner returned an error or unsupported-format result; absence of findings is inconclusive.",severity="low",confidence="high",path=rel,evidence=(p.stderr or p.stdout)[-700:],recommendation="Review supported formats and raw report; use a format-specific safe scanner where supported."))
            except subprocess.TimeoutExpired:
                outfile.unlink(missing_ok=True)
                findings.append(finding(scanner="modelscan",category="coverage",title="ModelScan timed out",description="Artifact analysis exceeded the configured timeout.",severity="low",confidence="high",path=rel,recommendation="Run this artifact in a separately provisioned isolated job."))
            except OSError as exc:
                outfile.unlink(missing_ok=True)
                findings.append(finding(scanner="modelscan",category="coverage",title="ModelScan could not execute",description="The scanner process could not be started; model artifact coverage is incomplete.",severity="low",confidence="high",path=rel,evidence=type(exc).__name__,recommendation="Verify ModelScan installation and execute in a controlled isolated environment."))
        else:
            skipped.append(rel)
            reason = "The engine does not have the optional h5py dependency required for HDF5 model inspection." if suffix in {".h5", ".hdf5"} else "The selected ModelScan integration does not deeply inspect this format in the current lightweight engine image."
            if not supported_for_modelscan:
                findings.append(finding(scanner="model-security",category="model-format-coverage",title=f"ModelScan did not deeply inspect this detected format: {suffix or 'unknown'}",description=f"The artifact was inventoried and hashed if within budget. {reason} No claim of behavioral model safety is made.",severity="info",confidence="high",path=rel,evidence=f"size={size}; hash_status={artifact_meta['hash_status']}",recommendation="Use a format-specific static validator and controlled runtime evaluation appropriate to this model type."))
    if artifacts and not shutil.which("modelscan") and any(Path(a["path"]).suffix.lower() in {".pkl", ".pickle", ".joblib"} for a in artifacts):
        findings.append(finding(scanner="model-security",category="coverage",title="ModelScan unavailable; supported artifact checks incomplete",description="Potential model artifacts were detected, but ModelScan was not installed. Artifact-format and hashing indicators ran without loading model files.",severity="low",confidence="high",recommendation="Build the engine with the pinned ModelScan dependency or explicitly mark supported formats as not tested."))
    (reports_dir()/"model-artifacts.json").write_text(json.dumps({"schema_version":"1.0","artifact_count":len(inv.get("model_artifacts",[])),"hashed_bytes":hashed_bytes,"artifacts":manifest},indent=2)+"\n",encoding="utf-8")
    write_stage("model-security",findings,{"detected_artifacts":len(inv.get("model_artifacts",[])),"modelscan_inspections":scanned,"skipped":skipped,"hashed_bytes":hashed_bytes,"manifest":"aishield-reports/model-artifacts.json","note":"No model was loaded or executed by AIShield."})
    print(f"Model security: {len(artifacts)} artifacts considered; {len(findings)} findings")

if __name__ == "__main__": run()
