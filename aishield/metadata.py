from __future__ import annotations
import json, os, platform, subprocess
from pathlib import Path
from . import __version__
from .common import reports_dir, repo_root


def main() -> None:
    root=repo_root()
    try:
        commit=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,timeout=3,check=False).stdout.strip() or None
    except Exception: commit=None
    payload={"product":"AIShield","version":__version__,"python":platform.python_version(),"commit":commit,
             "ci_pipeline_id":os.getenv("CI_PIPELINE_ID"),"ci_project_path":os.getenv("CI_PROJECT_PATH"),"ci_job_id":os.getenv("CI_JOB_ID"),
             "scan_time_utc":__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
             "scan_mode":"static-plus-opt-in-runtime-tests","note":"No repository code or model artifact is executed by inventory/static/model stages."}
    (reports_dir()/"scan-metadata.json").write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__": main()
