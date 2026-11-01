"""Upload normalized scan reports to the hosted AIShield Dashboard."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

from .common import reports_dir, repo_root


def git_value(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def normalize_repo_url(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if (parsed.scheme != "https" or parsed.hostname not in {"github.com", "gitlab.com"}
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.query or parsed.fragment):
        raise ValueError("Repository URL must be a public HTTPS GitHub or GitLab URL without credentials.")
    path = parsed.path.rstrip("/")
    if not path or path == "/":
        raise ValueError("Repository URL must include its owner/group and repository name.")
    if path.endswith(".git"):
        path = path[:-4]
    return f"https://{parsed.hostname}{path}"


def upload(required: bool = False) -> dict:
    base_url = os.getenv("AISECURITY_DASHBOARD_URL", "").strip().rstrip("/")
    token = os.getenv("AISECURITY_UPLOAD_TOKEN", "").strip()
    if not base_url or not token:
        message = "AIShield Dashboard upload is not configured (AISECURITY_DASHBOARD_URL / AISECURITY_UPLOAD_TOKEN)."
        if required:
            raise RuntimeError(message)
        print(f"[AIShield] {message}", file=sys.stderr)
        return {"status": "skipped", "message": message}

    report_path = reports_dir() / "report.json"
    if not report_path.is_file():
        raise RuntimeError("report.json was not generated; cannot upload this scan.")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    root = repo_root()
    raw_url = os.getenv("AISECURITY_REPOSITORY_URL", "").strip() or os.getenv("CI_PROJECT_URL", "").strip()
    if not raw_url:
        remote = git_value(root, "remote", "get-url", "origin")
        raw_url = remote
    repository_url = normalize_repo_url(raw_url)
    branch = os.getenv("AISECURITY_BRANCH", "").strip() or git_value(root, "branch", "--show-current") or os.getenv("CI_COMMIT_REF_NAME", "")
    commit_sha = git_value(root, "rev-parse", "HEAD") or os.getenv("CI_COMMIT_SHA", "")
    payload = {
        "repository_url": repository_url,
        "branch": branch or "default",
        "commit_sha": commit_sha or None,
        "scan_status": str(report.get("status", report.get("execution_summary", {}).get("status", "completed"))),
        "scanner_version": "0.1.0",
        "ci": {"provider": "gitlab", "pipeline_url": os.getenv("CI_PIPELINE_URL"), "job_url": os.getenv("CI_JOB_URL"), "pipeline_id": os.getenv("CI_PIPELINE_ID")},
        "report": report,
    }
    timeout = float(os.getenv("AISECURITY_UPLOAD_TIMEOUT_SECONDS", "30"))
    response = requests.post(
        f"{base_url}/api/v1/scans/upload",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=(5, timeout),
        allow_redirects=False,
    )
    if 300 <= response.status_code < 400:
        raise RuntimeError("Dashboard upload endpoint redirected the request; the uploader does not follow redirects with its bearer token.")
    response.raise_for_status()
    result = response.json()
    dashboard_url = result.get("dashboard_url")
    print("\n[AIShield] Scan report uploaded successfully.")
    if dashboard_url:
        print(f"[AIShield] Dashboard: {dashboard_url}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload an AIShield report to the hosted dashboard.")
    parser.add_argument("--required", action="store_true", help="Fail if upload cannot be completed.")
    args = parser.parse_args()
    try:
        upload(required=args.required)
        return 0
    except Exception as exc:
        print(f"[AIShield] Dashboard upload failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
