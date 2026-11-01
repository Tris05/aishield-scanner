"""Smoke benchmark for high-signal custom source rules on seeded positive/negative fixtures."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = {
    "vulnerable": {
        "path": ROOT / "examples" / "vulnerable-demo",
        "expected": {"Pickle deserialization detected", "Shell execution enabled in subprocess call"},
    },
    "benign": {
        "path": ROOT / "examples" / "benign-demo",
        "expected": set(),
    },
}


def evaluate_case(name: str, case: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"aishield-bench-{name}-") as report_dir:
        env = {
            **os.environ,
            "AISECURITY_REPO": str(case["path"].resolve()),
            "AISECURITY_REPORT_DIR": report_dir,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = subprocess.run(
            [sys.executable, "-m", "aishield.static_analysis"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        report = Path(report_dir) / "static-analysis.json"
        if proc.returncode != 0 or not report.is_file():
            raise RuntimeError(f"Benchmark case {name} failed to run; exit_code={proc.returncode}.")
        payload = json.loads(report.read_text(encoding="utf-8"))
        actual = {
            str(f.get("title"))
            for f in payload.get("findings", [])
            if f.get("scanner") == "ai-security-rules"
        }
        return {
            "case": name,
            "expected": sorted(case["expected"]),
            "actual": sorted(actual),
            "matched_expected": sorted(actual & case["expected"]),
            "missed_expected": sorted(case["expected"] - actual),
            "unexpected": sorted(actual - case["expected"]),
            "scanner_exit_code": proc.returncode,
        }


def main() -> int:
    results = [evaluate_case(name, case) for name, case in CASES.items()]
    positives = [r for r in results if r["expected"]]
    tp = sum(len(r["matched_expected"]) for r in positives)
    fn = sum(len(r["missed_expected"]) for r in positives)
    fp = sum(len(r["unexpected"]) for r in results)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    summary = {
        "benchmark": "AIShield seeded source-rule smoke benchmark",
        "ground_truth_cases": sum(len(r["expected"]) for r in results),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision_on_tiny_fixture": round(precision, 4),
        "recall_on_tiny_fixture": round(recall, 4),
        "results": results,
        "limitations": "Tiny seeded fixtures only; not a measure of general production security efficacy.",
    }
    print(json.dumps(summary, indent=2))
    return 0 if fn == 0 and fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
