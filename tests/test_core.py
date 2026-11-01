import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aishield.common import finding, stable_id
from aishield.intake import validate_repository_url
from aishield.inventory import scan_tree
from aishield.mcp_security import inspect_mcp_source
from aishield.dataset_security import inspect_values, row_fingerprint, run as run_dataset_security
from aishield.redteam import validate_target, _read_garak_findings, GARAK_TARGET_TYPES
from aishield.report import normalize_findings, load_findings, run as run_report
from aishield.pipeline import _coverage_matrix, _enrich_scan_status, _execution_summary, _clear_previous_run_artifacts


class CommonTests(unittest.TestCase):
    def test_finding_id_is_stable(self):
        self.assertEqual(stable_id("bandit", "x.py", 3, "unsafe"), stable_id("bandit", "x.py", 3, "unsafe"))
        self.assertNotEqual(stable_id("bandit", "x.py", 3, "unsafe"), stable_id("bandit", "y.py", 3, "unsafe"))

    def test_finding_normalizes_severity_and_path(self):
        f = finding(scanner="test", category="test", title="x", description="y", severity="weird", path="folder\\x.py")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["path"], "folder/x.py")
        self.assertIn("id", f)
        self.assertEqual(f["schema_version"], "1.1")
        self.assertEqual(f["source_scanners"], ["test"])
        self.assertIn("vulnerability_id", f)
        self.assertIn("fixed_version", f)

    def test_finding_redacts_common_secret_shapes(self):
        f = finding(scanner="test", category="test", title="secret", description="x", evidence="api_key=abcdefghijk12345 and AKIA1234567890ABCDEF")
        self.assertNotIn("abcdefghijk12345", f["evidence"])
        self.assertNotIn("AKIA1234567890ABCDEF", f["evidence"])
        self.assertIn("REDACTED", f["evidence"])


class InventoryTests(unittest.TestCase):
    def test_inventory_does_not_follow_symlinks_or_execute_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text("raise RuntimeError('should not execute')\n", encoding="utf-8")
            (root / "model.pkl").write_bytes(b"not a real pickle")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "noise.js").write_text("noise", encoding="utf-8")
            external = root.parent / (root.name + "-external.txt")
            external.write_text("outside", encoding="utf-8")
            try:
                (root / "outside-link.txt").symlink_to(external)
            except OSError:
                pass
            inv = scan_tree(root)
            paths = {x["path"] for x in inv["files"]}
            self.assertIn("app.py", paths)
            self.assertIn("model.pkl", paths)
            self.assertNotIn("node_modules/noise.js", paths)
            self.assertNotIn("outside-link.txt", paths)
            self.assertEqual(len(inv["model_artifacts"]), 1)
            external.unlink(missing_ok=True)

    def test_inventory_detects_llm_rag_mcp_and_api_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text(
                "from fastapi import FastAPI\nfrom openai import OpenAI\nfrom qdrant_client import QdrantClient\nfrom mcp.server.fastmcp import FastMCP\napp = FastAPI()\n",
                encoding="utf-8",
            )
            inv = scan_tree(root)
            self.assertTrue(inv["capabilities"]["api_or_web_application"])
            self.assertTrue(inv["capabilities"]["llm_application"])
            self.assertTrue(inv["capabilities"]["rag_or_vector_retrieval"])
            self.assertTrue(inv["capabilities"]["mcp_enabled"])


class RepositoryIntakeTests(unittest.TestCase):
    @patch("aishield.intake.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("140.82.112.3", 443))])
    def test_public_https_repository_host_is_accepted(self, _mock_dns):
        url, addresses = validate_repository_url("https://github.com/openai/example.git", {"github.com"}, False)
        self.assertEqual(url, "https://github.com/openai/example.git")
        self.assertEqual(addresses, ["140.82.112.3"])

    def test_repository_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_repository_url("https://token@github.com/acme/project.git", {"github.com"}, False)

    @patch("aishield.intake.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))])
    def test_private_repository_resolution_fails_closed(self, _mock_dns):
        with self.assertRaises(ValueError):
            validate_repository_url("https://github.com/acme/project.git", {"github.com"}, False)


class TargetValidationTests(unittest.TestCase):
    def test_redteam_requires_exact_allowlist(self):
        with self.assertRaises(ValueError):
            validate_target("https://example.com/api", set(), False)

    def test_redteam_rejects_http_public_target(self):
        with self.assertRaises(ValueError):
            validate_target("http://example.com/api", {"example.com"}, False)


    def test_garak_jsonl_detector_hits_are_normalized_without_raw_output(self):
        with tempfile.TemporaryDirectory() as temp:
            report_dir = Path(temp)
            (report_dir / "sample.report.jsonl").write_text(json.dumps({
                "entry_type": "attempt",
                "uuid": "attempt-1",
                "probe": "probes.promptinject.SomeProbe",
                "prompt": "do not persist this prompt",
                "outputs": ["do not persist this output"],
                "detector_results": {"detectors.promptinject.SomeDetector": [1.0]},
            }) + "\n", encoding="utf-8")
            findings, attempts = _read_garak_findings(report_dir)
            self.assertEqual(attempts, 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["scanner"], "garak")
            self.assertNotIn("do not persist this output", json.dumps(findings))

    def test_garak_target_type_is_allowlisted(self):
        self.assertIn("openai", GARAK_TARGET_TYPES)
        self.assertIn("llm", GARAK_TARGET_TYPES)
        self.assertNotIn("arbitrary.module.Path", GARAK_TARGET_TYPES)


class MCPSecurityTests(unittest.TestCase):
    def test_mcp_privileged_tool_surface_is_flagged_as_review_indicator(self):
        source = """from mcp.server.fastmcp import FastMCP
mcp = FastMCP('demo')
@mcp.tool()
def run_command(command: str):
    return subprocess.run(command, shell=True)
"""
        results = inspect_mcp_source(source)
        self.assertTrue(any("shell execution" in result[0] for result in results))
        self.assertEqual(next(result for result in results if "shell execution" in result[0])[1], "medium")

    def test_http_transport_without_local_auth_is_only_info(self):
        source = """from mcp.server.fastmcp import FastMCP
app = FastMCP('demo')
app.run(transport='streamable-http')
"""
        results = inspect_mcp_source(source)
        self.assertTrue(any("authentication indicator" in result[0] for result in results))
        self.assertEqual(next(result for result in results if "authentication indicator" in result[0])[1], "info")

    def test_non_mcp_code_not_flagged_by_mcp_scanner(self):
        self.assertEqual(inspect_mcp_source("subprocess.run(user_command, shell=True)"), [])


class DatasetSecurityTests(unittest.TestCase):
    def test_sensitive_value_inspection_returns_counts_not_values(self):
        results = inspect_values(["contact person@example.com", "AKIA1234567890ABCDEF"])
        self.assertEqual(results["email_like"], 1)
        self.assertEqual(results["known_token_shape"], 1)
        self.assertNotIn("person@example.com", repr(results))

    def test_row_fingerprint_is_stable_and_order_independent_for_dicts(self):
        self.assertEqual(row_fingerprint({"a": 1, "b": 2}), row_fingerprint({"b": 2, "a": 1}))
        self.assertNotEqual(row_fingerprint({"a": 1}), row_fingerprint({"a": 2}))


class DatasetStageTests(unittest.TestCase):
    def test_dataset_stage_reports_counts_without_raw_values_and_detects_split_overlap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            reports = Path(temp) / "reports"
            (root / "train.csv").write_text("email,label\nperson@example.com,yes\nrepeat@example.org,no\n", encoding="utf-8")
            (root / "test.csv").write_text("email,label\nperson@example.com,yes\n", encoding="utf-8")
            with patch.dict(os.environ, {"AISECURITY_REPO": str(root), "CI_PROJECT_DIR": str(root), "AISECURITY_REPORT_DIR": str(reports)}):
                scan_tree(root)
                run_dataset_security()
            payload = json.loads((reports / "dataset-security.json").read_text(encoding="utf-8"))
            text = (reports / "dataset-security.json").read_text(encoding="utf-8")
            self.assertTrue(any(f.get("category") == "dataset-privacy" for f in payload["findings"]))
            self.assertTrue(any(f.get("category") == "dataset-integrity" for f in payload["findings"]))
            self.assertNotIn("person@example.com", text)
            self.assertNotIn("repeat@example.org", text)


class OrchestrationAndReportTests(unittest.TestCase):
    def test_cross_scanner_duplicate_cve_is_merged_with_provenance(self):
        findings = [
            {"id": "a", "scanner": "trivy", "category": "dependency", "rule_id": "CVE-2026-12345", "title": "CVE-2026-12345 in libfoo", "severity": "high", "confidence": "high", "path": "requirements.txt", "line": None, "evidence": "package=libfoo; installed=1.0", "references": []},
            {"id": "b", "scanner": "osv-scanner", "category": "dependency", "rule_id": "CVE-2026-12345", "title": "CVE-2026-12345 found", "severity": "critical", "confidence": "medium", "path": "requirements.txt", "line": None, "evidence": "package=libfoo; installed=1.0", "references": ["https://example.test/advisory"]},
        ]
        normalized = normalize_findings(findings)
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["severity"], "critical")
        self.assertEqual(normalized[0]["source_scanners"], ["osv-scanner", "trivy"])
        self.assertIn("https://example.test/advisory", normalized[0]["references"])

    def test_coverage_matrix_marks_dast_disabled_by_default(self):
        with patch.dict(os.environ, {"AISECURITY_ENABLE_DAST": "false"}):
            matrix = _coverage_matrix({"architecture_types": [], "model_artifacts": [], "data_artifacts": []}, [])
        categories = {item["id"]: item for item in matrix["categories"]}
        self.assertEqual(len(categories), 12)
        self.assertEqual(categories["api-and-web-dast"]["status"], "disabled")
        self.assertIn("separate job", categories["api-and-web-dast"]["note"])

    def test_coverage_matrix_marks_dast_conditional_when_enabled(self):
        with patch.dict(os.environ, {"AISECURITY_ENABLE_DAST": "true"}):
            matrix = _coverage_matrix({"architecture_types": [], "model_artifacts": [], "data_artifacts": []}, [])
        categories = {item["id"]: item for item in matrix["categories"]}
        self.assertEqual(categories["api-and-web-dast"]["status"], "conditional")
        self.assertIn("unsafe-model-artifacts", categories)
        self.assertIn("rag-agent-tools-and-mcp", categories)

    def test_inventory_stage_findings_are_not_discarded_by_report_loader(self):
        with tempfile.TemporaryDirectory() as temp:
            reports = Path(temp)
            payload = {"stage": "inventory", "metadata": {}, "findings": [{"id": "inv-1", "scanner": "inventory", "category": "coverage", "title": "Inventory incomplete", "severity": "low"}]}
            (reports / "inventory.json").write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict(os.environ, {"AISECURITY_REPORT_DIR": str(reports)}):
                findings, stages = load_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["title"], "Inventory incomplete")
            self.assertEqual(stages[0]["stage"], "inventory")

    def test_previous_run_artifacts_are_cleared_but_unrelated_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            report_dir = Path(temp)
            (report_dir / "static-analysis.json").write_text("stale", encoding="utf-8")
            (report_dir / "stage-error-redteam.json").write_text("stale", encoding="utf-8")
            (report_dir / "operator-notes.txt").write_text("keep", encoding="utf-8")
            _clear_previous_run_artifacts(report_dir)
            self.assertFalse((report_dir / "static-analysis.json").exists())
            self.assertFalse((report_dir / "stage-error-redteam.json").exists())
            self.assertEqual((report_dir / "operator-notes.txt").read_text(encoding="utf-8"), "keep")

    def test_missing_scanner_report_is_explicitly_marked_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            outcomes = [{"module": "static_analysis", "status": "completed", "exit_code": 0}]
            issues = _enrich_scan_status(outcomes, Path(temp))
            self.assertEqual(outcomes[0]["scan_status"], "missing_stage_report")
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0]["category"], "coverage")

    def test_optional_freshness_skip_is_reported_without_marking_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            report_dir = Path(temp)
            (report_dir / "freshness.json").write_text(json.dumps({
                "stage": "freshness", "metadata": {"status": "skipped", "reason": "Opt-in required."}, "findings": []
            }), encoding="utf-8")
            outcomes = [{"module": "freshness", "status": "completed", "exit_code": 0}]
            issues = _enrich_scan_status(outcomes, report_dir)
            summary = _execution_summary(outcomes)
            self.assertEqual(outcomes[0]["scan_status"], "skipped")
            self.assertEqual(issues, [])
            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["optional_stages_skipped"][0]["module"], "freshness")

    def test_stage_with_coverage_finding_is_not_marked_fully_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            report_dir = Path(temp)
            (report_dir / "static-analysis.json").write_text(json.dumps({
                "stage": "static-analysis", "metadata": {"tools": {"semgrep": {"exit_code": 127}}},
                "findings": [{"category": "coverage", "title": "Semgrep unavailable"}]
            }), encoding="utf-8")
            outcomes = [{"module": "static_analysis", "status": "completed", "exit_code": 0}]
            _enrich_scan_status(outcomes, report_dir)
            summary = _execution_summary(outcomes)
            self.assertEqual(outcomes[0]["scan_status"], "coverage_gap")
            self.assertEqual(summary["status"], "incomplete")
            self.assertEqual(summary["incomplete_stages"][0]["module"], "static_analysis")

    def test_report_marks_operationally_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            reports = Path(temp)
            (reports / "pipeline-status.json").write_text(json.dumps({
                "stages": [{"module": "static_analysis", "status": "completed", "scan_status": "coverage_gap", "duration_seconds": 2.5}],
                "execution_summary": {"status": "incomplete", "stage_count": 1,
                    "incomplete_stages": [{"module": "static_analysis", "process_status": "completed", "scan_status": "coverage_gap"}],
                    "optional_stages_skipped": []},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"AISECURITY_REPORT_DIR": str(reports), "AISECURITY_FAIL_ON": "none", "AISECURITY_FAIL_ON_COVERAGE": "false"}):
                self.assertEqual(run_report(), 0)
            payload = json.loads((reports / "report.json").read_text(encoding="utf-8"))
            markdown = (reports / "report.md").read_text(encoding="utf-8")
            self.assertEqual(payload["status"], "incomplete")
            self.assertIn("static_analysis", markdown)
            self.assertIn("Scan status", markdown)


if __name__ == "__main__":
    unittest.main()
