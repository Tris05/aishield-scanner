# AIShield Phase 2: Scanner orchestration and coverage

## Changes in this patch

- `aishield/pipeline.py`: runs metadata and inventory first, then runs independent scanners concurrently with a bounded worker pool and per-stage timeout; captures stage logs; records process and scan status; writes `pipeline-status.json` and `coverage-matrix.json`; preserves the final report/policy gate and opt-in remediation behavior.
- `aishield/common.py`: normalizes findings to schema version 1.1, preserves source scanner identity, and extracts common CVE/CWE/package/version fields when available without requiring every scanner adapter to implement its own parser.
- `aishield/inventory.py`: expands bounded, non-executing technology detection for APIs, LLM providers, vector/RAG components, agents, MCP, and guardrail indicators; emits a capabilities map.
- `aishield/report.py`: deduplicates matching CVE/package/path findings across tools while preserving source scanners/references; includes the coverage matrix and pipeline status in JSON/Markdown/SARIF output; stops dropping the inventory stage report.
- `tests/test_core.py`: adds tests for expanded inventory, cross-tool deduplication, coverage declarations, and inventory report retention.

## Category map and limits

The report matrix describes implemented checks, conditional checks and known gaps. It is intentionally not a promise that every vulnerability can be found.

| Security area | Phase 2 integration status |
|---|---|
| Dependency/package CVEs | Partial: OSV-Scanner, pip-audit, Trivy; npm audit is opt-in and manifest support matters |
| Container/OS CVEs | Partial: Trivy filesystem scanning and the separate engine-image CI scan; scanning arbitrary built application images is not automatic |
| SAST and Python issues | Partial: Semgrep, Bandit and AIShield heuristics |
| Secrets | Partial: Gitleaks, detect-secrets and Trivy |
| IaC/CI misconfiguration | Partial: Trivy misconfiguration scanning; provider-specific policies may be missing |
| Unsafe model artifacts | Conditional: ModelScan for supported formats plus bounded hashing/metadata; no model is loaded or executed |
| Dataset privacy/integrity | Conditional and heuristic; only supported formats and bounded samples are inspected |
| LLM prompt injection/jailbreak | Static indicators by default; dynamic probes are opt-in, require explicit authorization, allowlisted HTTPS target and synthetic canary |
| RAG/agents/tools/MCP | Partial static heuristics; runtime authorization, tenant isolation and retrieval ACLs are not proven |
| AI data leakage/misuse | Partial: dataset pattern checks and opt-in canary tests; not a universal misuse classifier |
| API/web DAST | Not implemented in this Phase 2 patch; do not treat this category as scanned |
| License/provenance | Partial: Trivy license indicators, CycloneDX SBOM and scan metadata; signed attestation verification is not implemented |

## Validation performed

- `python -m compileall -q aishield tests`: passed.
- `python -m unittest discover -s tests -v`: 23 tests passed.
- `python -m aishield.benchmark`: could not be completed using the uploaded source archive because the `examples/vulnerable-demo` and `examples/benign-demo` fixtures were not included in that archive. Run it against the full repository checkout that contains those fixtures.

The component template now exposes opt-in runtime LLM test and OWASP ZAP Baseline DAST inputs. See `DAST-REDTEAM-SETUP.md` for the required input values, protected CI variables, and limitations. ZAP runs in a separate official scanner image to avoid bloating the engine image. The DAST job emits `zap-baseline.json`, `zap-status.json`, and `dast-security.json` artifacts. In this version DAST findings are a separate job artifact and are not merged into the source scan job’s `report.json`. Runtime LLM tests reuse AIShield’s bounded HTTP adapter and require protected project CI variables `AISECURITY_CANARY` and optionally `AISECURITY_TARGET_BEARER_TOKEN`; these values are not component inputs. The root `.gitlab-ci.yml` and `requirements.txt` do not need changes for these integrations.
