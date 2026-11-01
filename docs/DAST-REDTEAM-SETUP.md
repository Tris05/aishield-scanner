# AIShield optional DAST and runtime LLM tests

## OWASP ZAP Baseline DAST

Set these component inputs only when the repository has a running web/API deployment you are authorized to test:

- `enable-dast: true`
- `dast-target-url: https://staging.example.com`
- `dast-allowed-hosts: staging.example.com`
- `dast-allow-private-target: true` only for an isolated private staging environment; otherwise leave false.

The URL must use HTTPS, must not contain credentials/query/fragment, and its hostname must exactly match the comma-separated allowlist. Non-public addresses are blocked unless the private-target opt-in is set; link-local, multicast and unspecified addresses remain blocked. ZAP Baseline is passive and does not run active attacks. The DAST job emits `zap-baseline.json`, `zap-status.json`, and normalized `dast-security.json`. It fails on operational errors or findings at/above the configured `fail-on` threshold. DAST runs as a separate job and report artifact; it is not merged into the source scan's `report.json` in this version.

The endpoint must already be running and reachable from the GitLab runner. `repository-url` is the Git source URL and is not a DAST target.

## Runtime LLM canary tests

Set these component inputs:

- `enable-redteam: true`
- `llm-target-url: https://llm-staging.example.com/test`
- `llm-allowed-hosts: llm-staging.example.com`
- `llm-request-field: input` (change only if the endpoint expects another JSON field)
- `llm-max-requests: "2"` (allowed values: `1`, `2`, `3`)
- `llm-allow-private-target: true` only for an isolated private staging environment.

Add `AISECURITY_CANARY` as a protected/masked CI variable containing a **synthetic, non-production test token** that is pre-seeded in the test application's model context. Optionally add `AISECURITY_TARGET_BEARER_TOKEN` as a protected/masked CI variable if the endpoint requires bearer authentication. Do not put either secret in the component inputs or repository. The runtime adapter sends a small, bounded set of non-destructive prompts, never follows redirects, does not save raw model responses, and records only whether the exact synthetic canary appeared. This is an application-endpoint check, not a comprehensive jailbreak benchmark.

## Selectable Garak runtime red teaming

AIShield now exposes `llm-redteam-mode: garak|custom`. Garak mode invokes the pinned Garak CLI against a supported generator interface and model identifier; custom mode uses AIShield's bounded application-endpoint canary checks. Neither mode silently falls back to the other. The detailed setup guide lists the exact `.env` and GitLab CI/CD variable names, provider credential names, supported target type strings, and limitations: [`docs/LLM-RED-TEAMING.md`](docs/LLM-RED-TEAMING.md).

For local use, copy `.env.example` to `.env`; for GitLab CI, create provider secrets as masked/protected CI/CD variables. Never commit `.env` or run red-team probes against a target without explicit authorization.

## Validation limits

The local patch checks include Python compilation, unit tests, YAML parsing, embedded Bash syntax, and a synthetic ZAP-report normalization smoke test. They do not verify live ZAP connectivity, target behavior, GitLab's remote component lint, or a live LLM endpoint. Run those checks in a controlled staging pipeline before publishing a release.
