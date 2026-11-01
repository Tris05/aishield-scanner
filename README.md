# AIShield Scanner

AIShield Scanner is the independent security-scanning repository. It runs as a GitLab CI/CD component, scans public GitHub/GitLab repositories, generates normalized JSON/SARIF/Markdown results, and uploads the report to the hosted AIShield Dashboard.

## Architecture boundary

- This repository performs scanning only. It does not host the dashboard, call Gemini for remediation, or push code changes.
- The hosted dashboard is in the separate `aishield-dashboard` repository.
- GitLab Runner executes the scan using the existing component/engine approach. No new hosted scanning worker is required.
- A branch input is optional. Blank means the remote repository's default branch.

## Use the GitLab component

Add this to the target GitLab repository's `.gitlab-ci.yml` (replace the namespace, project and version with your published component reference):

```yaml
include:
  - component: $CI_SERVER_FQDN/<namespace>/aishield-scanner/ai-security@0.1.0
    inputs:
      repository-url: "https://github.com/OWNER/REPOSITORY"
      # Optional; omit to scan the target repository's default branch.
      branch: "main"
      engine-image: "registry.gitlab.com/<namespace>/aishield-scanner/engine"
```

When scanning the current GitLab checkout, omit `repository-url`; `branch` is also optional. The component supports exact public host allowlists for `github.com` and `gitlab.com`. It does not accept embedded credentials, non-HTTPS URLs, arbitrary ports, or private repository hosts.

## Required GitLab CI/CD variables

Configure these in the GitLab project/group that runs the component. Mark the upload token **masked** and **protected** where compatible with your pipeline refs.

| Variable | Required | Description |
|---|---:|---|
| `AISECURITY_DASHBOARD_URL` | Yes | Deployed dashboard backend origin, e.g. `https://api.example.com` (no trailing slash required). |
| `AISECURITY_UPLOAD_TOKEN` | Yes | Shared ingestion secret configured as `AISHIELD_INGEST_TOKEN` on the backend. |

The component sets `AISECURITY_UPLOAD_REQUIRED=true`, so a failed report upload fails the job rather than silently leaving the report out of the dashboard. Severity/coverage policy gates still preserve their scan exit status; upload is attempted even when a scan gate fails.

## Optional inputs and settings

- `repository-url`: target public repository URL. Blank scans the current checkout.
- `branch`: optional target branch. Blank uses the repository default branch.
- `engine-image`: published engine image base path. The component tag is appended automatically. Set this to the image path in the registry of the AIShield Scanner project. The checked-in default still points to the source project's original registry path; change that default to your new scanner project's path before publishing, or pass this input in each consuming project.
- `.config`: target repository scan policy. If absent, the scanner uses its built-in baseline configuration.
- `AISECURITY_FAIL_ON`: `critical`, `high`, `medium`, `low`, `info`, or `none`.
- `AISECURITY_FAIL_ON_COVERAGE`: fail if scan coverage is incomplete.
- `AISECURITY_ENABLE_DAST`: opt-in passive ZAP baseline scan with an exact host allowlist.
- `AISECURITY_AUTHORIZED`: opt-in for bounded runtime LLM red-team checks against explicitly authorized targets.

## Scanner outputs

`aishield-reports/` contains `report.json`, `report.sarif`, `report.md`, pipeline status, coverage matrix, SBOM, scanner stage outputs and an artifact manifest. The dashboard stores the normalized `report.json`; the other CI artifacts are retained for local troubleshooting and native GitLab artifact access.

## Local development and tests

```bash
python -m compileall -q aishield tests
python -m unittest discover -s tests -v
python -m aishield.benchmark
```

For the engine container, build with `docker build -t aishield-engine:dev .`. Docker is used for packaging/reproducibility; GitLab Runner executes the job using the executor configured for your GitLab project.

## Security notes

This component is a static and bounded security assessment, not proof that a repository is secure. Public repositories are treated as untrusted data. It does not execute discovered project code as part of the static/model inventory stages. Runtime DAST/LLM tests remain separately opt-in and allowlisted. Never put Git tokens, Gemini keys, or dashboard ingestion secrets in repository files.
