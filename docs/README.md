# AIShield GitLab Component

AIShield is a GitLab CI component for scanning AI/ML repositories and applications. It combines dependency and infrastructure checks, static analysis, secret scanning, model/dataset checks, inventory, and optional runtime tests. Its reports describe implemented coverage and known gaps; no scanner guarantees that every vulnerability will be detected.

## Optional runtime security checks

- **Web/API DAST:** opt in to OWASP ZAP Baseline for passive checks against an already-running, explicitly allowlisted staging URL. Configure `enable-dast`, `dast-target-url`, and `dast-allowed-hosts`.
- **LLM red teaming:** opt in with `enable-redteam: true`, then select `llm-redteam-mode: garak` or `llm-redteam-mode: custom`. Garak tests supported model/provider interfaces; custom mode runs bounded tests against an application endpoint.

Runtime scans are disabled by default. Never scan a target without authorization. Use staging deployments and synthetic test data, and store credentials in local `.env` files or masked/protected GitLab CI/CD variables—not in committed YAML.

## LLM red-teaming documentation

Read [`docs/LLM-RED-TEAMING.md`](docs/LLM-RED-TEAMING.md) for:

- exact `.env` and GitLab CI variable names;
- provider credential names and setup notes;
- Garak target interface compatibility list;
- component input examples;
- behavior on unsupported providers, errors, and timeouts;
- security limits and troubleshooting.

For local development, copy `.env.example` to `.env` and fill only the variables required by the selected mode. `.env` is git-ignored; never commit secrets.

## Component example: Garak

```yaml
include:
  - component: $CI_SERVER_FQDN/trisai-secure/eagleshield/ai-security@<version>
    inputs:
      enable-redteam: true
      llm-redteam-mode: garak
      llm-garak-target-type: openai
      llm-garak-target-name: gpt-4o-mini
      llm-garak-probes: probes.promptinject,probes.encoding
      llm-garak-generations: "1"
```

Add `OPENAI_API_KEY` in GitLab **Settings → CI/CD → Variables** as a masked/protected variable. For another provider, use the credential variable documented for that Garak generator and selected release.

## Component example: custom endpoint

```yaml
include:
  - component: $CI_SERVER_FQDN/trisai-secure/eagleshield/ai-security@<version>
    inputs:
      enable-redteam: true
      llm-redteam-mode: custom
      llm-target-url: https://llm-staging.example.com/api/chat
      llm-allowed-hosts: llm-staging.example.com
      llm-request-field: input
      llm-max-requests: "2"
```

Create `AISECURITY_CANARY` and, if needed, `AISECURITY_TARGET_BEARER_TOKEN` as masked/protected CI/CD variables. The synthetic canary must be pre-seeded in the isolated test application's context.

## Reports

Reports are written to `aishield-reports/`. Runtime red-team output is normalized to `redteam.json`. The separate DAST job writes `dast-security.json`, `zap-status.json`, and the raw ZAP JSON artifact. Garak raw reports are temporary because they can contain prompts and model outputs. Review each stage's status; an error or skipped scanner is not a security pass.

## Development validation

Run unit tests with `python -m unittest discover -s tests -v`. A successful unit-test run does not replace validation in a real GitLab pipeline or a controlled staging deployment.
