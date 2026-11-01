# AIShield LLM Red Teaming: setup, environment variables, and Garak compatibility

AIShield has two explicit runtime red-team modes. Enable runtime testing only against a deployment you own or are authorized to assess. Prefer a staging environment populated with synthetic data.

- `garak`: runs NVIDIA Garak against a supported model/provider generator.
- `custom`: sends a small, bounded set of non-destructive prompts to an explicitly allowlisted application endpoint and checks whether a synthetic canary is disclosed.

There is no silent fallback between modes. A Garak error, missing provider package, unsupported target type, or unparseable report is reported as an incomplete/error result, not as a clean scan.

## 1. Local `.env` setup

1. Copy `.env.example` to `.env` in the project root.
2. Set `AISECURITY_AUTHORIZED=true` only when you have permission to test the target.
3. Choose `AISECURITY_LLM_REDTEAM_MODE=garak` or `AISECURITY_LLM_REDTEAM_MODE=custom`.
4. Fill in only the variables required for the selected mode.
5. Run `python -m aishield.redteam` or the full pipeline with `python -m aishield.pipeline`.

The Python code loads `.env` with `python-dotenv` for local development. Existing shell/CI environment variables take precedence over `.env`. `.env` is ignored by Git; commit `.env.example`, never a real `.env`.

## 2. GitLab CI/CD setup

For CI, do not commit or upload a `.env` file. In **Settings → CI/CD → Variables**, create provider credentials as masked and protected variables (where supported by the project and pipeline). For example, an OpenAI Garak scan needs `OPENAI_API_KEY`. These variables are injected into the job environment; AIShield does not print their values in its reports.

Select the mode and target using the component inputs:

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

For custom mode, use `llm-redteam-mode: custom` and set `llm-target-url`, `llm-allowed-hosts`, and the CI variables `AISECURITY_CANARY` and optionally `AISECURITY_TARGET_BEARER_TOKEN`. The target URL and allowlist must refer to the same exact hostname. The endpoint must accept JSON in the configured `AISECURITY_REQUEST_FIELD` and return a response field AIShield can extract (`output`, `response`, `text`, `answer`, `content`, or OpenAI-style `choices`).

For an OpenAI-compatible provider, configure its base URL separately from the model ID:

```yaml
include:
  - component: $CI_SERVER_FQDN/trisai-secure/eagleshield/ai-security@<version>
    inputs:
      enable-redteam: true
      llm-redteam-mode: garak
      llm-garak-target-type: openai.OpenAICompatible
      llm-garak-target-name: my-model-id
      llm-garak-base-url: https://llm-staging.example.com/v1/
      llm-garak-allowed-hosts: llm-staging.example.com
```

Add `OPENAICOMPATIBLE_API_KEY` as a masked/protected CI variable when that server requires an API key. For private staging only, set `llm-garak-allow-private-target: true` after confirming the target is authorized and isolated.

## 3. Exact AIShield environment variables

| Variable | Required for | Meaning |
|---|---|---|
| `AISECURITY_AUTHORIZED` | Both | Must be `true`; otherwise runtime testing is skipped. |
| `AISECURITY_LLM_REDTEAM_MODE` | Both | `garak` or `custom`. Defaults to `custom`. |
| `AISECURITY_GARAK_TARGET_TYPE` | Garak | Generator interface, e.g. `openai`, `openai.OpenAICompatible`, `anthropic`, `cohere`, `replicate`, `huggingface.InferenceAPI`, `ollama`, `bedrock`, `groq`, `mistral`, `nim`, `litellm`, or `llm`. The exact name must exist in the pinned Garak release. |
| `AISECURITY_GARAK_TARGET_NAME` | Garak | Provider model ID/name expected by the generator; never put credentials here. |
| `AISECURITY_GARAK_BASE_URL` | OpenAI-compatible Garak | HTTPS base URL, usually ending in `/v1/`; used only with `openai.OpenAICompatible`. |
| `AISECURITY_GARAK_ALLOWED_HOSTS` | OpenAI-compatible Garak | Exact hostname allowlist for the configured base URL; no wildcards. |
| `AISECURITY_GARAK_ALLOW_PRIVATE_TARGET` | OpenAI-compatible Garak | Set to `true` only for an authorized isolated private staging endpoint. |
| `AISECURITY_GARAK_PROBES` | Garak | Comma-separated list of up to eight `probes.*` modules. Default: `probes.promptinject,probes.encoding`. Confirm the modules exist in the installed Garak version. |
| `AISECURITY_GARAK_GENERATIONS` | Garak | `1`, `2`, or `3`; limits generations per probe. |
| `AISECURITY_GARAK_TIMEOUT_SECONDS` | Garak | Maximum scan time, clamped to 60–1800 seconds. |
| `AISECURITY_TARGET_URL` | Custom | Authorized application endpoint URL. Must use HTTPS except explicit local-loopback tests. |
| `AISECURITY_ALLOWED_HOSTS` | Custom | Comma-separated exact hostnames; wildcards are not accepted. |
| `AISECURITY_ALLOW_PRIVATE_TARGET` | Custom | Set to `true` only for an authorized isolated private staging target. |
| `AISECURITY_REQUEST_FIELD` | Custom | JSON field containing the prompt; default `input`. |
| `AISECURITY_MAX_REDTEAM_REQUESTS` | Custom | Number of prompts, clamped to 1–3. |
| `AISECURITY_HTTP_TIMEOUT_SECONDS` | Custom | Per-request timeout, clamped to 1–30 seconds. |
| `AISECURITY_TARGET_BEARER_TOKEN` | Custom | Optional bearer token for the target application. Store as a secret, not in YAML or source. |
| `AISECURITY_CANARY` | Custom | Required synthetic token that is deliberately pre-seeded in the test fixture. The report records only a match and redacts the value. |
| `AISECURITY_REPORT_DIR` | Both | Report directory; default `aishield-reports`. |

## 4. Provider credential variable names for Garak

Garak's generator documentation is authoritative for environment variables and optional dependencies. Common examples are:

| Generator / provider | Environment variable or credential setup |
|---|---|
| OpenAI (`openai`) | `OPENAI_API_KEY` |
| OpenAI-compatible (`openai.OpenAICompatible`) | `OPENAICOMPATIBLE_API_KEY` and AIShield's `AISECURITY_GARAK_BASE_URL` + `AISECURITY_GARAK_ALLOWED_HOSTS`. |
| Anthropic (`anthropic`) | `ANTHROPIC_API_KEY` |
| Cohere (`cohere`) | `COHERE_API_KEY` |
| Replicate (`replicate`) | `REPLICATE_API_TOKEN` |
| Hugging Face Inference API | `HF_INFERENCE_TOKEN` (verify the exact variable in the pinned generator docs) |
| Groq / Mistral | Use the provider variable documented by the installed Garak generator version, commonly `GROQ_API_KEY` / `MISTRAL_API_KEY`. Verify before use. |
| AWS Bedrock (`bedrock`) | AWS SDK credential chain, such as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION`, or an appropriate workload role. Prefer short-lived role credentials. |
| `llm` generator | Provider credentials and optional provider plugins are managed by Simon Willison's `llm` library. Install/configure the required plugin for the selected model; setting a random API key variable is not enough. |
| Ollama (`ollama`) | A reachable Ollama service and a model name supported by the installed generator; configure host/model according to the pinned Garak documentation. |

Provider support and exact key names can change between Garak releases. Check the linked generator page for the exact version AIShield installs. Do not assume that every provider has the same authentication mechanism or that every model identifier works with every generator.

## 5. Garak interfaces listed for user selection

The current AIShield allowlist includes these target type strings as candidate interfaces:

- `openai`
- `openai.OpenAICompatible` (requires `AISECURITY_GARAK_BASE_URL` and `AISECURITY_GARAK_ALLOWED_HOSTS`; the endpoint URL is validated before Garak is invoked)
- `anthropic`
- `cohere`
- `replicate`
- `huggingface`
- `huggingface.InferenceAPI`
- `huggingface.InferenceEndpoint`
- `ollama`
- `ggml`
- `llm`
- `bedrock`
- `groq`
- `mistral`
- `nim`
- `litellm`

This is an interface allowlist, not a claim that every entry is installed or operational in every deployment. Some require provider-specific packages, credentials, local model files, endpoint configuration, or a supported Garak plugin in the pinned version. AIShield validates the target type against its allowlist and records runtime errors; it does not infer support from the model name alone.
Garak itself has additional generators beyond AIShield's curated allowlist (for example Azure OpenAI, LangChain, Watsonx, Rasa, WebSocket and REST integrations). They are not automatically enabled by this component because their endpoint/configuration requirements vary. Check the official generator catalog; choose custom mode for an application endpoint not covered by AIShield's current Garak adapter, or extend the allowlist/configuration only after adding validation and tests.

Official references:

- Garak CLI and generator selection: https://reference.garak.ai/en/stable/cliref.html
- Garak generators: https://reference.garak.ai/en/latest/generators.html
- OpenAI and OpenAI-compatible generator: https://reference.garak.ai/en/latest/generators/openai.html
- REST generator: https://reference.garak.ai/en/latest/generators/rest.html
- `llm` plugin generator: https://reference.garak.ai/en/latest/generators/llm.html
- NVIDIA Garak source: https://github.com/NVIDIA/garak

## 6. What each mode tests

### Garak

AIShield invokes Garak with the selected target type, model name, probe list, generation budget, and a temporary report directory. The raw Garak report may contain prompts and model responses, so AIShield does not publish the raw report as a normal CI artifact. It converts detector hits into normalized findings and records engine, target type, probe selection, parsed attempt count, and status. If Garak exits non-zero, times out, or returns a report format AIShield cannot parse, the stage is incomplete/error, not passed.

### Custom

AIShield sends up to three bounded prompts to the configured application endpoint, does not follow redirects, validates the exact host allowlist, and checks whether the configured synthetic canary appears in a response. It does not save raw responses. This is a small application-specific smoke test, not a comprehensive jailbreak benchmark.

## 7. Security and troubleshooting

- Never point either mode at a production model/application without explicit authorization and a defined test budget.
- API usage may incur provider costs. Start with one generation and a small probe selection.
- Never commit `.env`, provider tokens, production secrets, or real customer data.
- Use synthetic canaries only. The custom mode's canary must be seeded in the isolated test context; otherwise the disclosure check has nothing meaningful to detect.
- A `completed` status means the selected tests executed, not that the model is universally safe.
- `error`, `timeout`, `unsupported`, `configuration_error`, or `report_unparsed` means coverage is incomplete.
- If a provider is not supported or cannot be configured through the selected Garak generator, choose `custom` only if you have an authorized application endpoint with the documented JSON request/response contract.
