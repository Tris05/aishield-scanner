from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
from .common import finding, repo_root, reports_dir, write_stage

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target", ".next", "aishield-reports", ".scannerwork", ".terraform"}
MAX_FILES = int(os.getenv("AISECURITY_MAX_FILES", "100000"))
MAX_TEXT_BYTES = int(os.getenv("AISECURITY_MAX_TEXT_FILE_BYTES", str(2 * 1024 * 1024)))
MAX_TOTAL_TEXT_BYTES = int(os.getenv("AISECURITY_MAX_TOTAL_TEXT_BYTES", str(100 * 1024 * 1024)))
MODEL_EXTS = {".pt", ".pth", ".pkl", ".pickle", ".joblib", ".h5", ".hdf5", ".keras", ".onnx", ".safetensors", ".pb", ".tflite", ".gguf", ".ggml", ".bin"}
DATA_EXTS = {".csv", ".tsv", ".parquet", ".jsonl", ".arrow", ".avro", ".feather", ".npy", ".npz", ".jpg", ".jpeg", ".png", ".webp", ".wav", ".mp3"}
LOCK_FILES = {"requirements.txt", "poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "pom.xml", "gradle.lockfile", "gemfile.lock", "composer.lock"}


def scan_tree(root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    file_count = 0
    errors: list[str] = []
    stop_walk = False
    for cur, dirs, names in os.walk(root, topdown=True, followlinks=False):
        if stop_walk:
            dirs[:] = []
            continue
        dirs[:] = sorted([d for d in dirs if d not in SKIP_DIRS and not (Path(cur) / d).is_symlink()])
        for name in sorted(names):
            p = Path(cur) / name
            file_count += 1
            if file_count > MAX_FILES:
                errors.append(f"File-count safety limit reached ({MAX_FILES}); inventory may be incomplete.")
                dirs[:] = []
                stop_walk = True
                break
            if p.is_symlink() or not p.is_file():
                continue
            try:
                stat = p.stat()
                rel = p.relative_to(root).as_posix()
                suffix = p.suffix.lower()
                lower = name.lower()
                files.append({"path": rel, "name": name, "suffix": suffix, "size": stat.st_size,
                              "is_model_artifact": suffix in MODEL_EXTS,
                              "is_data_artifact": suffix in DATA_EXTS,
                              "is_lockfile": lower in LOCK_FILES,
                              "is_text_candidate": stat.st_size <= MAX_TEXT_BYTES and (lower == "dockerfile" or suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".ipynb", ".yaml", ".yml", ".toml", ".json", ".md", ".txt", ".env", ".sh", ".tf", ".sql", ".ini", ".cfg", ".xml", ".properties"})})
            except OSError as exc:
                errors.append(f"Could not stat {p.name}: {type(exc).__name__}")
    llm_markers = {
        "openai": ["openai", "responses.create", "chat.completions"],
        "anthropic": ["anthropic", "messages.create"],
        "google_genai": ["google.genai", "generativeai", "generate_content"],
        "langchain": ["langchain"],
        "llamaindex": ["llama_index", "llama-index"],
        "vector_db": ["qdrant", "faiss", "chromadb", "pinecone", "weaviate", "milvus", "pgvector"],
        "agent_tools": ["tool_calls", "tool_call", "@tool", "function_call", "create_react_agent", "agentexecutor", "toolnode", "bind_tools"],
        "mcp_protocol": ["@modelcontextprotocol/sdk", "mcp.server", "fastmcp", "fast_mcp", "mcp.tool", "stdiotransport", "streamablehttpservertransport"],
        "rag": ["retriever", "vectorstore", "similarity_search", "retrievalqa", "rag_chain", "contextual_compression"],
        "guardrails": ["guardrails", "llama_guard", "presidio", "rebuff", "prompt_injection", "promptinjection"],
    }
    api_markers = {
        "python_api": ["fastapi", "flask", "django", "starlette", "sanic"],
        "javascript_api": ["express(", "fastify", "koa(", "nestjs", "hono("],
        "api_routes": ["@app.route", "@router.", "app.get(", "app.post(", "router.get(", "router.post(", "urlpatterns"],
        "auth": ["oauth", "jwt", "authorization", "verify_token", "authmiddleware", "permission_classes"],
    }
    ml_markers = {"pytorch": ["import torch", "from torch"], "tensorflow": ["import tensorflow", "from tensorflow"], "sklearn": ["sklearn", "scikit-learn"], "xgboost": ["xgboost"], "keras": ["import keras", "from keras"], "transformers": ["from transformers", "import transformers"]}
    hit_counts = {k: 0 for k in llm_markers}
    api_counts = {k: 0 for k in api_markers}
    ml_counts = {k: 0 for k in ml_markers}
    model_files, data_files, manifests = [], [], []
    text_bytes_read = 0
    # Only inspect bounded text files; do not parse or execute repository code.
    for entry in files:
        if entry["is_model_artifact"]: model_files.append(entry)
        if entry["is_data_artifact"]: data_files.append(entry)
        if entry["is_lockfile"]: manifests.append(entry["path"])
        if entry["is_text_candidate"]:
            size = int(entry.get("size", 0))
            if text_bytes_read + size > MAX_TOTAL_TEXT_BYTES:
                if "Total text-inspection byte budget reached; architecture marker detection may be incomplete." not in errors:
                    errors.append("Total text-inspection byte budget reached; architecture marker detection may be incomplete.")
                continue
            try:
                text = (root / entry["path"]).read_text(encoding="utf-8", errors="ignore").lower()
                text_bytes_read += size
            except OSError:
                continue
            for key, needles in llm_markers.items():
                if any(needle in text for needle in needles):
                    hit_counts[key] += 1
            for key, needles in ml_markers.items():
                if any(needle in text for needle in needles):
                    ml_counts[key] += 1
            for key, needles in api_markers.items():
                if any(needle in text for needle in needles):
                    api_counts[key] += 1
    ai_type = "unknown"
    architecture_types = []
    has_llm = any(hit_counts[k] for k in ("openai", "anthropic", "google_genai", "langchain", "llamaindex"))
    has_ml = bool(model_files) or any(ml_counts.values())
    has_vector_db = hit_counts["vector_db"] > 0
    has_agent_tools = hit_counts["agent_tools"] > 0
    has_mcp = hit_counts["mcp_protocol"] > 0
    has_rag = hit_counts["rag"] > 0 or (has_llm and has_vector_db)
    has_api = any(api_counts.values())
    has_guardrails = hit_counts["guardrails"] > 0
    if has_api:
        architecture_types.append("api_or_web_application")
    if has_ml:
        architecture_types.append("traditional_ml_or_model_artifacts")
    if has_llm:
        architecture_types.append("llm_application")
    if has_rag:
        architecture_types.append("rag_or_vector_retrieval")
    if has_guardrails:
        architecture_types.append("ai-guardrails-or-prompt-security")
    if has_agent_tools:
        architecture_types.append("tool_using_or_agentic_ai")
    if has_mcp:
        architecture_types.append("mcp_enabled_tool_server")
    if has_llm:
        ai_type = "llm_application"
    elif has_ml:
        ai_type = "ml_project"
    capabilities = {
        "dependency_manifests": any(Path(x["path"]).name.lower() in {
            "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "uv.lock",
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.mod",
            "go.sum", "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts",
            "gemfile", "gemfile.lock", "composer.json", "composer.lock"
        } for x in files),
        "container_build_files": any(x["name"].lower() in {"dockerfile", "containerfile"} for x in files),
        "iac_files": any(x["suffix"] in {".tf", ".yaml", ".yml", ".json"} and any(t in x["path"].lower() for t in ("terraform", "k8s", "kubernetes", "helm", "cloudformation", ".gitlab-ci", ".github/workflows")) for x in files),
        "api_or_web_application": has_api,
        "llm_application": has_llm,
        "rag_or_vector_retrieval": has_rag,
        "agent_tools": has_agent_tools,
        "mcp_enabled": has_mcp,
        "model_artifacts": bool(model_files),
        "dataset_artifacts": bool(data_files),
        "guardrail_indicators": has_guardrails,
    }
    inventory = {"schema_version": "1.1", "root": ".", "file_count": len(files), "files": files,
                 "model_artifacts": model_files, "data_artifacts": data_files, "lockfiles": manifests,
                 "ai_type": ai_type, "architecture_types": architecture_types,
                 "capabilities": capabilities,
                 "detected_markers": {**hit_counts, **{f"api_{k}": v for k,v in api_counts.items()}, **{f"ml_{k}": v for k,v in ml_counts.items()}}, "text_bytes_inspected": text_bytes_read, "errors": errors}
    (reports_dir() / "ai-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    findings = []
    if errors:
        findings.append(finding(scanner="inventory", category="coverage", title="Repository inventory incomplete",
             description="Safety limits or filesystem errors prevented a complete inventory.", severity="low", confidence="high",
             evidence="; ".join(errors), recommendation="Review inventory.json and increase limits only when the repository is trusted and runner capacity is sufficient."))
    write_stage("inventory", findings, {"file_count": len(files), "ai_type": ai_type, "markers": {**hit_counts, **{f"ml_{k}": v for k,v in ml_counts.items()}}, "model_artifact_count": len(model_files), "text_bytes_inspected": text_bytes_read})
    return inventory


def main() -> None:
    root = repo_root()
    inventory = scan_tree(root)
    print(f"AIShield inventory: {inventory['file_count']} files; AI type={inventory['ai_type']}; model artifacts={len(inventory['model_artifacts'])}")

if __name__ == "__main__": main()
