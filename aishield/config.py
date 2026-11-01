"""Configuration manager for AIShield.

Loads settings from `.config` in the target repository.
If `.config` is not found in the target repository, falls back to the `.config`
in the AIShield repository root.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Component repository root
COMPONENT_ROOT = Path(__file__).resolve().parent.parent


def parse_config_text(content: str) -> dict[str, str]:
    """Parse key=value lines, ignoring comments and whitespace."""
    values: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k:
                values[k] = v
    return values


def find_config_file(target_repo: Path | None = None) -> tuple[Path | None, bool]:
    """
    Locates .config file.
    Returns (path, is_fallback).
    """
    # 1. Target repository .config
    if target_repo and (target_repo / ".config").is_file():
        return (target_repo / ".config"), False

    # Check env var AISECURITY_REPO
    env_repo = os.getenv("AISECURITY_REPO")
    if env_repo:
        cand = Path(env_repo).resolve() / ".config"
        if cand.is_file():
            return cand, False

    # 2. Fallback: Component root .config
    fallback = COMPONENT_ROOT / ".config"
    if fallback.is_file():
        return fallback, True

    # 3. Fallback: Current working directory .config
    cwd_config = Path.cwd() / ".config"
    if cwd_config.is_file():
        return cwd_config, True

    return None, False


def load_config(target_repo: Path | None = None, verbose: bool = True) -> tuple[Path | None, dict[str, str]]:
    """
    Load .config and populate os.environ (without overwriting explicitly provided env vars).
    """
    config_path, is_fallback = find_config_file(target_repo)
    if not config_path or not config_path.is_file():
        if verbose:
            print("[AIShield] No .config file found; using default built-in parameters.", file=sys.stderr)
        return None, {}

    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")
        values = parse_config_text(content)
    except OSError as exc:
        if verbose:
            print(f"[AIShield] Warning: Could not read {config_path}: {exc}", file=sys.stderr)
        return None, {}

    # Inject into os.environ only if not already set by operator or CI environment
    applied_count = 0
    for k, v in values.items():
        if k not in os.environ:
            os.environ[k] = v
            applied_count += 1

    if verbose:
        if is_fallback:
            print(f"[AIShield] .config not found in target repository. Using default fallback: {config_path} ({applied_count} variables loaded)", file=sys.stderr)
        else:
            print(f"[AIShield] Loaded configuration from target repository: {config_path} ({applied_count} variables loaded)", file=sys.stderr)

    return config_path, values
