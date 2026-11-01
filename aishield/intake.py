"""Resolve the scan target safely: current GitLab checkout or an explicitly provided HTTPS Git URL."""
from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_ALLOWED_HOSTS = {"github.com", "gitlab.com"}
CLONE_TIMEOUT = max(10, min(int(os.getenv("AISECURITY_CLONE_TIMEOUT_SECONDS", "300")), 900))


def validate_repository_url(raw_url: str, allowed_hosts: set[str], allow_private: bool) -> tuple[str, list[str]]:
    parsed = urlparse(raw_url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Repository URL must be an HTTPS URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Repository URL must not contain credentials, query parameters, or fragments.")
    host = parsed.hostname.lower().rstrip(".")
    if host not in allowed_hosts:
        raise ValueError("Repository hostname is not in AISECURITY_GIT_ALLOWED_HOSTS (exact hostname required).")
    if parsed.port not in (None, 443):
        raise ValueError("Only the default HTTPS port is allowed for repository cloning.")
    if not parsed.path or parsed.path == "/":
        raise ValueError("Repository URL must include an owner/group and repository path.")
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
    except socket.gaierror as exc:
        raise ValueError("Repository hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("Repository hostname resolved to no addresses.")
    for raw_ip in addresses:
        ip = ipaddress.ip_address(raw_ip)
        if (not ip.is_global and not allow_private) or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Repository URL resolves to a non-public address; private hosts require explicit operator authorization.")
    # Return URL exactly as provided: credentials and URL rewriting are blocked above and by git config below.
    return raw_url.strip(), addresses


def resolve_target() -> Path:
    workspace = Path(os.getenv("CI_PROJECT_DIR", ".")).resolve()
    configured_url = os.getenv("AISECURITY_REPOSITORY_URL", "").strip()
    if not configured_url:
        current = Path(os.getenv("AISECURITY_REPO", workspace)).resolve()
        if not current.is_dir():
            raise RuntimeError("The current checkout does not exist.")
        return current

    allowed_hosts = {host.strip().lower().rstrip(".") for host in os.getenv("AISECURITY_GIT_ALLOWED_HOSTS", ",".join(sorted(DEFAULT_ALLOWED_HOSTS))).split(",") if host.strip()}
    allow_private = os.getenv("AISECURITY_ALLOW_PRIVATE_GIT_HOST", "false").lower() == "true"
    clone_url, addresses = validate_repository_url(configured_url, allowed_hosts, allow_private)
    parent = Path(os.getenv("AISECURITY_CLONE_PARENT", tempfile.gettempdir())).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix="aishield-target-", dir=parent))
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_CONFIG_") and k not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_LFS_SKIP_SMUDGE": "1", "GIT_OPTIONAL_LOCKS": "0"})
    branch = os.getenv("AISECURITY_BRANCH", "").strip()
    command = ["git", "-c", "http.followRedirects=false", "-c", "http.sslVerify=true", "-c", "protocol.file.allow=never",
               "-c", "protocol.ext.allow=never", "clone", "--depth=1", "--single-branch", "--no-recurse-submodules"]
    if branch:
        if branch.startswith("-") or "\x00" in branch or len(branch) > 240:
            shutil.rmtree(destination, ignore_errors=True)
            raise ValueError("Requested branch name is invalid.")
        command.extend(["--branch", branch])
    command.extend([clone_url, str(destination)])
    try:
        completed = subprocess.run(command, cwd=parent, env=env, text=True, capture_output=True, timeout=CLONE_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(f"Repository clone timed out after {CLONE_TIMEOUT} seconds.") from exc
    except OSError as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(f"Could not start Git clone ({type(exc).__name__}).") from exc
    if completed.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
        # Do not persist Git stderr: it may include repository URLs or credential-like material.
        raise RuntimeError(f"Git clone failed with exit code {completed.returncode}. Check repository visibility, exact host allowlist, and network policy.")
    if not (destination / ".git").is_dir():
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError("Git clone did not produce a repository worktree.")
    print(f"AIShield target host validated; resolved address count={len(addresses)}", file=sys.stderr)
    return destination


def main() -> int:
    try:
        target = resolve_target()
    except (RuntimeError, ValueError) as exc:
        print(f"AIShield intake error: {exc}", file=sys.stderr)
        return 2
    # stdout is machine-readable so the CI component can export AISECURITY_REPO without log parsing.
    print(str(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
