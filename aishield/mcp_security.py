"""Conservative static review of Model Context Protocol (MCP) server/tool surfaces.

These checks are indicators only. Authentication may live in gateway middleware or a
separate deployment layer, and a sink may be safely wrapped elsewhere in the codebase.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from .common import finding, get_inventory, repo_root, write_stage

MCP_MARKERS = re.compile(
    r"@modelcontextprotocol/sdk|mcp\.server|fastmcp|fast_mcp|mcp\.tool|"
    r"stdiotransport|streamablehttpservertransport|streamable_http|sse_server|"
    r"@server\.tool|@mcp\.tool|McpServer|MCPServer",
    re.IGNORECASE,
)
TOOL_REGISTRATION = re.compile(
    r"@(?:mcp|server)\.tool|\.tool\s*\(|register_tool|add_tool|tools\s*=|"
    r"McpServer|MCPServer|FastMCP|fastmcp",
    re.IGNORECASE,
)
PRIVILEGED_SINKS = {
    "shell execution": re.compile(r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|execSync|child_process\.exec)\s*\(", re.I),
    "dynamic code execution": re.compile(r"\b(?:eval|exec)\s*\(", re.I),
    "filesystem mutation": re.compile(r"\b(?:unlink|rmtree|write_text|write_bytes|writeFile|rmSync)\s*\(", re.I),
}
HTTP_TRANSPORT = re.compile(r"streamable[-_ ]?http|sse_server|SSEServerTransport|HTTPServerTransport", re.I)
AUTH_INDICATORS = re.compile(r"\b(?:auth(?:entication|orization)?|oauth|bearer|jwt|verify_token|token_verifier|identity_provider)\b", re.I)
MAX_MCP_FILES = max(1, min(5000, int(os.getenv("AISECURITY_MAX_MCP_FILES", "500"))))
MAX_FILE_BYTES = max(1024, min(5_000_000, int(os.getenv("AISECURITY_MAX_MCP_FILE_BYTES", "1000000"))))
MAX_TOTAL_TEXT_BYTES = max(MAX_FILE_BYTES, min(100 * 1024 * 1024, int(os.getenv("AISECURITY_MAX_MCP_TOTAL_TEXT_BYTES", str(25 * 1024 * 1024)))))


def inspect_mcp_source(text: str) -> list[tuple[str, str, str, str]]:
    """Return (title, severity, confidence, recommendation) indicators for a source file."""
    if not MCP_MARKERS.search(text):
        return []
    output = []
    if TOOL_REGISTRATION.search(text):
        for label, pattern in PRIVILEGED_SINKS.items():
            if pattern.search(text):
                output.append((
                    f"MCP tool surface and {label} occur in the same file",
                    "medium", "low",
                    "Review each tool's authorization, schema validation and least-privilege boundary. Avoid passing model/user-controlled arguments to privileged sinks; use explicit allowlists and require approval for high-impact actions.",
                ))
    if HTTP_TRANSPORT.search(text) and not AUTH_INDICATORS.search(text):
        output.append((
            "MCP HTTP transport has no obvious in-file authentication indicator",
            "info", "low",
            "Verify authentication and per-tool authorization at the server or trusted gateway. This heuristic cannot see middleware, reverse proxies or identity controls configured elsewhere.",
        ))
    return output


def run() -> None:
    root = repo_root()
    inventory = get_inventory(root)
    findings = []
    inspected = 0
    mcp_files = 0
    skipped_over_limit = 0
    total_bytes = 0
    for item in inventory.get("files", []):
        if not item.get("is_text_candidate"):
            continue
        if inspected >= MAX_MCP_FILES:
            skipped_over_limit += 1
            continue
        rel = str(item.get("path", ""))
        p = root / rel
        if p.is_symlink() or not p.is_file():
            continue
        try:
            size = p.stat().st_size
            if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_TEXT_BYTES:
                skipped_over_limit += 1
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            total_bytes += size
        except OSError:
            continue
        inspected += 1
        if not MCP_MARKERS.search(text):
            continue
        mcp_files += 1
        for title, severity, confidence, recommendation in inspect_mcp_source(text):
            findings.append(finding(
                scanner="mcp-security", category="agent-tool-security", rule_id=title,
                title=title, description="A conservative MCP source heuristic matched a potentially sensitive tool or transport pattern. This is a review indicator, not proof of exploitability.",
                severity=severity, confidence=confidence, path=rel,
                evidence="Source content is intentionally omitted from reports; review the file and deployment boundary.",
                recommendation=recommendation,
            ))
    if skipped_over_limit:
        findings.append(finding(scanner="mcp-security", category="coverage", title="MCP scan skipped oversized text files", description="Some text files exceeded the MCP scanner's per-file inspection limit.", severity="low", confidence="high", evidence=f"skipped_files={skipped_over_limit}", recommendation="Review scan coverage and adjust bounded limits only when runner resources allow."))
    write_stage("mcp-security", findings, {
        "status": "mcp_detected" if mcp_files else "mcp_not_detected",
        "files_inspected": inspected,
        "mcp_source_files": mcp_files,
        "text_bytes_inspected": total_bytes,
        "oversized_or_over_budget_files_skipped": skipped_over_limit,
        "file_limit": MAX_MCP_FILES,
        "text_byte_limit": MAX_TOTAL_TEXT_BYTES,
        "limitation": "Static indicators only; auth may be external and cross-file data flow is not proven.",
    })
    print(f"MCP security: {mcp_files} MCP source file(s); {len(findings)} finding(s)")


if __name__ == "__main__":
    run()
