"""Opt-in latest-compatible-version discovery with candidate checks against OSV.

This stage sends package names and versions to public registries/OSV and is deliberately opt-in.
It does not promise complete CVE coverage or automatically change dependency files.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from packaging.version import InvalidVersion, Version

from .common import finding, get_inventory, repo_root, write_stage

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9_.+!-]*)\s*(?:;.*)?$")
TIMEOUT = max(2.0, min(float(os.getenv("AISECURITY_FRESHNESS_TIMEOUT", "5")), 20.0))
MAX_PACKAGES = max(1, min(500, int(os.getenv("AISECURITY_MAX_FRESHNESS_PACKAGES", "60"))))
MAX_CANDIDATES = max(1, min(10, int(os.getenv("AISECURITY_MAX_RELEASE_CANDIDATES", "5"))))
USER_AGENT = "AIShield-version-freshness/0.1"


def _ordered_stable_versions(values: list[str]) -> list[str]:
    parsed: list[tuple[Version, str]] = []
    for raw in values:
        try:
            version = Version(raw)
        except InvalidVersion:
            continue
        if version.is_prerelease or version.is_devrelease:
            continue
        parsed.append((version, raw))
    # Descending order, stable-only. Package versions are returned as original strings for the API.
    parsed.sort(key=lambda item: item[0], reverse=True)
    return list(dict.fromkeys(raw for _, raw in parsed))


def query_pypi(name: str) -> dict | None:
    try:
        response = requests.get(
            f"https://pypi.org/pypi/{quote(name, safe='')}/json",
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code != 200:
            return None
        data = response.json()
        latest = (data.get("info") or {}).get("version")
        releases = data.get("releases") or {}
        candidates = []
        for version, distributions in releases.items():
            # Skip releases with no downloadable files or only yanked artifacts.
            if isinstance(distributions, list) and distributions and all(bool(x.get("yanked")) for x in distributions if isinstance(x, dict)):
                continue
            if not distributions:
                continue
            candidates.append(str(version))
        versions = _ordered_stable_versions(candidates)
        if latest and latest not in versions:
            versions = _ordered_stable_versions([str(latest), *versions])
        return {"ecosystem": "PyPI", "name": name, "latest": latest, "candidates": versions[:MAX_CANDIDATES]}
    except (requests.RequestException, ValueError, TypeError):
        return None


def query_npm(name: str) -> dict | None:
    try:
        response = requests.get(
            f"https://registry.npmjs.org/{quote(name, safe='@')}",
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code != 200:
            return None
        data = response.json()
        latest = (data.get("dist-tags") or {}).get("latest")
        versions = data.get("versions") or {}
        candidates = []
        for version, metadata in versions.items():
            if isinstance(metadata, dict) and metadata.get("deprecated"):
                continue
            candidates.append(str(version))
        ordered = _ordered_stable_versions(candidates)
        if latest and latest not in ordered:
            # Preserve the registry's latest tag for explicit vulnerability checking, even if its version
            # metadata is absent/deprecated; semver parsing remains required for older fallback candidates.
            try:
                if not Version(str(latest)).is_prerelease:
                    ordered = [str(latest), *[v for v in ordered if v != str(latest)]]
            except InvalidVersion:
                pass
        return {"ecosystem": "npm", "name": name, "latest": latest, "candidates": ordered[:MAX_CANDIDATES]}
    except (requests.RequestException, ValueError, TypeError):
        return None


def query_osv_batch(queries: list[tuple[str, str, str]]) -> list[list[str] | None]:
    """Check candidate versions with a bounded OSV batch API rather than one request per package."""
    output: list[list[str] | None] = []
    batch_size = 500
    for offset in range(0, len(queries), batch_size):
        chunk = queries[offset:offset + batch_size]
        body = {"queries": [{"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                            for ecosystem, name, version in chunk]}
        try:
            response = requests.post(
                "https://api.osv.dev/v1/querybatch", json=body, timeout=TIMEOUT, allow_redirects=False,
                headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
            )
            if response.status_code != 200:
                output.extend([None] * len(chunk))
                continue
            payload = response.json()
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                output.extend([None] * len(chunk))
                continue
            for result in results:
                vulns = result.get("vulns", []) if isinstance(result, dict) else None
                if not isinstance(vulns, list):
                    output.append(None)
                else:
                    output.append(sorted({str(x.get("id")) for x in vulns if isinstance(x, dict) and x.get("id")}))
        except (requests.RequestException, ValueError, TypeError):
            output.extend([None] * len(chunk))
    return output


def collect(root: Path, inv: dict) -> tuple[list[tuple[str, str, str]], list[str]]:
    packages: list[tuple[str, str, str]] = []
    notes: list[str] = []
    for entry in inv.get("files", []):
        filename = entry.get("name", "").lower()
        relative = entry.get("path", "")
        if filename.startswith("requirements") and filename.endswith(".txt"):
            path = root / relative
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(line.strip().startswith(("--index-url", "--extra-index-url", "--trusted-host")) for line in text.splitlines()):
                notes.append(f"Skipped {relative}: custom package index is configured; package names may be private.")
                continue
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                match = REQ_RE.match(line)
                if match:
                    packages.append(("PyPI", match.group(1), match.group(2)))
        elif filename == "package-lock.json":
            path = root / relative
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for package_path, metadata in (data.get("packages", {}) or {}).items():
                if not package_path.startswith("node_modules/") or not isinstance(metadata, dict):
                    continue
                resolved = str(metadata.get("resolved", ""))
                parsed = urlparse(resolved) if resolved else None
                # Do not disclose possible private package names to public npm APIs.
                if not parsed or parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
                    continue
                package_name = package_path[len("node_modules/"):]
                version = str(metadata.get("version", ""))
                if package_name and version:
                    packages.append(("npm", package_name, version))
    unique = list(dict.fromkeys(packages))
    if len(unique) > MAX_PACKAGES:
        notes.append(f"Package cap reached: found {len(unique)} exact-pinned public package entries; checked only {MAX_PACKAGES}.")
    return unique[:MAX_PACKAGES], notes


def _inspect_latest(item: tuple[str, str, str], registry: dict | None,
                    vulnerability_map: dict[tuple[str, str, str], list[str] | None]) -> dict:
    ecosystem, name, current = item
    if not registry:
        return {"item": item, "status": "registry_unavailable"}
    candidates = registry.get("candidates") or ([registry.get("latest")] if registry.get("latest") else [])
    if not candidates:
        return {"item": item, "status": "no_release_candidates", "latest": registry.get("latest")}

    tested: list[dict] = []
    safe_version = None
    safe_vulns: list[str] = []
    for candidate in candidates[:MAX_CANDIDATES]:
        key = (ecosystem, name, str(candidate))
        vulns = vulnerability_map.get(key)
        if vulns is None:
            return {"item": item, "status": "osv_unavailable", "latest": registry.get("latest"), "tested": tested}
        tested.append({"version": str(candidate), "vulnerability_ids": vulns})
        if not vulns:
            safe_version = str(candidate)
            break
        safe_vulns = vulns
    return {"item": item, "status": "safe_candidate_found" if safe_version else "no_safe_candidate_in_window",
            "latest": registry.get("latest"), "safe_candidate": safe_version,
            "latest_candidate_vulnerabilities": tested[0]["vulnerability_ids"] if tested else [],
            "last_tested_vulnerabilities": safe_vulns, "tested": tested}


def main() -> None:
    if os.getenv("AISECURITY_CHECK_VERSION_FRESHNESS", "false").lower() != "true":
        write_stage("freshness", [], {"status": "skipped", "reason": "Freshness checks send package metadata to public PyPI/npm and OSV APIs; opt in explicitly."})
        print("Version freshness stage skipped (opt-in).")
        return

    root = repo_root()
    inventory = get_inventory(root)
    packages, notes = collect(root, inventory)

    def get_registry(item: tuple[str, str, str]) -> tuple[tuple[str, str, str], dict | None]:
        ecosystem, name, _current = item
        return item, query_pypi(name) if ecosystem == "PyPI" else query_npm(name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        registry_results = list(pool.map(get_registry, packages))

    # Deduplicate package/version pairs and send bounded batches to OSV. This reduces registry/API
    # traffic substantially for repositories with duplicate pins and several candidate releases.
    osv_queries: list[tuple[str, str, str]] = []
    seen_queries: set[tuple[str, str, str]] = set()
    for item, registry in registry_results:
        if not registry:
            continue
        ecosystem, name, _current = item
        for candidate in (registry.get("candidates") or [registry.get("latest")]):
            if not candidate:
                continue
            key = (ecosystem, name, str(candidate))
            if key not in seen_queries:
                seen_queries.add(key)
                osv_queries.append(key)
    osv_results = query_osv_batch(osv_queries)
    vulnerability_map = {key: result for key, result in zip(osv_queries, osv_results)}
    inspected = [_inspect_latest(item, registry, vulnerability_map) for item, registry in registry_results]

    findings = []
    unavailable = 0
    queried = 0
    for result in inspected:
        ecosystem, name, current = result["item"]
        status = result["status"]
        if status in {"registry_unavailable", "osv_unavailable", "no_release_candidates"}:
            unavailable += 1
            continue
        latest = result.get("latest")
        safe = result.get("safe_candidate")
        try:
            current_version = Version(current)
            safe_is_newer = bool(safe and Version(safe) > current_version)
        except InvalidVersion:
            safe_is_newer = False

        if safe_is_newer:
            findings.append(finding(
                scanner="version-freshness", category="dependency-freshness", rule_id=f"freshness:{ecosystem}:{name}",
                title=f"Newer release without an OSV match found for {name}",
                description="AIShield checked recent stable releases from the public package registry against OSV and found a candidate newer than the currently pinned version with no OSV match at scan time. If the registry's newest release matched an advisory, the selected safe candidate may be an earlier release. This is not proof that the package has no vulnerabilities or is compatible.",
                severity="info", confidence="medium", path="",
                evidence=f"ecosystem={ecosystem}; installed={current}; registry_latest={latest}; newest_checked_candidate_without_osv_match={safe}; registry_latest_osv_ids={','.join(result.get('latest_candidate_vulnerabilities', [])) or 'none reported'}; release_candidates_checked={len(result.get('tested', []))}",
                recommendation="Review release notes, compatibility constraints, other advisories and tests before upgrading. Do not auto-upgrade from freshness metadata alone.",
                references=["https://osv.dev/"],
            ))
        if status == "no_safe_candidate_in_window":
            latest_vulns = result.get("latest_candidate_vulnerabilities", [])
            findings.append(finding(
                scanner="version-freshness", category="dependency-freshness", rule_id=f"freshness-risk:{ecosystem}:{name}",
                title=f"No OSV-clean release found in the recent candidate window for {name}",
                description="The most recent stable candidates checked were associated with OSV vulnerability records, or no clean candidate was found within the configured search window. This does not establish that every release is vulnerable.",
                severity="medium", confidence="medium", path="",
                evidence=f"ecosystem={ecosystem}; installed={current}; registry_latest={latest}; latest_candidate_osv_ids={','.join(latest_vulns) or 'none reported'}; candidate_limit={MAX_CANDIDATES}",
                recommendation="Review the linked advisories and fixed-version ranges. Increase the candidate window only with an explicit query budget, or rely on the advisories' affected/fixed ranges to choose a safe upgrade.",
                references=["https://osv.dev/"],
            ))

    if unavailable:
        findings.append(finding(scanner="version-freshness", category="coverage", title="Some freshness or OSV candidate queries were unavailable",
            description="At least one registry or OSV query failed, so no safe/unsafe conclusion was made for those packages.", severity="low", confidence="high",
            evidence=f"unavailable_packages={unavailable}; successfully_inspected_packages={len(inspected)-unavailable}",
            recommendation="Review rate limits/connectivity and rerun if freshness metadata is needed."))
    for note in notes:
        limited = note.startswith("Package cap reached")
        findings.append(finding(scanner="version-freshness", category="coverage" if limited else "freshness-note",
            title="Version freshness scan coverage limit reached" if limited else "Version freshness metadata note",
            description="Some dependency entries were intentionally skipped rather than guessed or disclosed to a public registry.",
            severity="low" if limited else "info", confidence="high", evidence=note,
            recommendation="Review the manifest and use an explicitly approved internal-registry integration if additional coverage is required."))

    write_stage("freshness", findings, {"status": "completed", "osv_candidate_queries": len(osv_queries), "osv_batch_requests": (len(osv_queries) + 499) // 500, "unavailable_packages": unavailable,
        "packages_considered": len(packages), "candidate_limit_per_package": MAX_CANDIDATES,
        "data_sent": "Exact package names and candidate versions only; only exact-pinned requirements and public npm-registry lockfile entries; opt-in stage."})
    print(f"Version freshness: {len(osv_queries)} candidate-version checks in {(len(osv_queries) + 499) // 500} OSV batch request(s); {len(findings)} finding(s)")


if __name__ == "__main__":
    main()
