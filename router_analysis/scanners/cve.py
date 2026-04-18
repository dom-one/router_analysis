from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from pwn import log

from router_analysis.config import (
    CACHE_DIR,
    OSV_API_URL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from router_analysis.scanners.base import BaseScanner, register
from router_analysis.scanners.cve_rules import (
    BUILTIN_RULES,
    CVEMatcher,
    load_rules,
    match_disassembly_patterns,
    version_matches,
)


# ---------------------------------------------------------------------------
# osv.dev API helpers
# ---------------------------------------------------------------------------

OSV_ECOSYSTEMS: dict[str, str] = {
    "openssl":    "Alpine",
    "libcrypto":  "Alpine",
    "libssl":     "Alpine",
    "libcurl":    "Alpine",
    "libpng":     "Alpine",
    "libjpeg":    "Alpine",
    "zlib":       "Alpine",
    "busybox":    "Alpine",
    "uclibc":     "Alpine",
    "musl":       "Alpine",
}


def _normalize_name(name: str) -> str:
    return name.lower().lstrip("lib")


def query_osv(package: str, version: str) -> list[dict[str, Any]]:
    ecosystem = OSV_ECOSYSTEMS.get(package.lower(), "Alpine")
    try:
        resp = requests.post(
            OSV_API_URL,
            json={
                "package": {"name": _normalize_name(package), "ecosystem": ecosystem},
                "version": version,
            },
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        return resp.json().get("vulns", [])
    except requests.RequestException:
        return []


def parse_cvss(score_str: str) -> tuple[float, str]:
    try:
        score = float(score_str)
    except (ValueError, TypeError):
        score = 0.0
    if score >= SEVERITY_CRITICAL:
        label = "CRITICAL"
    elif score >= SEVERITY_HIGH:
        label = "HIGH"
    elif score >= SEVERITY_MEDIUM:
        label = "MEDIUM"
    elif score > 0:
        label = "LOW"
    else:
        label = "UNKNOWN"
    return score, label


# ---------------------------------------------------------------------------
# CVEScanner
# ---------------------------------------------------------------------------

@register(priority=30)
class CVEScanner(BaseScanner):
    """CVE scanner combining version-based API lookups and local CVE rules.

    Matching is three-tier:
      Tier 1 — osv.dev API:    library + exact version → CVE list
      Tier 2 — CVE rules:      component glob + version + subsystem → CVE match
      Tier 3 — disasm rules:   code patterns in binary disassembly → vuln match
    """

    name = "cve"

    def __init__(self, ctx: "FirmwareContext", **kwargs) -> None:
        super().__init__(ctx, **kwargs)
        self.rules: list[dict[str, Any]] = []
        self.matcher: CVEMatcher | None = None

    def check(self) -> bool:
        return len(self.ctx.identified_components) > 0

    def run(self) -> None:
        # Load CVE rules
        rules_path = Path(self.kwargs.get("cve_db", "")).expanduser() if self.kwargs.get("cve_db") else None
        self.rules = load_rules(rules_path)
        self.matcher = CVEMatcher(self.rules)

        lib_components = [
            c for c in self.ctx.identified_components
            if c.is_library or c.magika_label == "ELF"
        ]
        self._log_info(f"Scanning {len(lib_components)} components ({len(self.rules)} CVE rules loaded)")

        osv_hits = 0
        rule_hits = 0

        for comp in lib_components:
            pkg = comp.library_name or Path(comp.path).name

            # Tier 1: osv.dev version lookup
            if comp.library_version:
                osv_findings = self._query_osv(pkg, comp.library_version, comp.path)
                osv_hits += len(osv_findings)

            # Tier 2: local CVE rules
            rule_findings = self._match_cve_rules(comp)
            rule_hits += len(rule_findings)

            # Tier 3: disassembly code patterns (binary-specific rules)
            if comp.path in self.ctx.disassembly_results:
                self._match_disasm_rules(comp)

        self._log_info(f"  osv.dev hits: {osv_hits},  CVE rule hits: {rule_hits}")
        self._update_risk()

    # ------------------------------------------------------------------
    # Tier 1: osv.dev
    # ------------------------------------------------------------------

    def _query_osv(self, pkg: str, version: str, binary_path: str) -> list:
        from router_analysis.context import CVEFinding

        self._log_info(f"  Querying osv.dev for {pkg}@{version} ...")
        vulns = query_osv(pkg, version)
        time.sleep(0.25)

        results: list[CVEFinding] = []
        for v in vulns:
            cve_id = v.get("id", "")
            if not cve_id.startswith("CVE-"):
                continue

            severity_str = ""
            for alias in v.get("aliases", []):
                if alias.startswith("NVD-CVE"):
                    break

            cvss = v.get("severity", {})
            if isinstance(cvss, dict):
                severity_str = str(cvss.get("score", ""))
            elif isinstance(cvss, str):
                severity_str = cvss

            severity_score, severity_label = parse_cvss(severity_str)
            if not severity_str:
                severity_label = "UNKNOWN"

            refs = v.get("references", [])
            ref_url = refs[0]["url"] if refs else ""

            finding = CVEFinding(
                cve_id=cve_id,
                component=pkg,
                component_version=version,
                severity=severity_label,
                severity_score=severity_score,
                description=v.get("summary", ""),
                matched_by="version_api",
                affected_binary=binary_path,
                confidence="confirmed",
                references=[ref_url] if ref_url else [],
            )
            results.append(finding)
            self.ctx.cve_findings.append(finding)

        if not vulns:
            self._log_info(f"  No CVEs found for {pkg}@{version}")

        return results

    # ------------------------------------------------------------------
    # Tier 2: CVE rules
    # ------------------------------------------------------------------

    def _match_cve_rules(self, comp: "IdentifiedFile") -> list:
        from router_analysis.context import CVEFinding

        if not self.matcher:
            return []

        results: list[CVEFinding] = []
        matches = self.matcher.match(comp)

        for m in matches:
            rule = m["rule"]
            finding = CVEFinding(
                cve_id=rule["cve_id"],
                component=m["component"],
                component_version=comp.library_version,
                severity=rule.get("severity", "UNKNOWN"),
                severity_score=rule.get("cvss", 0.0),
                description=rule.get("description", ""),
                matched_by=f"rule:{rule['cve_id']}",
                affected_binary=m["affected_binary"],
                confidence=m["confidence"],
                references=rule.get("references", []),
            )
            results.append(finding)
            self.ctx.cve_findings.append(finding)
            self._log_info(
                f"  [{finding.confidence.upper()}] {rule['cve_id']} — "
                f"{rule.get('title', '')} "
                f"(binary: {Path(comp.path).name})"
            )

        return results

    # ------------------------------------------------------------------
    # Tier 3: disassembly code patterns
    # ------------------------------------------------------------------

    def _match_disasm_rules(self, comp: "IdentifiedFile") -> None:
        from router_analysis.context import VulnMatch

        disasm_result = self.ctx.disassembly_results[comp.path]
        matched_rules = self.matcher.match(comp)

        for m in matched_rules:
            rule = m["rule"]
            code_patterns = rule.get("code_patterns", [])
            string_patterns = rule.get("string_patterns", [])

            pattern_matches = match_disassembly_patterns(
                disasm_result, code_patterns, string_patterns
            )

            for pm in pattern_matches:
                vm = VulnMatch(
                    binary_path=comp.path,
                    vuln_type=pm["type"],
                    location=disasm_result.tool,
                    cve_id=rule["cve_id"],
                    confidence=pm["severity"].lower(),
                    description=(
                        f"{rule['cve_id']} — {rule.get('title', '')}: "
                        f"{pm['description']}"
                    ),
                    code_snippet=pm.get("matched_string", pm.get("matched_pattern", ""))[:200],
                )
                self.ctx.vulnerability_matches.append(vm)
                self._log_info(
                    f"  [CODE MATCH] {rule['cve_id']} — {pm['type']} "
                    f"({disasm_result.tool})"
                )

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------

    def _update_risk(self) -> None:
        if not self.ctx.cve_findings:
            self.ctx.overall_risk = "low"
            return

        max_score = max(f.severity_score for f in self.ctx.cve_findings)
        if max_score >= SEVERITY_CRITICAL:
            self.ctx.overall_risk = "critical"
        elif max_score >= SEVERITY_HIGH:
            self.ctx.overall_risk = "high"
        elif max_score >= SEVERITY_MEDIUM:
            self.ctx.overall_risk = "medium"
        else:
            self.ctx.overall_risk = "low"

    def get_findings(self) -> list[dict[str, Any]]:
        return [
            {
                "cve_id": f.cve_id,
                "component": f.component,
                "version": f.component_version,
                "severity": f.severity,
                "severity_score": f.severity_score,
                "confidence": f.confidence,
                "affected_binary": Path(f.affected_binary).name,
            }
            for f in self.ctx.cve_findings
        ]
