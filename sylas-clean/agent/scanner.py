"""Vulnerability data model and scanner base."""

import json
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    XSS = "xss"
    OUTDATED_DEPENDENCY = "outdated_dependency"
    CODE_FLAW = "code_flaw"
    UNKNOWN = "unknown"


@dataclass
class VerificationResult:
    """Result of post-remediation verification scan."""
    fixed_count: int
    remaining_count: int
    new_issues_count: int
    still_vulnerable_ids: list[str]
    success: bool
    message: str = ""


@dataclass
class Vulnerability:
    id: str
    title: str
    severity: str
    file: str
    line: int
    description: str
    vuln_type: str
    scanner: str = "unknown"
    cwe: Optional[str] = None
    vulnerable_code: Optional[str] = None
    vulnerable_dependency: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None


class VulnerabilityScanner:
    """Parses vulnerability reports and runs scanner integrations."""

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)

    @staticmethod
    def deduplicate(vulns: list) -> list:
        """Smart deduplication across all scanner types."""
        import re

        seen_ids: set[str] = set()
        seen_cves: set[str] = set()
        seen_file_line: set[tuple[str, int, str]] = set()
        seen_dep: set[tuple[str, str]] = set()
        unique: list = []

        def _extract_cve(vuln_id: str) -> str | None:
            if not vuln_id:
                return None
            m = re.search(r'(CVE-\d{4}-\d+)', vuln_id, re.IGNORECASE)
            return m.group(1).upper() if m else None

        for vuln in vulns:
            if isinstance(vuln, str):
                if vuln not in seen_ids:
                    seen_ids.add(vuln)
                    unique.append(vuln)
                continue

            vuln_id = getattr(vuln, "id", "") or ""
            file_path = getattr(vuln, "file", "") or ""
            line = getattr(vuln, "line", 0) or 0
            vtype = getattr(vuln, "vuln_type", "") or ""
            dep = getattr(vuln, "vulnerable_dependency", None)
            severity = (getattr(vuln, "severity", "") or "UNKNOWN").upper()
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            cve = _extract_cve(vuln_id) if vuln_id else None

            fl_key = (file_path, line, vtype) if file_path and line > 0 and vtype else None
            if fl_key and fl_key in seen_file_line:
                continue

            if cve:
                if cve in seen_cves:
                    for i, existing in enumerate(unique):
                        if isinstance(existing, Vulnerability):
                            e_cve = _extract_cve(getattr(existing, "id", "") or "")
                            if e_cve == cve:
                                e_sev = (getattr(existing, "severity", "") or "UNKNOWN").upper()
                                if sev_order.get(severity, 0) > sev_order.get(e_sev, 0):
                                    unique[i] = vuln
                                break
                    continue
                seen_cves.add(cve)

            dep_key = (dep.lower(), vtype) if dep and vtype else None
            if dep_key and dep_key in seen_dep:
                continue

            if vuln_id and vuln_id in seen_ids:
                continue

            if vuln_id:
                seen_ids.add(vuln_id)
            if fl_key:
                seen_file_line.add(fl_key)
            if dep_key:
                seen_dep.add(dep_key)
            unique.append(vuln)

        duplicates_removed = len(vulns) - len(unique)
        if duplicates_removed > 0:
            logger.info(f"Deduplicated {duplicates_removed} duplicates, {len(unique)} unique remaining")

        return unique

    def parse_json_report(self, report_path: str) -> list[Vulnerability]:
        """Parse JSON vulnerability report from Trivy/custom scanner."""
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        vulnerabilities = []
        for vuln_data in data.get("vulnerabilities", []):
            vuln = Vulnerability(
                id=vuln_data.get("id", ""),
                title=vuln_data.get("title", ""),
                severity=vuln_data.get("severity", "UNKNOWN"),
                file=vuln_data.get("file", ""),
                line=vuln_data.get("line", 0),
                description=vuln_data.get("description", ""),
                vuln_type=vuln_data.get("type", ""),
                cwe=vuln_data.get("cwe"),
                vulnerable_code=vuln_data.get("vulnerable_code"),
                vulnerable_dependency=vuln_data.get("vulnerable_dependency"),
                current_version=vuln_data.get("current_version"),
                fixed_version=vuln_data.get("fixed_version"),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def run_trivy_scan(self, scan_path: str = ".") -> list[Vulnerability]:
        """Run Trivy scanner and parse results."""
        try:
            result = subprocess.run(
                ["trivy", "json", "--output", "trivy_report.json", scan_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and Path("trivy_report.json").exists():
                return self.parse_json_report("trivy_report.json")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return []

    def scan_repo(self, report_path: Optional[str] = None) -> list[Vulnerability]:
        """Main scan entry point - uses provided report or runs Trivy."""
        if report_path and Path(report_path).exists():
            return self.parse_json_report(report_path)
        return self.run_trivy_scan(str(self.target_path))

    def filter_by_severity(self, vulnerabilities: list[Vulnerability], severity: str) -> list[Vulnerability]:
        """Filter vulnerabilities by severity level."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_order.get(severity.upper(), 0)
        return [
            v for v in vulnerabilities
            if severity_order.get(v.severity.upper(), 0) >= min_level
        ]

    def get_remediation_targets(self, vulnerabilities: list[Vulnerability]) -> dict:
        """Group vulnerabilities by remediation type."""
        targets = {"code_flaws": [], "dependencies": []}
        for vuln in vulnerabilities:
            if vuln.vuln_type == "outdated_dependency":
                targets["dependencies"].append(vuln)
            else:
                targets["code_flaws"].append(vuln)
        return targets
