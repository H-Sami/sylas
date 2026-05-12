"""Vulnerability Report Generator

Generates detailed reports of vulnerabilities found during scanning.
Supports both human-readable text and machine-parseable JSON formats.
All output uses UTF-8 encoding with proper error handling.
Reports are saved directly in the target project root by default.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from agent.scanner import Vulnerability


@dataclass
class ReportSummary:
    """Summary statistics for the report."""
    total: int
    critical: int
    high: int
    medium: int
    low: int
    secrets: int
    dependency_issues: int
    code_issues: int
    by_scanner: dict


class VulnerabilityReport:
    """Generate vulnerability reports in various formats."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir).resolve() if output_dir else None

    def generate(self, vulnerabilities: list, repo_name: str = "unknown", repo_url: str = "", target_path: Optional[str] = None) -> dict:
        """Generate complete report with both text and JSON.
        
        Reports are saved to output_dir if set, otherwise to target_path,
        otherwise to the current working directory.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if self.output_dir:
            out_path = self.output_dir
        elif target_path:
            out_path = Path(target_path).resolve()
        else:
            out_path = Path.cwd()
        out_path.mkdir(parents=True, exist_ok=True)

        text_file = out_path / f"vuln_report_{timestamp}.txt"
        json_file = out_path / f"vuln_report_{timestamp}.json"

        self.generate_text_report(vulnerabilities, str(text_file), repo_name, repo_url)
        self.generate_json_report(vulnerabilities, str(json_file), repo_name, repo_url)

        return {
            "text": str(text_file),
            "json": str(json_file),
            "timestamp": timestamp,
        }

    def generate_text_report(self, vulnerabilities: list, output_file: str, repo_name: str = "unknown", repo_url: str = "") -> str:
        """Generate human-readable text report."""
        summary = self._generate_summary(vulnerabilities)

        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY SCAN REPORT".center(80))
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Repository: {repo_name}")
        if repo_url:
            lines.append(f"URL: {repo_url}")
        lines.append(f"Total Vulnerabilities: {summary.total}")
        lines.append("")

        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Critical:  {summary.critical}")
        lines.append(f"High:      {summary.high}")
        lines.append(f"Medium:    {summary.medium}")
        lines.append(f"Low:       {summary.low}")
        if summary.secrets > 0:
            lines.append(f"Secrets:   {summary.secrets}  <-- CRITICAL - review immediately")
        lines.append(f"Dependency issues: {summary.dependency_issues}")
        lines.append(f"Code issues:       {summary.code_issues}")
        lines.append("")

        lines.append("VULNERABILITIES BY SCANNER")
        lines.append("-" * 40)
        for scanner, count in summary.by_scanner.items():
            lines.append(f"  {scanner}:  {count}")
        lines.append("")

        lines.append("RECOMMENDATIONS")
        lines.append("-" * 40)
        if summary.dependency_issues > 0:
            lines.append(f"- {summary.dependency_issues} dependency issues can be auto-fixed")
        if summary.code_issues > 0:
            lines.append(f"- {summary.code_issues} code issues require manual review")
        if summary.secrets > 0:
            lines.append(f"- {summary.secrets} secrets found - rotate immediately!")
        lines.append("")

        lines.append("DETAILED FINDINGS")
        lines.append("-" * 80)

        for i, vuln in enumerate(vulnerabilities, 1):
            if isinstance(vuln, str):
                severity = "UNKNOWN"
                vuln_type = "unknown"
                file_path = "N/A"
                line_num = 0
                vuln_id = vuln
                title = f"String vulnerability: {vuln}"
            elif isinstance(vuln, Vulnerability):
                severity = getattr(vuln, "severity", "UNKNOWN")
                if callable(severity):
                    severity = "UNKNOWN"
                vuln_type = getattr(vuln, "vuln_type", "unknown")
                if callable(vuln_type):
                    vuln_type = "unknown"
                file_path = getattr(vuln, "file", "N/A")
                if callable(file_path):
                    file_path = "N/A"
                line_num = getattr(vuln, "line", 0)
                if callable(line_num):
                    line_num = 0
                vuln_id = getattr(vuln, "id", "N/A")
                if callable(vuln_id):
                    vuln_id = "N/A"
                title = getattr(vuln, "title", "N/A")
                if callable(title):
                    title = f"Vulnerability title: {vuln_id}"
            else:
                severity = "UNKNOWN"
                vuln_type = "unknown"
                file_path = "N/A"
                line_num = 0
                vuln_id = str(vuln)
                title = f"Unknown vulnerability type: {type(vuln).__name__}"

            lines.append(f"\n[{i}] {severity} - {vuln_type}")
            lines.append(f"    ID: {vuln_id}")
            lines.append(f"    Title: {title}")
            lines.append(f"    File: {file_path}:{line_num}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT".center(80))
        lines.append("=" * 80)

        content = "\n".join(lines)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)

        return output_file

    def generate_json_report(self, vulnerabilities: list, output_file: str, repo_name: str = "unknown", repo_url: str = "") -> str:
        """Generate machine-parseable JSON report."""
        summary = self._generate_summary(vulnerabilities)

        vuln_list = []
        for vuln in vulnerabilities:
            vuln_dict = {
                "id": getattr(vuln, "id", None),
                "severity": getattr(vuln, "severity", "UNKNOWN"),
                "type": getattr(vuln, "vuln_type", "unknown"),
                "title": getattr(vuln, "title", ""),
                "file": getattr(vuln, "file", None),
                "line": getattr(vuln, "line", 0),
                "description": getattr(vuln, "description", ""),
                "scanner": getattr(vuln, "scanner", "unknown"),
            }
            vuln_list.append(vuln_dict)

        report = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repository": repo_name,
                "url": repo_url,
                "agent_version": "1.0.0",
                "scanner_mode": "scanner-only",
            },
            "summary": {
                "total": summary.total,
                "critical": summary.critical,
                "high": summary.high,
                "medium": summary.medium,
                "low": summary.low,
                "secrets": summary.secrets,
                "dependency_issues": summary.dependency_issues,
                "code_issues": summary.code_issues,
                "by_scanner": summary.by_scanner,
            },
            "recommendations": {
                "auto_fixable_dependencies": summary.dependency_issues,
                "manual_review_code": summary.code_issues,
                "immediate_rotation_secrets": summary.secrets,
            },
            "vulnerabilities": vuln_list,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return output_file

    def _generate_summary(self, vulnerabilities: list) -> ReportSummary:
        """Generate summary statistics."""
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0,
        }
        scanner_counts: dict[str, int] = {}
        secret_count = 0
        dependency_count = 0
        code_count = 0

        for vuln in vulnerabilities:
            severity = getattr(vuln, "severity", "UNKNOWN").upper()
            severity_counts[severity if severity in severity_counts else "UNKNOWN"] += 1

            vuln_type = getattr(vuln, "vuln_type", "")

            if vuln_type == "hardcoded_secret":
                secret_count += 1
            elif vuln_type in ("dependency", "outdated_dependency"):
                dependency_count += 1
            else:
                code_count += 1

            scanner = getattr(vuln, "scanner", None)
            if not scanner:
                vuln_id = getattr(vuln, "id", "")
                prefix = vuln_id.split("-")[0].upper()
                scanner = {
                    "BANDIT": "bandit",
                    "SEMGREP": "semgrep",
                    "GH": "github",
                    "GITLEAKS": "gitleaks",
                }.get(prefix, "unknown")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        return ReportSummary(
            total=len(vulnerabilities),
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            secrets=secret_count,
            dependency_issues=dependency_count,
            code_issues=code_count,
            by_scanner=scanner_counts,
        )

    def generate_summary_text(self, vulnerabilities: list) -> str:
        """Generate a brief summary string."""
        summary = self._generate_summary(vulnerabilities)

        lines = []
        lines.append(f"Total: {summary.total} vulnerabilities")

        if summary.critical > 0:
            lines.append(f"  Critical: {summary.critical}")
        if summary.high > 0:
            lines.append(f"  High: {summary.high}")
        if summary.medium > 0:
            lines.append(f"  Medium: {summary.medium}")
        if summary.low > 0:
            lines.append(f"  Low: {summary.low}")
        if summary.secrets > 0:
            lines.append(f"  Secrets: {summary.secrets} (CRITICAL)")

        return "\n".join(lines)
