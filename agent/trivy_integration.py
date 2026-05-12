"""Trivy vulnerability scanner integration.

Trivy must be installed separately.
See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
"""

import json
import logging
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from .scanner import Vulnerability
from .scanners import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)

TRIVY_INSTALL_URL = "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"


class TrivyScanner(BaseScanner):
    """Trivy vulnerability scanner integration."""
    trivy_cmd: str = "trivy"

    def __init__(self, target_path: str = ".", output_dir: Optional[str] = None):
        super().__init__(target_path)
        self.output_dir = Path(output_dir) if output_dir is not None else self.target_path

    def is_available(self) -> bool:
        """Check if Trivy is installed (must be pre-installed, not pip-installable)."""
        trivy_paths = ["trivy"]

        for trivy_cmd in trivy_paths:
            try:
                result = subprocess.run(
                    [trivy_cmd, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self.trivy_cmd = trivy_cmd
                    return True
            except FileNotFoundError:
                continue
        return False

    def scan(self, output_file: str = "trivy_results.json") -> "ScannerResult":
        """Scan for vulnerabilities and return ScannerResult."""
        output_path = str(self.output_dir / output_file)
        if not self.is_available():
            from .scanners import ScannerResult

            return ScannerResult(
                scanner="trivy",
                vulnerabilities=[],
                success=False,
                output="",
                error=(
                    "Trivy not installed or not found in PATH. "
                    f"Install from: {TRIVY_INSTALL_URL}"
                ),
            )

        try:
            if self.scan_filesystem(output_path):
                vulnerabilities = self.parse_trivy_results(output_path)
                from .scanners import ScannerResult

                return ScannerResult(
                    scanner="trivy",
                    vulnerabilities=vulnerabilities,
                    success=True,
                    output=(
                        f"Scan completed. "
                        f"Found {len(vulnerabilities)} vulnerabilities."
                    ),
                )
            else:
                from .scanners import ScannerResult

                return ScannerResult(
                    scanner="trivy",
                    vulnerabilities=[],
                    success=False,
                    output="",
                    error="Trivy scan failed",
                )
        except (subprocess.CalledProcessError, IOError, json.JSONDecodeError) as e:
            from .scanners import ScannerResult

            return ScannerResult(
                scanner="trivy",
                vulnerabilities=[],
                success=False,
                output="",
                error=str(e),
            )

    def scan_filesystem(self, output_file: str = "trivy_results.json") -> bool:
        """Scan filesystem for vulnerabilities."""
        if not self.is_available():
            self.logger.error(
                "[!] Trivy not installed. "
                f"Install from: {TRIVY_INSTALL_URL}"
            )
            return False

        try:
            result = subprocess.run(
                [
                    self.trivy_cmd,
                    "fs",
                    "--format",
                    "json",
                    "--output",
                    output_file,
                    str(self.target_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            self.logger.debug(f"Trivy output: {result.stdout[:500]}")
            self.logger.debug(f"Trivy stderr: {result.stderr[:500]}")
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.warning("Trivy filesystem scan timed out")
            return False

    def scan_container(self, image: str, output_file: str = "trivy_results.json") -> bool:
        if not self.is_available():
            return False
        try:
            result = subprocess.run(
                [self.trivy_cmd, "image", "--format", "json", "--output", output_file, image],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def scan_git_repo(self, repo_url: str, output_file: str = "trivy_results.json") -> bool:
        if not self.is_available():
            return False
        clone_dir = Path("temp_scan_repo")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
                capture_output=True,
                timeout=60,
            )
            result = subprocess.run(
                [self.trivy_cmd, "fs", "--format", "json", "--output", output_file, str(clone_dir)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        finally:
            if clone_dir.exists():
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    def parse_trivy_results(self, results_file: str = "trivy_results.json") -> list[Vulnerability]:
        """Parse Trivy JSON output into Vulnerability objects."""
        if not Path(results_file).exists():
            return []

        try:
            with open(results_file, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
            self.logger.warning(f"Failed to parse {results_file}: {e}")
            return []

        vulnerabilities = []

        if "Results" in data:
            for result in data["Results"]:
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []) or []:
                    vuln_id = vuln.get(
                        "VulnerabilityID", f"CVE-{vuln.get('PkgID', '')}"
                    )
                    severity = vuln.get("Severity", "UNKNOWN").upper()

                    file_match = re.search(r"demo[/\\](.*\.py)", target)
                    file_path = file_match.group(1) if file_match else target

                    v = Vulnerability(
                        id=vuln_id,
                        title=vuln.get("Title", vuln.get("Description", "Unknown")),
                        severity=severity,
                        file=file_path,
                        line=0,
                        description=vuln.get("Description", ""),
                        vuln_type=(
                            "code_flaw" if vuln.get("PkgName") is None else "dependency"
                        ),
                        scanner="trivy",
                        cwe=(
                            vuln.get("CweIDs", [None])[0]
                            if vuln.get("CweIDs")
                            else None
                        ),
                        vulnerable_dependency=vuln.get("PkgName"),
                        current_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                    )
                    vulnerabilities.append(v)

        elif "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                v = Vulnerability(
                    id=vuln.get("id", ""),
                    title=vuln.get("title", ""),
                    severity=vuln.get("severity", "UNKNOWN").upper(),
                    file=vuln.get("file", ""),
                    line=vuln.get("line", 0),
                    description=vuln.get("description", ""),
                    vuln_type=vuln.get("type", "code_flaw"),
                    scanner="trivy",
                    cwe=vuln.get("cwe"),
                    vulnerable_dependency=vuln.get("vulnerable_dependency"),
                    current_version=vuln.get("current_version"),
                    fixed_version=vuln.get("fixed_version"),
                )
                vulnerabilities.append(v)

        return vulnerabilities

    def generate_vulnerability_report(
        self, output_file: str = "vulnerability_report.json"
    ) -> str:
        """Generate a vulnerability report in standard JSON format."""
        vulns = self.parse_trivy_results()

        report = {
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "file": v.file,
                    "line": v.line,
                    "description": v.description,
                    "type": v.vuln_type,
                    "cwe": v.cwe,
                    "vulnerable_dependency": v.vulnerable_dependency,
                    "current_version": v.current_version,
                    "fixed_version": v.fixed_version,
                }
                for v in vulns
            ],
            "scan_metadata": {
                "scanner": "Trivy",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "target": str(self.target_path),
            },
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return output_file


def run_autonomous_scan(
    target: str, output_file: str = "vulnerability_report.json"
) -> Optional[str]:
    """Run a fully autonomous Trivy scan.

    NOTE: Trivy must be pre-installed. This function never attempts
    to pip install Trivy (it is not a Python package).
    See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
    """
    scanner = TrivyScanner(target)

    if not scanner.is_available():
        logger.error(
            "[!] Trivy not found. Install it manually from:\n"
            f"    {TRIVY_INSTALL_URL}"
        )
        return None

    logger.info(f"[*] Running Trivy scan on {target}...")
    if scanner.scan_filesystem("trivy_raw_results.json"):
        report = scanner.generate_vulnerability_report(output_file)
        logger.info(f"[+] Report generated: {report}")
        return report

    return None


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    run_autonomous_scan(target)


def run_trivy_scan(target: str = ".") -> list:
    """Wrapper for main.py compatibility - return list of vulnerability IDs."""
    scanner = TrivyScanner(target)
    if not scanner.is_available():
        return []

    output_file = "trivy_raw_results.json"
    if scanner.scan_filesystem(output_file):
        vulns = scanner.parse_trivy_results(output_file)
        vuln_ids = []
        for v in vulns:
            vuln_ids.append(v.id)
        return vuln_ids

    return []
