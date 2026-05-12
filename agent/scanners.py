"""Additional security scanners: Bandit, pip-audit, Semgrep, Gitleaks"""

import json
import subprocess
import sys
import logging
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scanner import Vulnerability
from .utils import safe_run
from .constants import DEFAULT_BANDIT_SKIP_IDS, GITLEAKS_INSTALL_URL

logger = logging.getLogger(__name__)


@dataclass
class ScannerResult:
    scanner: str
    vulnerabilities: list[Vulnerability]
    success: bool
    output: str
    error: Optional[str] = None


class BaseScanner:
    """Base class for all scanners with common functionality."""

    def __init__(self, target_path: str = "."):
        self.target_path = Path(target_path)
        self.logger = logging.getLogger(__name__)

    def is_available(self) -> bool:
        raise NotImplementedError

    def scan(self, output_file: str = "scan_results.json") -> ScannerResult:
        raise NotImplementedError

    def _run_check_version(self, cmd: list[str], timeout: int = 10) -> bool:
        try:
            result = safe_run(cmd, timeout=timeout)
            return result.returncode == 0
        except (FileNotFoundError, OSError) as e:
            self.logger.warning(f"Tool availability check failed: {e}")
            return False

    def _run_scan_command(
        self, cmd: list[str], output_file: str, timeout: int = 120
    ) -> subprocess.CompletedProcess:
        return safe_run(cmd, cwd=str(self.target_path), timeout=timeout)

    def _parse_json_file(self, file_path: Path) -> dict:
        if not file_path.exists():
            return {}
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return {}


class BanditScanner(BaseScanner):
    """Bandit - Python security linter."""

    def __init__(self, target_path: str = ".", skip_ids: set[str] = None):
        super().__init__(target_path)
        self.skip_ids = skip_ids if skip_ids is not None else DEFAULT_BANDIT_SKIP_IDS

    def is_available(self) -> bool:
        try:
            result = safe_run(["bandit", "--version"], timeout=10)
            return result.returncode == 0
        except FileNotFoundError:
            try:
                result = safe_run(
                    [sys.executable, "-m", "bandit", "--version"], timeout=10
                )
                return result.returncode == 0
            except FileNotFoundError:
                return False

    def scan(self, output_file: str = "bandit_results.json") -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                scanner="bandit",
                vulnerabilities=[],
                success=False,
                output="",
                error="Bandit not installed. Run: pip install bandit",
            )

        try:
            result = self._run_scan_command(
                [
                    sys.executable, "-m", "bandit",
                    "-r", str(self.target_path),
                    "-f", "json",
                    "-o", output_file,
                ],
                output_file,
            )

            vulnerabilities = []
            data = self._parse_json_file(self.target_path / output_file)

            if data:
                for issue in data.get("results", []):
                    test_id = issue.get("test_id", "")

                    if test_id in self.skip_ids:
                        self.logger.debug(
                            f"Skipping Bandit issue {test_id}: "
                            f"{issue.get('test_name', '')} "
                            f"(configured skip list)"
                        )
                        continue

                    if test_id == "B101" and "/tests/" in issue.get("filename", ""):
                        continue

                    test_id = issue.get("test_id", "unknown")
                    filename = issue.get("filename", "")
                    line_num = issue.get("line_number", 0)
                    vuln = Vulnerability(
                        id=f"BANDIT-{test_id}-{filename}-{line_num}",
                        title=issue.get("test_name", "Security Issue"),
                        severity=issue.get("issue_severity", "LOW").upper(),
                        file=issue.get("filename", ""),
                        line=issue.get("line_number", 0),
                        description=issue.get("issue_text", ""),
                        vuln_type="code_flaw",
                        scanner="bandit",
                        cwe=(
                            f"CWE-{issue['issue_cwe']['id']}"
                            if issue.get("issue_cwe") and issue["issue_cwe"].get("id")
                            else None
                        ),
                    )
                    vulnerabilities.append(vuln)

            return ScannerResult(
                scanner="bandit",
                vulnerabilities=vulnerabilities,
                success=result.returncode in [0, 1],
                output=result.stdout + result.stderr,
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner="bandit",
                vulnerabilities=[],
                success=False,
                output="",
                error="Scan timed out",
            )


class PipAuditScanner(BaseScanner):
    """pip-audit scanner for Python dependencies."""

    def is_available(self) -> bool:
        try:
            result = safe_run([sys.executable, "-m", "pip_audit", "--version"], timeout=10)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def scan(self, output_file: str = "pip_audit_results.json") -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                scanner="pip-audit",
                vulnerabilities=[],
                success=False,
                output="",
                error="pip-audit not installed. Run: pip install pip-audit",
            )

        try:
            req_file = self.target_path / "requirements.txt"
            pyproject_file = self.target_path / "pyproject.toml"

            cmd = [sys.executable, "-m", "pip_audit", "--format=json", "-o", output_file]

            if req_file.exists():
                cmd.append(str(req_file))
            elif pyproject_file.exists():
                cmd.append(str(pyproject_file))

            result = self._run_scan_command(cmd, output_file)

            vulnerabilities = []
            data = self._parse_json_file(self.target_path / output_file)

            if data:
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        severity = "UNKNOWN"
                        cvss = vuln.get("cvss", {})
                        if isinstance(cvss, dict):
                            cvss_score = cvss.get("cvss_score") or cvss.get("score")
                            if cvss_score:
                                cvss_score = float(cvss_score)
                                if cvss_score >= 9.0:
                                    severity = "CRITICAL"
                                elif cvss_score >= 7.0:
                                    severity = "HIGH"
                                elif cvss_score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                        elif vuln.get("severity"):
                            severity = vuln.get("severity", "").upper()

                        v = Vulnerability(
                            id=vuln.get("id", "unknown"),
                            title=vuln.get("name", "Vulnerability"),
                            severity=severity,
                            file=(
                                str(req_file)
                                if req_file.exists()
                                else str(self.target_path)
                            ),
                            line=0,
                            description=vuln.get("description", ""),
                            vuln_type="dependency",
                            scanner="pip-audit",
                            vulnerable_dependency=dep.get("name", ""),
                            current_version=dep.get("version", ""),
                            fixed_version=(
                                vuln.get("fix_versions", [""])[0]
                                if vuln.get("fix_versions")
                                else ""
                            ),
                        )
                        vulnerabilities.append(v)

            success = result.returncode in [0, 1]
            return ScannerResult(
                scanner="pip-audit",
                vulnerabilities=vulnerabilities,
                success=success,
                output=result.stdout + result.stderr,
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner="pip-audit",
                vulnerabilities=[],
                success=False,
                output="",
                error="Scan timed out",
            )


class GitleaksScanner(BaseScanner):
    """Gitleaks - Secret detection tool."""

    def is_available(self) -> bool:
        try:
            result = safe_run(["gitleaks", "--version"], timeout=10)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def scan(self, output_file: str = "gitleaks_results.json") -> ScannerResult:
        if not self.is_available():
            return ScannerResult(
                scanner="gitleaks",
                vulnerabilities=[],
                success=False,
                output="",
                error=(
                    "Gitleaks not installed or not found in PATH. "
                    f"Install from: {GITLEAKS_INSTALL_URL}"
                ),
            )

        output_path = str(self.target_path / output_file)
        try:
            result = safe_run(
                [
                    "gitleaks", "detect",
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", output_path,
                    "--source", str(self.target_path),
                ],
                timeout=120,
            )

            vulnerabilities = []
            data = self._parse_json_file(Path(output_path))

            if isinstance(data, list):
                for finding in data:
                    v = Vulnerability(
                        id=f"GITLEAKS-{finding.get('RuleID', 'unknown')}",
                        title=f"Secret: {finding.get('Description', 'Hardcoded Secret')}",
                        severity="CRITICAL",
                        file=finding.get("File", ""),
                        line=finding.get("StartLine", 0),
                        description=finding.get("Description", ""),
                        vuln_type="hardcoded_secret",
                        scanner="gitleaks",
                    )
                    vulnerabilities.append(v)

            return ScannerResult(
                scanner="gitleaks",
                vulnerabilities=vulnerabilities,
                success=True,
                output=result.stdout + result.stderr,
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner="gitleaks",
                vulnerabilities=[],
                success=False,
                output="",
                error="Scan timed out",
            )


def run_all_scans(target_path: str = ".") -> dict:
    """Run all available scanners and return combined results."""
    from .trivy_integration import TrivyScanner
    from .semgrep_scanner import SemgrepScanner

    def _build_scanners():
        scanners = {
            "bandit": BanditScanner(target_path),
            "pip-audit": PipAuditScanner(target_path),
            "trivy": TrivyScanner(target_path, output_dir=target_path),
            "semgrep": SemgrepScanner(target_path, output_dir=target_path),
            "gitleaks": GitleaksScanner(target_path),
        }
        return scanners

    scanners = _build_scanners()
    results: dict[str, ScannerResult] = {}
    all_vulnerabilities: list = []

    active = {name: s for name, s in scanners.items() if s.is_available()}
    inactive = {name: s for name, s in scanners.items() if not s.is_available()}

    for name in inactive:
        results[name] = ScannerResult(
            scanner=name, vulnerabilities=[], success=False, output="",
            error=f"{name} not installed",
        )

    if not active:
        logger.warning(
            "No scanners available. Install at least one: bandit, pip-audit, trivy, semgrep, gitleaks"
        )
        return {
            "scanner_results": results,
            "all_vulnerabilities": all_vulnerabilities,
            "summary": {
                "total_vulnerabilities": 0,
                "scanners_available": 0,
                "scanners_failed": len(results),
            },
        }

    with ThreadPoolExecutor(max_workers=min(5, len(active))) as executor:
        future_to_name = {executor.submit(s.scan): name for name, s in active.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                results[name] = result
                all_vulnerabilities.extend(result.vulnerabilities)
            except Exception as e:
                logger.warning(f"Scanner {name} raised an exception: {e}")
                results[name] = ScannerResult(
                    scanner=name, vulnerabilities=[], success=False, output="",
                    error=str(e),
                )

    return {
        "scanner_results": results,
        "all_vulnerabilities": all_vulnerabilities,
        "summary": {
            "total_vulnerabilities": len(all_vulnerabilities),
            "scanners_available": sum(1 for r in results.values() if r.success),
            "scanners_failed": sum(1 for r in results.values() if not r.success),
        },
    }


SCANNER_REGISTRY: dict[str, Any] = {
    "bandit": BanditScanner,
    "pip-audit": PipAuditScanner,
    "semgrep": None,  # lazily loaded via _lazy_semgrep
    "gitleaks": GitleaksScanner,
}


def _lazy_semgrep(target_path: str = "."):
    from .semgrep_scanner import SemgrepScanner
    return SemgrepScanner(target_path)


def get_scanner(name: str, target_path: str = "."):
    """Get scanner by name from registry."""
    factory = SCANNER_REGISTRY.get(name.lower())
    if factory is None:
        return None
    try:
        return factory(target_path)
    except ImportError:
        return None


def list_available_scanners(target_path: str = ".") -> list[str]:
    """List all available scanners."""
    available = []
    for name, factory in SCANNER_REGISTRY.items():
        try:
            if factory is None:
                scanner = _lazy_semgrep(target_path)
            else:
                scanner = factory(target_path)
            if scanner.is_available():
                available.append(name)
        except ImportError:
            continue
    return available
