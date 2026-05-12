"""Remediation Engine - Handles dependency-only vulnerability fixes."""

import subprocess
from pathlib import Path
from typing import Optional
from agent.scanner import Vulnerability
from agent.logger import get_logger
from agent.dependency_manager import DependencyManager


class RemediationEngine:
    """Handles vulnerability remediation - dependency updates only."""

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.logger = get_logger()
        self.dep_manager = DependencyManager(str(target_path), self.logger)
        self._init_git_repo()

    def _init_git_repo(self):
        """Initialize git repo if not exists."""
        if not (self.target_path / ".git").exists():
            try:
                subprocess.run(
                    ["git", "init"], cwd=str(self.target_path), capture_output=True
                )
                subprocess.run(
                    ["git", "config", "user.email", "agent@demo.local"],
                    cwd=str(self.target_path),
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "config", "user.name", "Security Agent"],
                    cwd=str(self.target_path),
                    capture_output=True,
                )
            except Exception as e:
                self.logger.warning(f"Failed to initialize git repo: {e}")

    def remediate_dependency(self, vuln: Vulnerability) -> bool:
        """Update outdated dependencies using package manager."""
        vuln_dep = getattr(vuln, "vulnerable_dependency", None)
        vuln_fixed = getattr(vuln, "fixed_version", None)

        if not vuln_dep or not vuln_fixed:
            return False

        req_files = list(self.target_path.glob("**/requirements.txt"))

        for req_file in req_files:
            try:
                with open(req_file, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if vuln_dep in content:
                    pkg_info = {
                        "package": vuln_dep,
                        "fixed_version": vuln_fixed,
                        "target": str(req_file),
                    }
                    success, _ = self.dep_manager.update_dependency(pkg_info)
                    return success
            except IOError:
                continue

        return False

    def remediate_all(
        self,
        vulnerabilities: list[Vulnerability],
        dry_run: bool = False,
    ) -> dict:
        """Remediate all vulnerabilities - dependencies only.

        Returns:
            Dict with 'dependencies', 'code_flaws', 'failed', 'diffs', 'files_modified'.
        """
        results = {"code_flaws": [], "dependencies": [], "failed": [], "diffs": [], "files_modified": 0}
        modified_files: set[str] = set()

        if not vulnerabilities:
            return results

        already_handled: set[str] = set()

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: sev_order.get(getattr(v, "severity", "UNKNOWN").upper(), 4)
        )

        for vuln in sorted_vulns:
            try:
                vuln_id = vuln.id if hasattr(vuln, "id") else str(vuln)
                vuln_type = getattr(vuln, "vuln_type", "code_flaw")
            except (AttributeError, ValueError) as e:
                vuln_id = str(vuln)
                vuln_type = "code_flaw"
                self.logger.error(f"Failed to get vuln info: {e}")

            if vuln_id in already_handled:
                continue

            try:
                if vuln_type in ("outdated_dependency", "dependency"):
                    success, diff = self.dep_manager.handle_dependency(vuln, dry_run)
                    if success:
                        results["dependencies"].append(vuln_id)
                        already_handled.add(vuln_id)
                        if diff:
                            results["diffs"].append(diff)
                    else:
                        results["failed"].append(vuln_id)
                else:
                    results["code_flaws"].append(vuln_id)
                    already_handled.add(vuln_id)
            except (ValueError, AttributeError, IOError) as e:
                self.logger.error(f"Failed processing {vuln_id}: {e}")
                results["failed"].append(vuln_id)

        # Track modified files from git diff
        try:
            import subprocess
            result = subprocess.run(
                ["git", "diff", "--name-only"],
                capture_output=True, text=True, cwd=str(self.target_path),
            )
            if result.returncode == 0:
                modified_files = {f.strip() for f in result.stdout.strip().split("\n") if f.strip()}
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            pass

        results["files_modified"] = len(modified_files)
        return results
