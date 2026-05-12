"""Agent Orchestrator - Central coordinator for the security remediation agent."""

from typing import Optional

from .scanner import VulnerabilityScanner
from .remediator import RemediationEngine
from .verifier import VerificationGate
from .git_integration import GitManager
from .scanners import run_all_scans, BanditScanner, PipAuditScanner
from pathlib import Path


class SecurityRemediationAgent:
    """Main agent orchestrator.

    Coordinates scanning, dependency remediation, and git operations.
    No LLM functionality - scanner-only design.
    """

    def __init__(self, target_path: str, config_path: str = "configs/agent_config.yaml", token: Optional[str] = None):
        self.target_path = Path(target_path)
        self.scanner = VulnerabilityScanner(target_path)
        self.remediator = RemediationEngine(target_path)
        self.verifier = VerificationGate(target_path)
        self.git_manager = GitManager(target_path, token=token)
        self.dry_run = False
        self._token = token

    def run_scan(self, report_path: str = None) -> list:
        """Scan for vulnerabilities."""
        vulns = self.scanner.scan_repo(report_path) if report_path else []
        return vulns

    def run_bandit_scan(self) -> list:
        """Run Bandit security scan."""
        scanner = BanditScanner(str(self.target_path))
        if scanner.is_available():
            result = scanner.scan()
            return result.vulnerabilities
        return []

    def run_pip_audit_scan(self) -> list:
        """Run pip-audit scan."""
        target = self.target_path
        if target.is_file():
            target = target.parent
        scanner = PipAuditScanner(str(target))
        if scanner.is_available():
            result = scanner.scan()
            return result.vulnerabilities
        return []

    def run_trivy_scan(self) -> list:
        """Run Trivy scan."""
        from .trivy_integration import TrivyScanner
        scanner = TrivyScanner(str(self.target_path))
        if scanner.is_available():
            result = scanner.scan()
            if result.success:
                return result.vulnerabilities
        return []

    def run_semgrep_scan(self, config: str = "p/security-audit") -> list:
        """Run Semgrep scanner."""
        from .semgrep_scanner import SemgrepScanner
        scanner = SemgrepScanner(str(self.target_path))
        if scanner and scanner.is_available():
            result = scanner.scan(config=config)
            if result.success:
                return result.vulnerabilities
        return []

    def run_gitleaks_scan(self) -> list:
        """Run Gitleaks secret detection."""
        from .scanners import GitleaksScanner
        scanner = GitleaksScanner(str(self.target_path))
        if scanner.is_available():
            result = scanner.scan()
            if result.success:
                return result.vulnerabilities
        return []

    def run_github_security_scan(
        self, owner: str = None, repo: str = None, token: str = None, include_secrets: bool = True
    ) -> list:
        """Fetch GitHub Advanced Security alerts."""
        from agent.github_security import run_github_security_scan

        result = run_github_security_scan(
            owner=owner, repo=repo, token=token, include_secrets=include_secrets
        )

        code_alerts = result.get("code_alerts", [])
        secret_alerts = result.get("secret_alerts", [])

        return code_alerts + secret_alerts

    def run_sarif_upload(
        self, sarif_file: str, owner: str = None, repo: str = None, token: str = None
    ) -> bool:
        """Upload SARIF results to GitHub."""
        from agent.github_security import upload_sarif_to_github
        return upload_sarif_to_github(sarif_file=sarif_file, owner=owner, repo=repo, token=token)

    def run_all_scanners(self) -> list:
        """Run all available scanners (5: Trivy, Semgrep, Bandit, pip-audit, Gitleaks)."""
        results = run_all_scans(str(self.target_path))
        vulns = results.get("all_vulnerabilities", [])

        return vulns

    def remediate(self, vulnerabilities: list) -> dict:
        """Remediate all vulnerabilities (dependencies only)."""
        return self.remediator.remediate_all(vulnerabilities, dry_run=self.dry_run)

    def create_branch_and_commit(self, branch_name: str, commit_message: str) -> bool:
        """Create branch and commit changes."""
        if not self.git_manager.is_valid_repo():
            return False

        current_branch = self.git_manager.get_current_branch()
        if current_branch != branch_name:
            result = self.git_manager.create_branch(branch_name)
            if result.status != "success":
                if not self.git_manager.branch_exists(branch_name):
                    return False
                self.git_manager.checkout_branch(branch_name)

        result = self.git_manager.commit_changes(commit_message)
        return result.status == "success"

    @staticmethod
    def _make_vuln_key(vuln) -> str:
        """Generate a stable, normalized key for vulnerability comparison.
        
        Priority:
          1. CVE ID extracted from the vulnerability id field
          2. vulnerable_dependency + current_version
          3. vulnerable_dependency + vulnerability id
          4. Just the vulnerability id (last resort)
        """
        import re

        vid = getattr(vuln, "id", None) or ""
        dep = getattr(vuln, "vulnerable_dependency", None) or ""
        current = getattr(vuln, "current_version", None) or ""

        cve_match = re.search(r"(CVE-\d{4}-\d+)", vid, re.IGNORECASE)
        if cve_match:
            return cve_match.group(1).upper()

        if dep:
            key = dep.lower().strip()
            if current:
                key += f":{current.lower().strip()}"
            else:
                key += f":{vid.lower().strip()}"
            return key

        return vid.lower().strip() if vid else ""

    def verify_remediation(self, before_dep_vulns: list) -> "VerificationResult":
        from agent.scanner import VerificationResult
        from agent.trivy_integration import TrivyScanner
        from agent.scanners import PipAuditScanner
        from agent.logger import get_logger

        log = get_logger()

        filtered_before = [
            v for v in before_dep_vulns
            if getattr(v, "scanner", "").lower() in ("trivy", "pip-audit")
            or (getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency")
                and getattr(v, "vulnerable_dependency", None))
        ]

        before_ids: set[str] = set()
        for v in filtered_before:
            key = self._make_vuln_key(v)
            if key:
                before_ids.add(key)

        after_vulns: list = []

        trivy = TrivyScanner(str(self.target_path))
        if trivy.is_available():
            result = trivy.scan()
            if result.success:
                after_vulns.extend(result.vulnerabilities)

        pip = PipAuditScanner(str(self.target_path))
        if pip.is_available():
            result = pip.scan()
            if result.success:
                after_vulns.extend(result.vulnerabilities)

        after_ids: set[str] = set()
        for v in after_vulns:
            if getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency"):
                key = self._make_vuln_key(v)
                if key:
                    after_ids.add(key)

        fixed_ids = before_ids - after_ids
        remaining_ids = before_ids & after_ids
        new_ids = after_ids - before_ids

        total = len(before_ids)
        fixed = len(fixed_ids)
        remaining = len(remaining_ids)
        new_issues = len(new_ids)

        log.info(
            f"Verification: filtered_before={total} after={len(after_ids)} "
            f"fixed={fixed} remaining={remaining} new={new_issues}"
        )

        if total == 0:
            msg = "No dependency vulnerabilities from Trivy/pip-audit to verify"
            success_flag = True
        elif fixed > 0 and remaining == 0:
            msg = f"All {fixed} dependency vulnerabilities successfully fixed"
            success_flag = True
        elif fixed > 0 and remaining > 0:
            msg = f"Fixed {fixed}/{total} – {remaining} still vulnerable"
            success_flag = False
        else:
            msg = f"No fixes detected ({total} still vulnerable)"
            success_flag = False

        return VerificationResult(
            fixed_count=fixed,
            remaining_count=remaining,
            new_issues_count=new_issues,
            still_vulnerable_ids=sorted(remaining_ids),
            success=success_flag,
            message=msg,
        )

    def push_and_create_pr(
        self, title: str, body: str, target_branch: str = "main"
    ) -> bool:
        """Push branch and create PR."""
        branch = self.git_manager.get_current_branch()

        result = self.git_manager.push_branch(branch)
        if result.status != "success":
            return False

        result = self.git_manager.create_pull_request(title, body, target_branch)
        return result.status == "success"
