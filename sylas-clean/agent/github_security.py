"""GitHub Advanced Security Scanner Integration."""

import json
import logging
import requests
import subprocess
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from .scanner import Vulnerability
from .constants import API_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class GitHubAlert(Vulnerability):
    """GitHub-specific vulnerability with alert URL."""
    alert_url: Optional[str] = None
    alert_id: Optional[int] = None
    alert_state: Optional[str] = None


class GitHubAdvancedSecurityScanner:
    """GitHub Advanced Security API integration.

    Features:
    - Fetch code scanning alerts
    - Fetch secret scanning alerts
    - Upload SARIF results (works without GHAS license)
    - Update alert status after remediation
    """

    def __init__(self, owner: str = None, repo: str = None, token: str = None):
        self.owner = owner
        self.repo = repo
        self.token = token or self._get_token()
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {self.token}" if self.token else "",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _get_token(self) -> Optional[str]:
        """Get token from config, environment, or gh CLI."""
        import os
        for path in [Path("configs/github_token.txt"), Path(".github_token")]:
            if path.exists():
                return path.read_text().strip()

        env_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if env_token:
            return env_token

        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
                if token and len(token) > 10:
                    return token
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def is_available(self) -> bool:
        """Check if GitHub Advanced Security is enabled."""
        if not self.owner or not self.repo:
            return False

        try:
            url = f"{self.base_url}/repos/{self.owner}/{self.repo}"
            response = requests.get(url, headers=self.headers, timeout=API_TIMEOUT)
            if response.status_code != 200:
                return False

            data = response.json()
            security = data.get("security_and_analysis", {})

            advanced_security = security.get("advanced_security", "disabled")
            code_scanning = security.get("code_scanning_enabled", False)

            return advanced_security == "enabled" or code_scanning is True
        except (requests.RequestException, json.JSONDecodeError, KeyError):
            return False

    def _get_severity_level(self, severity_str: str) -> str:
        """Convert GH severity to our format."""
        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "note": "INFO",
        }
        return mapping.get(severity_str.lower(), "MEDIUM")

    def list_code_scanning_alerts(self, state: str = "open", tool: str = None) -> list[GitHubAlert]:
        """Fetch code scanning alerts from GitHub."""
        if not self.owner or not self.repo:
            return []

        alerts = []
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/code-scanning/alerts"

        params = {"state": state}
        if tool:
            params["tool"] = tool

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 404:
                logger.info("Code scanning not enabled on this repository")
                return []
            elif response.status_code == 403:
                logger.info("GitHub Advanced Security not available (paid feature)")
                return []
            elif response.status_code != 200:
                logger.warning(f"Error fetching alerts: {response.status_code}")
                return []

            data = response.json()

            for alert in data:
                try:
                    location = alert.get("most_recent_instance", {}).get("location", {})
                    classification = alert.get("most_recent_instance", {}).get("classification", "inaccessible")

                    if classification in ["external", "test"]:
                        continue

                    severity_str = alert.get("security_severity_level", "medium")

                    desc = f"Code scanning alert: {alert.get('rule_description')}"
                    gh_alert = GitHubAlert(
                        id=f"GH-CODE-{alert.get('rule_id', 'unknown')}",
                        title=alert.get("rule_description", "Security issue"),
                        severity=self._get_severity_level(severity_str),
                        file=location.get("path", ""),
                        line=location.get("start_line", 0),
                        description=desc,
                        vuln_type="code_flaw",
                        scanner="github",
                        cwe=alert.get("rule_id", ""),
                        alert_url=alert.get("html_url", ""),
                        alert_id=alert.get("number"),
                        alert_state=alert.get("state", state),
                    )
                    alerts.append(gh_alert)
                except (KeyError, ValueError, json.JSONDecodeError):
                    continue

        except requests.RequestException as e:
            logger.error(f"Network error: {e}")

        return alerts

    def _get_head_sha(self) -> Optional[str]:
        """Resolve HEAD SHA by checking multiple branch sources.

        Priority:
        1. git symbolic-ref refs/remotes/origin/HEAD (local git metadata)
        2. Common branch names (main, master)
        3. Repository's default_branch from GitHub API
        """
        try:
            result = subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                capture_output=True, text=True, timeout=10,
                cwd=".",
            )
            if result.returncode == 0:
                ref = result.stdout.strip()
                if ref:
                    sha_result = subprocess.run(
                        ["git", "rev-parse", ref],
                        capture_output=True, text=True, timeout=10,
                        cwd=".",
                    )
                    if sha_result.returncode == 0:
                        sha = sha_result.stdout.strip()
                        if sha:
                            return sha
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        base = f"{self.base_url}/repos/{self.owner}/{self.repo}"
        for branch in ("main", "master"):
            try:
                resp = requests.get(
                    f"{base}/git/refs/heads/{branch}",
                    headers=self.headers,
                    timeout=API_TIMEOUT,
                )
                if resp.status_code == 200:
                    return resp.json().get("object", {}).get("sha")
            except requests.RequestException:
                continue

        try:
            repo_resp = requests.get(base, headers=self.headers, timeout=API_TIMEOUT)
            if repo_resp.status_code == 200:
                default_branch = repo_resp.json().get("default_branch")
                if default_branch:
                    ref_resp = requests.get(
                        f"{base}/git/refs/heads/{default_branch}",
                        headers=self.headers,
                        timeout=API_TIMEOUT,
                    )
                    if ref_resp.status_code == 200:
                        return ref_resp.json().get("object", {}).get("sha")
        except requests.RequestException:
            pass

        logger.error(
            "Could not determine HEAD commit SHA. "
            "Ensure the repository has at least one commit and a default branch."
        )
        return None

    def update_code_scanning_alert(self, alert_number: int, state: str = "fixed", dismissal_reason: str = None) -> bool:
        """Update code scanning alert status."""
        if not self.owner or not self.repo:
            return False

        base = f"{self.base_url}/repos/{self.owner}/{self.repo}"
        url = f"{base}/code-scanning/alerts/{alert_number}"

        payload = {"state": state}
        if state == "dismissed" and dismissal_reason:
            payload["dismissed_reason"] = dismissal_reason

        try:
            response = requests.patch(url, headers=self.headers, json=payload, timeout=API_TIMEOUT)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def list_secret_scanning_alerts(self, state: str = "open", secret_type: str = None) -> list[GitHubAlert]:
        """Fetch secret scanning alerts from GitHub."""
        if not self.owner or not self.repo:
            return []

        alerts = []
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/secret-scanning/alerts"

        params = {"state": state}
        if secret_type:
            params["secret_type"] = secret_type

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 404:
                logger.info("Secret scanning not enabled")
                return []
            elif response.status_code == 403:
                logger.info("GitHub Advanced Security required for secret scanning")
                return []
            elif response.status_code != 200:
                return []

            data = response.json()

            for alert in data:
                gh_alert = GitHubAlert(
                    id=f"GH-SECRET-{alert.get('secret_type', 'unknown')}",
                    title=f"Exposed {alert.get('secret_type', 'secret')}",
                    severity="CRITICAL",
                    file=alert.get("location", {}).get("path", ""),
                    line=alert.get("location", {}).get("start_line", 0),
                    description=f"Secret scanning alert: {alert.get('secret_type')}",
                    vuln_type="hardcoded_secret",
                    scanner="github",
                    alert_url=alert.get("html_url", ""),
                    alert_id=alert.get("number"),
                    alert_state=alert.get("state", state),
                )
                alerts.append(gh_alert)

        except requests.RequestException:
            pass

        return alerts

    def update_secret_scanning_alert(self, alert_number: int, resolution: str = "revoked") -> bool:
        """Update secret scanning alert status."""
        if not self.owner or not self.repo:
            return False

        base = f"{self.base_url}/repos/{self.owner}/{self.repo}"
        url = f"{base}/secret-scanning/alerts/{alert_number}"

        payload = {"state": "resolved", "resolution": resolution}

        try:
            response = requests.patch(url, headers=self.headers, json=payload, timeout=API_TIMEOUT)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def upload_sarif(self, sarif_file: str, commit_oid: str = None, category: str = "sec") -> Optional[dict]:
        """Upload SARIF results to GitHub."""
        if not self.owner or not self.repo:
            logger.error("Owner and repo required for SARIF upload")
            return None

        sarif_path = Path(sarif_file)
        if not sarif_path.exists():
            logger.error(f"SARIF file not found: {sarif_file}")
            return None

        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/code-scanning/sarifs"

        try:
            import gzip
            import base64

            sarif_content = sarif_path.read_bytes()

            compressed = gzip.compress(sarif_content)
            encoded = base64.b64encode(compressed).decode("ascii")

            if not commit_oid:
                commit_oid = self._get_head_sha()

            if not commit_oid:
                raise ValueError(
                    "Could not determine HEAD commit SHA. "
                    "Pass commit_oid explicitly or ensure the repository has at least one commit."
                )

            payload = {"sarif": encoded, "commit_sha": commit_oid, "category": category}

            response = requests.post(
                url,
                headers={**self.headers, "Content-Type": "application/json"},
                json=payload,
                timeout=60,
            )

            if response.status_code == 202:
                logger.info("SARIF uploaded successfully")
                return response.json()
            elif response.status_code == 400:
                error = response.json()
                logger.warning(f"SARIF validation error: {error.get('message', 'Unknown')}")
            else:
                logger.warning(f"SARIF upload failed: {response.status_code}")

        except (requests.RequestException, IOError, json.JSONDecodeError) as e:
            logger.error(f"Error uploading SARIF: {e}")

        return None

    def run_scan(self, include_secrets: bool = True) -> dict:
        """Run full GitHub Advanced Security scan."""
        result = {
            "code_alerts": [],
            "secret_alerts": [],
            "available": self.is_available(),
            "sarif_upload_supported": True,
        }

        code_alerts = self.list_code_scanning_alerts(state="open")
        result["code_alerts"] = code_alerts

        if include_secrets:
            secret_alerts = self.list_secret_scanning_alerts(state="open")
            result["secret_alerts"] = secret_alerts

        return result


def run_github_security_scan(
    owner: str = None, repo: str = None, token: str = None, include_secrets: bool = True
) -> dict:
    """Convenience function for GitHub Advanced Security scanning.

    Args:
        owner: Repository owner (defaults to remote origin)
        repo: Repository name
        token: GitHub token
        include_secrets: Include secret scanning

    Returns:
        Dict with scan results
    """
    scanner = GitHubAdvancedSecurityScanner(owner, repo, token)
    return scanner.run_scan(include_secrets=include_secrets)


def upload_sarif_to_github(
    sarif_file: str, owner: str = None, repo: str = None, token: str = None
) -> Optional[dict]:
    """Upload SARIF results to GitHub.

    Works even without GitHub Advanced Security!

    Args:
        sarif_file: Path to SARIF file
        owner: Repository owner
        repo: Repository name
        token: GitHub token

    Returns:
        Upload result or None
    """
    scanner = GitHubAdvancedSecurityScanner(owner, repo, token)
    return scanner.upload_sarif(sarif_file)
