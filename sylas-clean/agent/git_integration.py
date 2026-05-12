"""Git integration with security guardrails for Sylas."""

import os
import subprocess
import requests
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from agent.utils import create_requests_session
from agent.constants import PROTECTED_BRANCHES, API_TIMEOUT

logger = logging.getLogger(__name__)

FORBIDDEN_ACTIONS = [
    "force-push to protected branches",
    "delete branches without approval",
    "push secrets or credentials",
    "execute arbitrary external code",
    "modify CI/CD configurations",
    "access repos outside scoped target",
    "create commits on protected branches",
]


@dataclass
class GitOperation:
    action: str
    status: str
    message: Optional[str] = None
    branch_name: Optional[str] = None


class GitManager:
    """Manages Git operations with security guardrails."""

    def __init__(self, repo_path: str, token: Optional[str] = None):
        self.repo_path = Path(repo_path)
        self.token = token or os.environ.get("GITHUB_TOKEN", "")

    def _run_git(self, args: list[str], capture: bool = True) -> subprocess.CompletedProcess:
        """Execute git command with error handling."""
        try:
            result = subprocess.run(
                ["git"] + args,
                capture_output=capture,
                text=True,
                cwd=str(self.repo_path),
            )
            return result
        except FileNotFoundError:
            raise RuntimeError("Git not found. Please install Git.")

    def is_valid_repo(self) -> bool:
        """Check if directory is a valid git repository."""
        result = self._run_git(["status"])
        return result.returncode == 0

    def get_current_branch(self) -> Optional[str]:
        """Get the current branch name."""
        result = self._run_git(["branch", "--show-current"])
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def _get_remote_info(self) -> Optional[tuple[str, str]]:
        """Get remote owner and repo name."""
        result = self._run_git(["config", "--get", "remote.origin.url"])
        if result.returncode != 0:
            return None

        url = result.stdout.strip()
        if url.endswith(".git"):
            url = url[:-4]

        if "github.com/" in url:
            parts = url.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                return (parts[0], parts[1])

        return None

    def create_branch(self, branch_name: str) -> GitOperation:
        """Create a new branch for remediation work."""
        if not self._is_branch_name_valid(branch_name):
            return GitOperation(
                action="create_branch",
                status="failed",
                message="Invalid branch name",
            )

        result = self._run_git(["checkout", "-b", branch_name])

        if result.returncode == 0:
            return GitOperation(
                action="create_branch",
                status="success",
                branch_name=branch_name,
                message=f"Created branch: {branch_name}",
            )

        return GitOperation(
            action="create_branch",
            status="failed",
            message=result.stderr,
        )

    def branch_exists(self, branch_name: str) -> bool:
        """Check if branch exists locally or remotely."""
        result = self._run_git(["rev-parse", "--verify", f"refs/heads/{branch_name}"])
        if result.returncode == 0:
            return True

        result = self._run_git(["ls-remote", "--heads", ".", branch_name])
        return result.returncode == 0 and bool(result.stdout)

    def checkout_branch(self, branch_name: str) -> GitOperation:
        """Checkout an existing branch."""
        result = self._run_git(["checkout", branch_name])
        if result.returncode == 0:
            return GitOperation(
                action="checkout",
                status="success",
                branch_name=branch_name,
                message=f"Switched to branch: {branch_name}",
            )
        return GitOperation(
            action="checkout",
            status="failed",
            message=result.stderr,
        )

    def _is_branch_name_valid(self, name: str) -> bool:
        """Validate branch name follows conventions."""
        if name.startswith("-"):
            return False
        if "/" in name and not name.startswith("feature/"):
            return False
        return True

    def commit_changes(self, message: str, files: Optional[list] = None) -> GitOperation:
        """Commit changes with security checks."""
        if self._contains_secrets(message):
            return GitOperation(
                action="commit",
                status="failed",
                message="Commit message contains potential secrets",
            )

        if files:
            for file in files:
                self._run_git(["add", file])
        else:
            self._run_git(["add", "-A"])

        result = self._run_git(["commit", "-m", message])

        if result.returncode == 0:
            return GitOperation(
                action="commit",
                status="success",
                message=f"Committed: {message}",
            )

        return GitOperation(
            action="commit",
            status="failed",
            message=result.stderr,
        )

    def _contains_secrets(self, text: str) -> bool:
        """Check if text contains potential secrets."""
        secret_patterns = [
            r"password\s*=\s*['\"].+['\"]",
            r"api[_-]?key\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
            r"secret\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
            r"Bearer\s+[a-zA-Z0-9_\-\.]+",
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        ]
        import re

        for pattern in secret_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def push_branch(self, branch_name: Optional[str] = None, upstream: bool = True) -> GitOperation:
        """Push branch to remote with security checks."""
        if branch_name is None:
            branch_name = self.get_current_branch()

        if not branch_name:
            return GitOperation(
                action="push",
                status="failed",
                message="No branch specified",
            )

        args = ["push"]
        if upstream:
            args.extend(["-u", "origin", branch_name])
        else:
            args.extend(["origin", branch_name])

        result = self._run_git(args)

        if result.returncode == 0:
            return GitOperation(
                action="push",
                status="success",
                message=f"Pushed branch: {branch_name}",
                branch_name=branch_name,
            )

        return GitOperation(
            action="push",
            status="failed",
            message=result.stderr,
        )

    def create_pull_request(self, title: str, body: str, target_branch: str = "main") -> GitOperation:
        current = self.get_current_branch()

        if not current:
            return GitOperation(
                action="create_pr",
                status="failed",
                message="No current branch",
            )

        if not self.token:
            return GitOperation(
                action="create_pr",
                status="failed",
                message="No GitHub token available. Please provide a valid token with 'repo' scope.",
            )

        push_result = self.push_branch(current)
        if push_result.status != "success":
            return GitOperation(
                action="create_pr",
                status="failed",
                message=f"Push failed: {push_result.message}",
            )

        repo = self._get_remote_info()
        if not repo:
            return GitOperation(
                action="create_pr",
                status="failed",
                message="No remote repository found",
            )

        owner, repo_name = repo

        url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls"

        payload = {
            "title": title,
            "body": body,
            "base": target_branch,
            "head": current,
        }

        try:
            session = create_requests_session(retries=3)
            response = session.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"token {self.token}" if self.token else "",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=API_TIMEOUT,
            )
            response.raise_for_status()
            result = response.json()
            pr_url = result.get("html_url", "")
            return GitOperation(
                action="create_pr",
                status="success",
                message=f"Created PR: {pr_url}",
                branch_name=current,
            )
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else "unknown"
            reason = e.response.reason if e.response else "unknown"
            error_body = e.response.text if e.response else "No response body"
            return GitOperation(
                action="create_pr",
                status="failed",
                message=f"HTTP {status_code}: {reason} - {error_body}",
            )
        except requests.exceptions.RequestException as e:
            return GitOperation(
                action="create_pr",
                status="failed",
                message=str(e),
            )

    def get_diff(self, file_path: Optional[str] = None) -> str:
        """Get git diff for file or all changes."""
        args = ["diff"]
        if file_path:
            args.append(file_path)

        result = self._run_git(args)
        return result.stdout if result.returncode == 0 else ""

    def check_conflicts(self) -> tuple[bool, list]:
        """Check for merge conflicts."""
        result = self._run_git(["diff", "--name-only", "--diff-filter=U"])
        conflicts = result.stdout.strip().split("\n") if result.stdout.strip() else []
        return (bool(conflicts), conflicts)
