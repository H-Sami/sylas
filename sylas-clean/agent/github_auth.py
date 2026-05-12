"""GitHub Authentication Module - Interactive token handling with priority order."""

import os
import json
import subprocess
import re
import urllib.parse
import configparser
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from .constants import API_TIMEOUT


logger = logging.getLogger(__name__)


def _validate_github_url(url: str) -> bool:
    """Validate and sanitize GitHub URL to prevent injection."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.scheme not in ("https", "http"):
            return False
        if parsed.netloc and not parsed.netloc.endswith("github.com"):
            return False
        if any(c in url for c in [";", "|", "`", "$", "(", ")", "<", ">", "&"]):
            return False
        return True
    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to validate GitHub URL: {e}")
        return False


@dataclass
class GitHubUser:
    """GitHub user information."""
    login: str
    name: Optional[str] = None
    avatar_url: Optional[str] = None


@dataclass
class RepoInfo:
    """Repository information."""
    owner: str
    name: str
    full_name: str
    is_private: bool
    clone_url: str
    ssh_url: Optional[str] = None


class GitHubAuth:
    """GitHub authentication with multiple fallback methods.

    Token priority (in order):
    1. --token flag (explicit)
    2. GITHUB_TOKEN env var
    3. gh auth (if installed + authenticated)
    4. Interactive prompt (fallback)
    """

    def __init__(self, token: Optional[str] = None):
        # Token stored only in memory for this session. Never persisted to disk, env, or config.
        self.token = token
        self.user: Optional[GitHubUser] = None
        self.base_url = "https://api.github.com"

    def get_token(self, prefer_explicit: bool = False, force_prompt: bool = False) -> Optional[str]:
        """Get token using priority order.

        Token stored only in memory for this session. Never persisted.

        Priority:
        1. Existing self.token (from --token arg)
        2. GITHUB_TOKEN or GH_TOKEN env var (skipped if force_prompt=True)
        3. gh auth token (gh CLI) (skipped if force_prompt=True)
        4. Interactive prompt

        Args:
            prefer_explicit: If True, skip interactive prompt
            force_prompt: If True, skip env vars and gh auth, go straight to prompt

        Returns:
            Token string or None
        """
        if force_prompt:
            self.token = None
            return self._prompt_for_token()

        if self.token:
            return self.token

        env_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if env_token:
            # Token stored only in memory for this session. Never persisted.
            self.token = env_token
            return self.token

        gh_token = self._check_gh_auth()
        if gh_token:
            # Token stored only in memory for this session. Never persisted.
            self.token = gh_token
            return self.token

        if not prefer_explicit:
            return self._prompt_for_token()

        return None

    def _check_gh_auth(self) -> Optional[str]:
        """Check if gh CLI is authenticated and extract token.

        Uses `gh auth token` (modern gh CLI) as primary method, with
        `gh auth status --show-token` as fallback.

        Returns:
            Token if gh is available and authenticated, None otherwise
        """
        try:
            # Modern gh CLI: `gh auth token` simply prints the token
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=API_TIMEOUT,
            )

            if result.returncode == 0:
                token = result.stdout.strip()
                if token and len(token) > 10:
                    return token
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            logger.warning("gh auth token command timed out")

        # Fallback: try `gh auth status --show-token` (older gh versions)
        try:
            result = subprocess.run(
                ["gh", "auth", "status", "--show-token"],
                capture_output=True,
                text=True,
                timeout=API_TIMEOUT,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Format: "  Token: ghp_xxxxxxxxxxxx"
                    if "Token:" in line:
                        parts = line.split("Token:", 1)
                        if len(parts) > 1:
                            token = parts[1].strip()
                            if token:
                                return token
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass

        return None

    def _prompt_for_token(self) -> Optional[str]:
        """Prompt user for GitHub token (masked input).

        Token stored only in memory for this session. Never persisted.
        """
        prompt_text = (
            "[?] Enter your GitHub Personal Access Token "
            "(used only for this session - will not be saved):"
        )
        try:
            import getpass
            raw = getpass.getpass(f"\n{prompt_text} ")
            token = raw.strip() if raw else ""
            if token:
                # Token stored only in memory for this session. Never persisted.
                self.token = token
                return self.token
        except Exception as e:
            logger.debug(f"getpass unavailable, falling back to input(): {e}")
        except KeyboardInterrupt:
            print()
            return None

        # Fallback: normal input (no masking)
        try:
            print(f"\n{prompt_text} ", end="", flush=True)
            raw = input()
            token = raw.strip() if raw else ""
            if token:
                # Token stored only in memory for this session. Never persisted.
                self.token = token
                return self.token
        except (EOFError, KeyboardInterrupt):
            print()

        return None

    def check_token(self, token: str) -> Optional[GitHubUser]:
        """Verify token and return user info.

        Token stored only in memory for this session. Never persisted.
        """
        import requests

        try:
            response = requests.get(
                f"{self.base_url}/user",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=API_TIMEOUT,
            )

            if response.status_code == 200:
                data = response.json()
                self.user = GitHubUser(
                    login=data.get("login", ""),
                    name=data.get("name"),
                    avatar_url=data.get("avatar_url"),
                )
                # Token stored only in memory for this session. Never persisted.
                self.token = token
                return self.user
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to get user info: {e}")

        return None

    def verify_connection(self) -> bool:
        """Verify token and get user info.

        Token stored only in memory for this session. Never persisted.
        """
        token = self.get_token()
        if not token:
            return False
        user = self.check_token(token)
        return user is not None

    def get_repo_info_from_path(self, path: str = ".") -> Optional[RepoInfo]:
        """Get repo info from local git directory."""
        repo_path = Path(path)
        config_file = repo_path / ".git" / "config"
        if not config_file.exists():
            return None

        try:
            cfg = configparser.ConfigParser()
            cfg.read(str(config_file), encoding="utf-8")
        except (configparser.Error, IOError) as e:
            logger.warning(f"Failed to parse .git/config: {e}")
            return None

        section = 'remote "origin"'
        if section not in cfg:
            return None

        url = cfg.get(section, "url", fallback=None)
        if not url:
            return None

        owner = name = clone_url = ssh_url = None

        https_match = re.search(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", url)
        if https_match:
            owner, name = https_match.group(1), https_match.group(2)
            clone_url = url if url.endswith(".git") else f"{url}.git"

        ssh_match = re.search(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$", url)
        if ssh_match:
            owner, name = ssh_match.group(1), ssh_match.group(2)
            ssh_url = url if url.endswith(".git") else f"{url}.git"
            clone_url = f"https://github.com/{owner}/{name}.git"

        if not owner or not name:
            return None

        return RepoInfo(
            owner=owner,
            name=name,
            full_name=f"{owner}/{name}",
            is_private=False,
            clone_url=clone_url,
            ssh_url=ssh_url,
        )

    def get_repo_info_from_url(self, url: str) -> RepoInfo:
        """Parse repository URL to get info."""
        url = url.strip()
        owner = None
        name = None
        is_private = False

        if "github.com" in url:
            path = url.replace("https://github.com/", "").replace(
                "http://github.com/", ""
            )
            path = path.rstrip("/").split("/")
            if len(path) >= 2:
                owner, name = path[0], path[1]
                if name.endswith(".git"):
                    name = name[:-4]

        if not owner and "git@github.com:" in url:
            path = url.replace("git@github.com:", "").rstrip("/").split("/")
            if len(path) >= 2:
                owner, name = path[0], path[1]
                if name.endswith(".git"):
                    name = name[:-4]

        if not owner and "/" in url:
            parts = url.strip().split("/")
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
                if name.endswith(".git"):
                    name = name[:-4]

        if not owner or not name:
            raise ValueError(f"Invalid repository URL: {url}")

        return RepoInfo(
            owner=owner,
            name=name,
            full_name=f"{owner}/{name}",
            is_private=is_private,
            clone_url=f"https://github.com/{owner}/{name}.git",
            ssh_url=f"git@github.com:{owner}/{name}.git",
        )

    def clone_repo(
        self, url: str, target_dir: Optional[str] = None, token: Optional[str] = None
    ) -> tuple[bool, str]:
        """Clone repository with security checks."""
        if not _validate_github_url(url):
            return False, "Invalid URL - potential injection detected"

        repo_info = self.get_repo_info_from_url(url)

        if not target_dir:
            target_dir = repo_info.name

        if Path(target_dir).exists():
            return True, f"Directory '{target_dir}' already exists"

        try:
            result = subprocess.run(
                ["gh", "repo", "clone", repo_info.full_name, "--", target_dir],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                return True, f"Cloned via gh CLI: {repo_info.full_name}"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        clone_url = repo_info.clone_url
        git_cmd = "git"

        try:
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            if token and "github.com" in clone_url:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(clone_url)
                authed = parsed._replace(
                    netloc=f"x-token:{token}@{parsed.hostname}"
                )
                clone_url = urlunparse(authed)

            try:
                result = subprocess.run(
                    [git_cmd, "clone", clone_url, target_dir],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    env=env,
                )
                if result.returncode == 0:
                    return True, f"Cloned successfully: {repo_info.full_name}"
                else:
                    error = result.stderr or result.stdout
                    return False, f"Clone failed: {error}"
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                return False, f"Clone error: {str(e)}"
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return False, f"Clone error: {str(e)}"

    def is_private_repo(self, owner: str, name: str, token: str) -> bool:
        """Check if repository is private."""
        import requests

        try:
            response = requests.get(
                f"{self.base_url}/repos/{owner}/{name}",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=API_TIMEOUT,
            )

            if response.status_code == 200:
                return response.json().get("private", False)
        except requests.RequestException:
            pass

        return False


def check_gh_installed() -> bool:
    """Check if gh CLI is installed."""
    try:
        result = subprocess.run(
            ["gh", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def check_gh_authenticated() -> bool:
    """Check if gh CLI is authenticated."""
    if not check_gh_installed():
        return False

    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=API_TIMEOUT,
        )
        return result.returncode == 0 and "authenticated" in result.stdout.lower()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"Failed to check gh CLI: {e}")
        return False
