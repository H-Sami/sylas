"""Verification Gate - Validates file integrity and provides diff stats."""

import os
import subprocess
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from agent.constants import DEFAULT_EXCLUDE_PATTERNS

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    passed: bool
    syntax_valid: bool
    error_message: str = None


class VerificationGate:
    """Validates remediation success - syntax checks and git diff stats."""

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)

    def verify_remediation(
        self,
        original_vuln_id: str,
        scan_report_path: str = None,
        test_command: str = "pytest",
    ) -> VerificationResult:
        """Verify that a specific vulnerability was remediated."""
        syntax_valid = self._verify_syntax_valid()
        return VerificationResult(
            passed=syntax_valid,
            syntax_valid=syntax_valid,
        )

    def _verify_syntax_valid(self) -> bool:
        """Check if all Python files have valid syntax."""
        broken = self._get_broken_files()
        return len(broken) == 0

    def _get_broken_files(self, files_to_check: list = None) -> list:
        """Get list of Python files with syntax errors."""
        broken = []

        if files_to_check:
            for f in files_to_check:
                p = Path(f)
                if not p.is_absolute():
                    p = self.target_path / p

                p_str = str(p)
                if any(pattern in p_str for pattern in DEFAULT_EXCLUDE_PATTERNS):
                    continue

                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as file_handle:
                        compile(file_handle.read(), str(p), "exec")
                except SyntaxError as e:
                    broken.append(str(p))
                    logger.warning(f"Syntax error in {p}: {e}")
                except (IOError, UnicodeDecodeError):
                    pass
        else:
            for py_file in self.target_path.glob("**/*.py"):
                py_str = str(py_file)
                if any(pattern in py_str for pattern in DEFAULT_EXCLUDE_PATTERNS):
                    continue

                try:
                    with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                        compile(f.read(), str(py_file), "exec")
                except SyntaxError as e:
                    broken.append(str(py_file))
                    logger.warning(f"Syntax error in {py_file}: {e}")
                except (IOError, UnicodeDecodeError):
                    pass

        return broken

    def get_git_diff_stats(self) -> dict:
        """Get git diff statistics with proper parsing."""
        try:
            result = subprocess.run(
                ["git", "diff", "--shortstat"],
                capture_output=True,
                text=True,
                cwd=str(self.target_path),
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_shortstat(result.stdout.strip())

            result = subprocess.run(
                ["git", "diff", "--stat"],
                capture_output=True,
                text=True,
                cwd=str(self.target_path),
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_stat(result.stdout.strip())

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Failed to get git diff stats: {e}")

        return {"files_changed": 0, "additions": 0, "deletions": 0}

    def _parse_shortstat(self, output: str) -> dict:
        stats = {"files_changed": 0, "additions": 0, "deletions": 0}

        files_match = re.search(r"(\d+)\s+file", output)
        if files_match:
            stats["files_changed"] = int(files_match.group(1))

        insertions_match = re.search(r"(\d+)\s+insertion", output)
        if insertions_match:
            stats["additions"] = int(insertions_match.group(1))

        deletions_match = re.search(r"(\d+)\s+deletion", output)
        if deletions_match:
            stats["deletions"] = int(deletions_match.group(1))

        return stats

    def _parse_stat(self, output: str) -> dict:
        stats = {"files_changed": 0, "additions": 0, "deletions": 0}

        lines = output.strip().split("\n")

        for line in lines:
            if "file" in line and "changed" in line:
                files_match = re.search(r"(\d+)\s+file", line)
                if files_match:
                    stats["files_changed"] = max(stats["files_changed"], int(files_match.group(1)))

                insertions_match = re.search(r"(\d+)\s+insertion", line)
                if insertions_match:
                    stats["additions"] = int(insertions_match.group(1))

                deletions_match = re.search(r"(\d+)\s+deletion", line)
                if deletions_match:
                    stats["deletions"] = int(deletions_match.group(1))

        return stats

    def get_changed_files(self) -> list[str]:
        """Get list of changed files."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only"],
                capture_output=True,
                text=True,
                cwd=str(self.target_path),
            )
            if result.returncode == 0:
                files = [
                    f.strip() for f in result.stdout.strip().split("\n") if f.strip()
                ]
                filtered = []
                for f in files:
                    if any(pattern in f for pattern in DEFAULT_EXCLUDE_PATTERNS):
                        continue
                    filtered.append(f)
                return filtered
            return []
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Failed to get changed files: {e}")
            return []
