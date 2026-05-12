"""Semgrep Scanner Integration - Fast static analysis with 30+ languages."""

import json
import subprocess
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from .scanner import Vulnerability
from .scanners import BaseScanner
from .constants import SEMGREP_TYPE_MAPPINGS

logger = logging.getLogger(__name__)


@dataclass
class SemgrepResult:
    """Result from Semgrep scan."""
    scanner: str = "semgrep"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    success: bool = False
    output: str = ""
    error: Optional[str] = None


class SemgrepScanner(BaseScanner):
    """Semgrep - Fast, open-source static analysis tool.

    Supports 30+ languages with 3,000+ community rules.
    Install: pip install semgrep
    """

    def __init__(self, target_path: str = ".", output_dir: Optional[str] = None):
        super().__init__(target_path)
        self.output_dir = Path(output_dir) if output_dir is not None else self.target_path

    def is_available(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, output_file: str = "semgrep_results.json", config: str = "p/default") -> SemgrepResult:
        """Run Semgrep scan and return results.

        Args:
            output_file: JSON output file path
            config: Rule config (p/default, p/security-audit, or custom)
        """
        output_path = str(self.output_dir / output_file)
        if not self.is_available():
            return SemgrepResult(
                success=False,
                error="Semgrep not installed. Run: pip install semgrep",
            )

        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--json",
                    "--output",
                    output_path,
                    "--config",
                    config,
                    str(self.target_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )

            vulnerabilities = []
            if Path(output_path).exists():
                with open(output_path, encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                    for finding in data.get("results", []):
                        vuln = self._parse_finding(finding)
                        if vuln:
                            vulnerabilities.append(vuln)

            success = result.returncode in [0, 1]
            return SemgrepResult(
                scanner="semgrep",
                vulnerabilities=vulnerabilities,
                success=success,
                output=(result.stdout or "") + (result.stderr or ""),
            )

        except subprocess.TimeoutExpired:
            return SemgrepResult(
                success=False,
                error="Scan timed out",
            )
        except (subprocess.CalledProcessError, json.JSONDecodeError, IOError, ValueError) as e:
            return SemgrepResult(
                success=False,
                error=str(e),
            )

    def _parse_finding(self, finding: dict) -> Optional[Vulnerability]:
        """Parse a Semgrep finding into a Vulnerability object."""
        try:
            check_id = finding.get("check_id", "unknown")
            severity = self._map_severity(finding.get("extra", {}).get("severity"))

            return Vulnerability(
                id=f"SEMGREP-{check_id}",
                title=finding.get("extra", {}).get("message", "Security Issue"),
                severity=severity,
                file=finding.get("path", ""),
                line=finding.get("start", {}).get("line", 0),
                description=finding.get("extra", {}).get("message", ""),
                vuln_type=self._map_vuln_type(check_id),
                scanner="semgrep",
            )
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to parse Semgrep finding: {e}")
            return None

    def _map_severity(self, severity: str) -> str:
        """Map Semgrep severity to our format."""
        mapping = {
            "ERROR": "CRITICAL",
            "WARNING": "HIGH",
            "INFO": "MEDIUM",
            "EXPERIMENTAL": "LOW",
        }
        return mapping.get(severity, "MEDIUM")

    def _map_vuln_type(self, check_id: str) -> str:
        """Map Semgrep check ID to vulnerability type.

        Three-tier strategy:
        1. Exact short_name match in SEMGREP_TYPE_MAPPINGS
        2. Keyword extraction — scan the full check_id for known vulnerability
           keywords (xss, sql, csrf, pickle, subprocess, etc.) and map them.
           This catches patterns like python.django.security.xss.* even when
           no exact short_name matches exist.
        3. Fallback to 'code_flaw' (better than 'default' which has no prompt)
        """
        if not check_id:
            return "code_flaw"

        check_id_lower = check_id.lower()
        parts = check_id.split(".")
        short_name = parts[-1].lower() if parts else check_id_lower

        # Tier 1: exact short_name match
        if short_name in SEMGREP_TYPE_MAPPINGS:
            return SEMGREP_TYPE_MAPPINGS[short_name]

        # Tier 2: keyword extraction from full check_id (MOST specific match wins)
        # This runs BEFORE generic substring match to avoid "django.security"
        # matching before the specific "xss" keyword.
        keyword_map = [
            # Command / OS injection
            (["subprocess", "shell", "os.system", "os.exec", "popen", "os.popen", "command"], "command_injection"),
            # SQL injection
            (["sql", "sqli", "sqla", "database", "db."], "sql_injection"),
            # XSS / template injection
            (["xss", "cross.site", "template", "jinja2", "mark_safe", "format_html", "autoescape"], "xss"),
            # CSRF
            (["csrf", "csrf_token"], "django-no-csrf-token"),
            # Hardcoded secrets
            (["hardcoded", "secret", "password", "credential", "api.key", "jwt", "oauth", "token"], "hardcoded_secret"),
            # Insecure deserialization
            (["pickle", "yaml.load", "marshal", "jsonpickle", "deserialization"], "insecure_deserialization"),
            # Path traversal
            (["path", "traversal", "filepath", "directory"], "path_traversal"),
            # SSRF
            (["ssrf", "request.forgery", "url.fetch"], "ssrf"),
            # XXE
            (["xxe", "xml.external", "xml.parser", "lxml", "etree", "defusedxml"], "xxe"),
            # Open redirect
            (["redirect", "open_redirect"], "open_redirect"),
            # Prototype pollution
            (["prototype", "proto.pollution"], "prototype_pollution"),
            # Integrity / SRI
            (["integrity", "sri", "subresource"], "missing-integrity"),
            # Weak crypto
            (["md5", "sha1", "des", "rc4", "weak.cipher", "weak.hash", "insecure.hash"], "code_flaw"),
            # Dangerous functions
            (["eval", "exec", "compile"], "command_injection"),
            # Flask/Express
            (["app.run", "flask.debug", "debug.mode"], "avoid_using_app_run_directly"),
            # Insecure HTTP
            (["http.request", "http.url", "https", "ssl", "tls", "cleartext"], "request-with-http"),
        ]

        for keywords, vuln_type in keyword_map:
            for kw in keywords:
                if kw in check_id_lower:
                    return vuln_type

        # Tier 4: if short_name has no known keywords, map to code_flaw
        # (better than "default" which has no specific prompt)
        return "code_flaw"
