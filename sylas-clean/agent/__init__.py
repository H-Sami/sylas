"""Sylas - Autonomous Security Remediation.

Version maintained in agent.constants (single source of truth).
Scanner-only architecture - no LLM dependencies.
"""

from .constants import __version__
from .scanner import VulnerabilityScanner, Vulnerability, VerificationResult
from .remediator import RemediationEngine
from .verifier import VerificationGate
from .git_integration import GitManager
from .trivy_integration import TrivyScanner, run_autonomous_scan
from .scanners import (
    BanditScanner,
    PipAuditScanner,
    GitleaksScanner,
    run_all_scans,
    ScannerResult,
    SCANNER_REGISTRY,
    get_scanner,
    list_available_scanners,
)
from .github_security import (
    GitHubAdvancedSecurityScanner,
    run_github_security_scan,
    upload_sarif_to_github,
)
from .github_auth import (
    GitHubAuth,
    RepoInfo,
    GitHubUser,
    check_gh_installed,
    check_gh_authenticated,
)
from .safety import PathSafetyError, is_path_safe_to_delete, is_path_safe_to_modify, safe_delete
from .orchestrator import SecurityRemediationAgent

__all__ = [
    "__version__",
    "VulnerabilityScanner",
    "Vulnerability",
    "VerificationResult",
    "RemediationEngine",
    "VerificationGate",
    "GitManager",
    "TrivyScanner",
    "run_autonomous_scan",
    "BanditScanner",
    "PipAuditScanner",
    "GitleaksScanner",
    "run_all_scans",
    "ScannerResult",
    "SCANNER_REGISTRY",
    "get_scanner",
    "list_available_scanners",
    "GitHubAdvancedSecurityScanner",
    "run_github_security_scan",
    "upload_sarif_to_github",
    "GitHubAuth",
    "RepoInfo",
    "GitHubUser",
    "check_gh_installed",
    "check_gh_authenticated",
    "PathSafetyError",
    "is_path_safe_to_delete",
    "is_path_safe_to_modify",
    "safe_delete",
    "SecurityRemediationAgent",
]
