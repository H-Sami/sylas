"""Sylas - Autonomous Security Remediation - Main CLI Entry Point."""

import argparse
import sys
from pathlib import Path

from agent.report import VulnerabilityReport
from agent.logger import get_logger, init_logging
from agent.orchestrator import SecurityRemediationAgent
from agent.cli import (
    interactive_mode,
    print_banner,
    print_info,
    print_success,
    print_warning,
    print_error,
    _show_scan_summary,
    _show_remediation_summary,
    C,
    get_input,
)
from agent.github_auth import GitHubAuth
from agent.constants import __version__


def main():
    """Main entry point for CLI."""
    print_banner()
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.interactive or args.target is None:
        return interactive_mode()

    if not args.target:
        print_error("Target path required. Use --interactive for interactive mode.")
        print_info("Usage: python -m agent.main --interactive")
        print_info("   or: python -m agent.main <path> [options]")
        return 1

    agent = SecurityRemediationAgent(args.target, token=args.token)
    agent.skip_git = args.no_git

    auth = None
    if args.token:
        auth = GitHubAuth(args.token)
        if auth.verify_connection():
            print_success(f"GitHub: @{auth.user.login}")
        else:
            print_error("Invalid GitHub token")
            return 1
    elif args.github_security or args.sarif_upload:
        auth = GitHubAuth()
        token = auth.get_token()
        if token:
            auth = GitHubAuth(token)
            if auth.verify_connection():
                print_success(f"GitHub: @{auth.user.login}")

    vulns = []

    if args.all_scanners:
        vulns = agent.run_all_scanners()
    elif args.bandit:
        vulns = agent.run_bandit_scan()
    elif args.pip_audit:
        vulns = agent.run_pip_audit_scan()
    elif args.semgrep:
        vulns = agent.run_semgrep_scan()
    elif args.trivy:
        vulns = agent.run_trivy_scan()
    elif args.github_security:
        gh_token = auth.token if auth else None
        vulns = agent.run_github_security_scan(
            owner=args.github_owner, repo=args.github_repo, token=gh_token, include_secrets=True
        )
    elif args.sarif_upload:
        gh_token = auth.token if auth else None
        success = agent.run_sarif_upload(
            sarif_file=args.sarif_upload,
            owner=args.github_owner,
            repo=args.github_repo,
            token=gh_token,
        )
        if success:
            print_success("SARIF upload complete!")
        return 0 if success else 1
    else:
        vulns = agent.run_all_scanners()

    if vulns:
        deduplicated = agent.scanner.deduplicate(vulns)
        if len(deduplicated) < len(vulns):
            count = len(vulns) - len(deduplicated)
            print_info(f"Deduplicated {count} duplicate vulnerabilities")
            vulns = deduplicated

    if not vulns:
        print_info("No vulnerabilities found")
        return 0

    _show_scan_summary(vulns)

    if args.log_level:
        init_logging(console_level=args.log_level)
        logger = get_logger()
        vuln_ids_list = [getattr(v, "id", "") for v in vulns]
        logger.log_scan_complete("all", len(vulns), vuln_ids_list)

    if args.report or args.report_only:
        repo_name = Path(args.target).name
        print_info(f"Generating report for {len(vulns)} vulnerabilities...")
        report_dir = args.report_dir if args.report_dir else args.target
        report = VulnerabilityReport(report_dir)
        report_files = report.generate(vulns, repo_name=repo_name, target_path=args.target)
        print_success(f"Report generated: {report_files['text']}")

    if args.report_only:
        print_info("Report only mode - skipping remediation")
        return 0

    if args.pause:
        print_warning(f"Found {len(vulns)} vulnerabilities - review above report")
        get_input("Press Enter to continue remediation...")

    if not args.no_git:
        create_ok = agent.create_branch_and_commit(args.branch, "chore: start remediation")
        if not create_ok:
            print_warning("Git branch creation skipped (not a git repo or already on branch)")

    dep_vulns = [v for v in vulns if getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency")]
    code_vulns = [v for v in vulns if getattr(v, "vuln_type", "") not in ("dependency", "outdated_dependency", "hardcoded_secret")]
    secret_vulns = [v for v in vulns if getattr(v, "vuln_type", "") == "hardcoded_secret"]

    results = agent.remediate(dep_vulns)
    success_count = len(results.get("dependencies", []))
    files_mod = results.get("files_modified", 0)

    verification = None
    if dep_vulns:
        print_info("Verifying fixes...")
        verification = agent.verify_remediation(dep_vulns)

    if not args.no_git and success_count > 0:
        agent.git_manager.commit_changes("fix: security dependency updates")
        print_info(f"Files changed: {files_mod}")

        if args.auto_pr:
            if args.pause:
                confirm = get_input("Create PR? [y/n]: ")
                if confirm.lower() not in ("y", "yes"):
                    print_info("PR creation cancelled")
                    return 0
            verified_count = verification.fixed_count if verification else success_count
            pr_title = f"Security: Fix {verified_count} dependency vulnerabilities"
            pr_body = (
                f"## Summary\n"
                f"- Scanned with Trivy, Semgrep, Bandit, pip-audit, Gitleaks\n"
                f"- Fixed {verified_count} dependency vulnerabilities\n"
            )
            if verification:
                pr_body += f"- Verification: {verification.message}\n"
            print_info("Pushing branch and creating pull request...")
            if agent.push_and_create_pr(pr_title, pr_body):
                print_success("PR created successfully!")
            else:
                print_error("Failed to create PR")
                print_info("Ensure GITHUB_TOKEN or --token has 'repo' scope")
                print_info("Or push manually: git push origin HEAD")

    _show_remediation_summary(
        results,
        total_vulns=len(vulns),
        code_count=len(code_vulns),
        secret_count=len(secret_vulns),
        verification=verification,
    )

    if len(secret_vulns) > 0:
        print_warning("IMPORTANT: Rotate exposed secrets immediately!")

    return 0 if success_count > 0 or not dep_vulns else 1


def build_argument_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser with input validation."""
    parser = argparse.ArgumentParser(
        description="Sylas - Autonomous Security Remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m agent.main --interactive\n"
            "  python -m agent.main /path/to/repo --all-scanners --auto-pr\n"
            "  python -m agent.main /path --bandit --report\n"
        ),
    )

    parser.add_argument("target", nargs="?", help="Target repository path")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--trivy", action="store_true", help="Force use Trivy scanner")
    parser.add_argument("--bandit", action="store_true", help="Run Bandit scanner")
    parser.add_argument("--pip-audit", action="store_true", help="Run pip-audit scanner")
    parser.add_argument("--all-scanners", action="store_true", help="Run all scanners")
    parser.add_argument("--semgrep", action="store_true", help="Run Semgrep scanner")
    parser.add_argument("--branch", default="remediation-fix", help="Branch name")
    parser.add_argument("--test-cmd", default="pytest", help="Test command (default: pytest)")
    parser.add_argument("--auto-pr", action="store_true", help="Auto-create PR after remediation")
    parser.add_argument("--no-git", "--skip-git", action="store_true", help="Skip git operations")
    parser.add_argument("--github-security", action="store_true", help="Fetch GitHub Advanced Security alerts")
    parser.add_argument("--github-owner", help="GitHub owner/organization")
    parser.add_argument("--github-repo", help="GitHub repository name")
    parser.add_argument("--sarif-upload", help="Upload SARIF results file to GitHub")
    parser.add_argument("--token", help="GitHub personal access token")
    parser.add_argument("--report", action="store_true", help="Generate vulnerability report")
    parser.add_argument("--report-dir", default=None, help="Report output directory (default: target project root)")
    parser.add_argument("--report-only", action="store_true", help="Only generate report, skip remediation")
    parser.add_argument("--pause", "-p", action="store_true", help="Pause for user review before remediation")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Console log level")

    return parser


if __name__ == "__main__":
    sys.exit(main())
