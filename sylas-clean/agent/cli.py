"""Interactive CLI module for Sylas."""

import os
import sys
from pathlib import Path
from typing import Optional

from agent.safety import safe_delete, is_path_safe_to_modify, PathSafetyError
from agent.github_auth import (
    GitHubAuth,
    RepoInfo,
    check_gh_installed,
    check_gh_authenticated,
)
from agent.orchestrator import SecurityRemediationAgent
from agent.constants import __version__

# Rich for enhanced output (optional)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Color handling (always define C for backwards compatibility)
try:
    from colorama import init as colorama_init, Fore, Style

    colorama_init(autoreset=True, strip=not sys.stdout.isatty())
    C = type(
        "Colors",
        (),
        {
            "RED": Fore.RED,
            "GREEN": Fore.GREEN,
            "YELLOW": Fore.YELLOW,
            "CYAN": Fore.CYAN,
            "MAGENTA": Fore.MAGENTA,
            "WHITE": Fore.WHITE,
            "RESET": Style.RESET_ALL,
            "BRIGHT": Style.BRIGHT,
            "DIM": Style.DIM,
        },
    )()
except ImportError:
    class C:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = BRIGHT = DIM = ""


if RICH_AVAILABLE:
    console = Console()

BANNER = None  # built lazily


def _build_banner(version: str) -> str:
    inner = f"Sylas v{version}"
    width = max(48, len(inner) + 4)
    top = "+" + "=" * width + "+"
    middle = "|  " + inner.center(width - 2) + "  |"
    bottom = "+" + "=" * width + "+"
    return f"\n{top}\n{middle}\n{bottom}\n"


def get_banner() -> str:
    global BANNER
    if BANNER is None:
        BANNER = _build_banner(__version__)
    return BANNER


def print_banner():
    """Print startup banner."""
    print(get_banner())


def print_info(msg: str):
    """Print info message."""
    if RICH_AVAILABLE:
        console.print(f"[cyan][*][/cyan] {msg}")
    else:
        print(f"{C.CYAN}[*] {msg}{C.RESET}")


def print_success(msg: str):
    """Print success message."""
    if RICH_AVAILABLE:
        console.print(f"[green][+][/green] {msg}")
    else:
        print(f"{C.GREEN}[+] {msg}{C.RESET}")


def print_error(msg: str):
    """Print error message."""
    if RICH_AVAILABLE:
        console.print(f"[red][!][/red] {msg}")
    else:
        print(f"{C.RED}[!] {msg}{C.RESET}")


def print_warning(msg: str):
    """Print warning message."""
    if RICH_AVAILABLE:
        console.print(f"[yellow][-][/yellow] {msg}")
    else:
        print(f"{C.YELLOW}[-] {msg}{C.RESET}")


def print_divider(char: str = "=", width: int = 50):
    """Print divider line."""
    print(f"{C.CYAN}{char * width}{C.RESET}")


def clear_screen():
    """Clear screen (cross-platform)."""
    os.system("cls" if os.name == "nt" else "clear")


def get_input(prompt: str) -> str:
    """Get user input. KeyboardInterrupt re-raised to allow clean exit."""
    print(f"{C.YELLOW}{prompt}{C.RESET} ", end="", flush=True)
    try:
        return input().strip()
    except EOFError:
        return ""
    except KeyboardInterrupt:
        print()
        raise


def get_choice(
    options: list[str], prompt: str = "Enter option", display_options: bool = True
) -> str:
    """Get choice from numbered options."""
    if display_options:
        _display_menu(options)

    while True:
        try:
            choice = get_input(f"\n{prompt}: ")
        except KeyboardInterrupt:
            print()
            return "q"
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return choice
        elif choice.lower() in ("q", "quit", "exit"):
            return "q"

        print_warning("Invalid choice. Try again.")


def _display_menu(options: list[str], title: str = None):
    """Display menu options consistently."""
    if RICH_AVAILABLE:
        table = Table(title=title, show_header=False, box=None)
        table.add_column(style="cyan")
        table.add_column()
        for i, opt in enumerate(options, 1):
            table.add_row(f"[{i}]", opt)
        console.print(table)
    else:
        if title:
            print(f"\n{title}")
        for i, opt in enumerate(options, 1):
            print(f"  {C.CYAN}[{i}]{C.RESET} {opt}")


# === Helper handlers for interactive_scan_menu ===


def _cleanup_scanner_files(target_dir: str) -> None:
    """Clean up temporary scanner result files from the target project directory."""
    cleanup_files = [
        "trivy_results.json",
        "semgrep_results.json",
        "bandit_results.json",
        "pip_audit_results.json",
        "gitleaks_results.json",
    ]
    target_path = Path(target_dir).resolve()
    for filename in cleanup_files:
        file_path = target_path / filename
        if file_path.exists():
            try:
                is_path_safe_to_modify(str(file_path))
                file_path.unlink()
            except (PathSafetyError, OSError):
                pass


def _handle_scan_only(agent: SecurityRemediationAgent) -> bool:
    """Handle 'Scan only' option."""
    print_info("Running full scan (5 scanners)...")
    vulns = agent.run_all_scanners()
    _show_scan_summary(vulns)
    return True


def _handle_fix_deps(agent: SecurityRemediationAgent) -> bool:
    """Handle 'Scan + Fix Dependencies' option with post-fix verification."""
    print_info("Running scan + dependency fix...")
    vulns = agent.run_all_scanners()

    if not vulns:
        print_info("No vulnerabilities found")
        _cleanup_scanner_files(str(agent.target_path))
        return True

    dep_vulns = [v for v in vulns if getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency")]
    code_vulns = [v for v in vulns if getattr(v, "vuln_type", "") not in ("dependency", "outdated_dependency", "hardcoded_secret")]
    secret_vulns = [v for v in vulns if getattr(v, "vuln_type", "") == "hardcoded_secret"]

    verification = None
    if dep_vulns:
        results = agent.remediate(dep_vulns)
        print_info("Verifying fixes...")
        verification = agent.verify_remediation(dep_vulns)
    else:
        results = {"dependencies": [], "code_flaws": [], "failed": [], "diffs": [], "files_modified": 0}

    _show_remediation_summary(
        results,
        total_vulns=len(vulns),
        code_count=len(code_vulns),
        secret_count=len(secret_vulns),
        verification=verification,
    )
    _cleanup_scanner_files(str(agent.target_path))
    return True


def _ensure_github_token(auth: GitHubAuth) -> tuple[bool, str]:
    """Check token from all sources (including interactive prompt).

    Priority:
    1. --token arg (cached in auth.token)
    2. GITHUB_TOKEN / GH_TOKEN env var
    3. gh auth token CLI
    4. Interactive masked prompt — token never persisted to disk or env

    Token stored only in memory for this session. Never persisted.

    Returns:
        (has_token, status_message)
    """
    token = auth.get_token()
    if token:
        return True, "token available in memory"
    return False, "no token provided"


def _handle_fix_deps_pr(agent: SecurityRemediationAgent, auth: GitHubAuth) -> bool:
    """Handle 'Scan + Fix Dependencies + Create PR' option with verification."""
    print_info("GitHub token required for PR creation")
    auth.token = None
    token = auth.get_token(force_prompt=True)
    if token:
        auth.token = token
        has_token = True
        agent = SecurityRemediationAgent(str(agent.target_path), token=token)
        print_info("GitHub token available — PR will be created after fixes")
    else:
        print_warning("No token provided. Skipping PR creation.")
        return True
    pr_status = None

    print_info("Running scan + dependency fix...")
    vulns = agent.run_all_scanners()

    if not vulns:
        print_info("No vulnerabilities found")
        _cleanup_scanner_files(str(agent.target_path))
        return True

    dep_vulns = [v for v in vulns if getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency")]
    code_vulns = [v for v in vulns if getattr(v, "vuln_type", "") not in ("dependency", "outdated_dependency", "hardcoded_secret")]
    secret_vulns = [v for v in vulns if getattr(v, "vuln_type", "") == "hardcoded_secret"]

    verification = None

    if not dep_vulns:
        results = {"dependencies": [], "code_flaws": [], "failed": [], "diffs": [], "files_modified": 0}
        _show_remediation_summary(
            results,
            total_vulns=len(vulns),
            code_count=len(code_vulns),
            secret_count=len(secret_vulns),
            pr_status=pr_status,
        )
        _cleanup_scanner_files(str(agent.target_path))
        return True

    agent.create_branch_and_commit("remediation-fix", "chore: start remediation")

    results = agent.remediate(dep_vulns)
    fixed = len(results.get("dependencies", []))

    print_info("Verifying fixes...")
    verification = agent.verify_remediation(dep_vulns)

    if has_token and fixed > 0 and verification and verification.fixed_count > 0:
        agent.git_manager.commit_changes("fix: security dependency updates")
        pr_title = f"Security: Fix {verification.fixed_count} dependency vulnerabilities"
        pr_body = (
            f"## Summary\n"
            f"- Scanned with Trivy, Semgrep, Bandit, pip-audit, Gitleaks\n"
            f"- Fixed {verification.fixed_count} dependency vulnerabilities\n"
            f"- Verification: {verification.message}\n"
        )

        print_info("Pushing branch and creating pull request...")
        if agent.push_and_create_pr(pr_title, pr_body):
            print_success("PR created successfully!")
            pr_status = "created"
        else:
            print_error("Failed to create PR - your token may be invalid or lack 'repo' scope")
            print_info("  - Verify token has 'repo' scope: https://github.com/settings/tokens")
            print_info("  - Or push manually: git push origin HEAD")
            print_info("  - Then create PR at: https://github.com/OWNER/REPO/pulls")
            pr_status = "failed"
    elif has_token and fixed > 0 and verification and verification.fixed_count == 0:
        print_warning("Verification shows 0 fixes applied — skipping PR creation")
        pr_status = "skipped"
    elif has_token:
        print_warning("No dependencies were fixed — skipping PR")
        if verification:
            print_info(f"Verification: {verification.message}")
        pr_status = "skipped"

    _show_remediation_summary(
        results,
        total_vulns=len(vulns),
        code_count=len(code_vulns),
        secret_count=len(secret_vulns),
        verification=verification,
        pr_status=pr_status,
    )
    _cleanup_scanner_files(str(agent.target_path))
    return True


def _show_scan_summary(vulns: list):
    """Show a polished scan summary with severity breakdown."""
    if not vulns:
        print_info("No vulnerabilities found")
        return

    dep_count = sum(1 for v in vulns if getattr(v, "vuln_type", "") in ("dependency", "outdated_dependency"))
    code_count = sum(1 for v in vulns if getattr(v, "vuln_type", "") not in ("dependency", "outdated_dependency", "hardcoded_secret"))
    secret_count = sum(1 for v in vulns if getattr(v, "vuln_type", "") == "hardcoded_secret")

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    sev_colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.WHITE, "UNKNOWN": C.DIM}
    for v in vulns:
        sev = (getattr(v, "severity", "") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print_divider(char="=", width=56)
    print(f"  {C.CYAN}{C.BRIGHT}SCAN SUMMARY{C.RESET}")
    print_divider(char="=", width=56)
    print(f"  Total Vulnerabilities : {len(vulns)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(sev, 0) > 0:
            print(f"    {sev_colors.get(sev, C.WHITE)}{sev:<12}{C.RESET} {sev_counts[sev]}")
    print()
    print(f"  Dependencies (auto-fixable) : {dep_count}")
    print(f"  Code Issues (manual review) : {code_count}")
    if secret_count > 0:
        print(f"  {C.RED}Secrets (review immediately)  : {secret_count}{C.RESET}")
    else:
        print(f"  Secrets                       : {secret_count}")
    print_divider(char="=", width=56)


def _show_remediation_summary(
    results: dict,
    total_vulns: int = 0,
    code_count: int = 0,
    secret_count: int = 0,
    verification=None,
    pr_status: Optional[str] = None,
):
    """Show a polished remediation summary with next steps and verification results.

    Args:
        pr_status: "created", "skipped", "failed", or None if PR not applicable.
    """
    deps_fixed = len(results.get("dependencies", []))
    failed = len(results.get("failed", []))
    files_mod = results.get("files_modified", 0)

    print()
    print_divider(char="=", width=56)
    print(f"  {C.GREEN}{C.BRIGHT}REMEDIATION COMPLETE{C.RESET}")
    print_divider(char="=", width=56)
    print(f"  Dependencies Updated : {deps_fixed}")

    if verification is not None:
        remaining = verification.remaining_count
        new_count = verification.new_issues_count
        vcolor = C.GREEN if verification.success else C.RED
        label = "SUCCESS" if verification.success else "REMAINING"
        print(f"  Still Vulnerable     : {remaining}")
        print(f"  New Issues After Fix : {new_count}")
        print(f"  {vcolor}Verification Status  : {label}{C.RESET}")

    print(f"  Code Issues Found    : {code_count}   (manual review recommended)")

    if secret_count > 0:
        print(f"  {C.RED}Secrets Found        : {secret_count}   (rotate immediately!){C.RESET}")
    else:
        print(f"  Secrets Found        : {secret_count}")

    print(f"  Files Modified       : {files_mod}")

    if pr_status == "created":
        print(f"  {C.GREEN}PR Status            : Created successfully{C.RESET}")
    elif pr_status == "skipped":
        print(f"  PR Status            : Skipped (no token provided)")
    elif pr_status == "failed":
        print(f"  {C.RED}PR Status            : Failed (token or scope issue){C.RESET}")

    if failed > 0:
        print(f"  {C.RED}Failed Fixes         : {failed}{C.RESET}")
    else:
        print(f"  Failed Fixes         : {failed}")

    print()
    print(f"  {C.CYAN}{C.BRIGHT}Next Steps:{C.RESET}")
    if verification is not None and verification.remaining_count > 0:
        print(f"  {C.YELLOW}*{C.RESET} {verification.remaining_count} vulnerabilities still need attention")
    if code_count > 0:
        print(f"  {C.CYAN}*{C.RESET} Review the {code_count} code vulnerabilities manually")
    if secret_count > 0:
        print(f"  {C.RED}*{C.RESET} Rotate exposed secrets immediately")
    print(f"  {C.CYAN}*{C.RESET} Run tests to verify changes")
    if deps_fixed > 0 and pr_status != "created":
        print(f"  {C.CYAN}*{C.RESET} Create a Pull Request with the dependency fixes")
    print_divider(char="=", width=56)
    print()


def _handle_delete_clone(path: str) -> bool:
    """Handle 'Delete clone and return to menu' option."""
    path_obj = Path(path)
    if path_obj.name != "." and path_obj.exists() and (path_obj / ".git").exists():
        choice = get_choice(["Yes, delete", "No, keep"], "Delete cloned repository?")
        if choice == "1":
            try:
                safe_delete(path, allow_in_project=True)
                print_success(f"Deleted: {path}")
                return False
            except PathSafetyError as e:
                print_error(f"Cannot delete: {e}")
    return True


def _handle_exit() -> bool:
    """Handle 'Exit' option."""
    return False


# === Interactive Scan Menu ===


def run_interactive_scan_menu(path: str, repo_info: RepoInfo, auth: GitHubAuth) -> bool:
    """Interactive scan and remediate menu."""
    show_repo_summary(repo_info, path, auth.user)

    agent = SecurityRemediationAgent(path)

    while True:
        print()
        menu_options = [
            ("Scan only (no changes)", _handle_scan_only, {"agent": agent}),
            ("Scan + Fix Dependencies", _handle_fix_deps, {"agent": agent}),
            ("Scan + Fix Dependencies + Create PR", _handle_fix_deps_pr, {"agent": agent, "auth": auth}),
            ("Delete clone and return to menu", _handle_delete_clone, {"path": path}),
            ("Exit", _handle_exit, {}),
        ]

        _display_menu([opt[0] for opt in menu_options], "SCAN MENU")

        try:
            raw = get_input("\nSelect option")
        except KeyboardInterrupt:
            print()
            return False

        if raw.lower() in ("q", "quit", "exit"):
            return False

        if not raw.isdigit():
            print_warning("Invalid choice. Try again.")
            continue

        idx = int(raw) - 1
        if not (0 <= idx < len(menu_options)):
            print_warning("Invalid choice. Try again.")
            continue

        _, handler, kwargs = menu_options[idx]
        try:
            should_continue = handler(**kwargs)
            if not should_continue:
                return False
        except KeyboardInterrupt:
            print()
            return False


# === Main Interactive Mode ===


def show_repo_summary(repo_info: RepoInfo, path: str, user: Optional[object] = None):
    """Show repository summary."""
    name = Path(path).name

    if RICH_AVAILABLE:
        lines = []
        lines.append(f"[bold]Name:[/bold] {name}")
        if repo_info:
            lines.append(f"[bold]Owner:[/bold] {repo_info.owner}")
            lines.append(f"[bold]Full:[/bold] {repo_info.full_name}")
            lines.append(f"[bold]Private:[/bold] {'Yes' if repo_info.is_private else 'No'}")
        if user and hasattr(user, "login"):
            lines.append(f"[bold]GitHub:[/bold] @{user.login}")
        lines.append(f"[bold]Path:[/bold] {path}")
        console.print(
            Panel("\n".join(lines), title="REPOSITORY SUMMARY", border_style="cyan")
        )
    else:
        print()
        print_divider()
        print(f" {C.CYAN}REPOSITORY SUMMARY{C.RESET}")
        print_divider()
        print(f"  {C.CYAN}Name:{C.RESET}     {name}")
        if repo_info:
            print(f"  {C.CYAN}Owner:{C.RESET}     {repo_info.owner}")
            print(f"  {C.CYAN}Full:{C.RESET}      {repo_info.full_name}")
            private = "Yes" if repo_info.is_private else "No"
            print(f"  {C.CYAN}Private:{C.RESET}  {private}")
        if user and hasattr(user, "login"):
            print(f"  {C.CYAN}GitHub:{C.RESET}    @{user.login}")
        print(f"  {C.CYAN}Path:{C.RESET}      {path}")
        print_divider()


def clone_repository(auth: GitHubAuth) -> tuple[bool, str, Optional[RepoInfo]]:
    """Interactive clone workflow."""
    print()
    print_info("Clone a repository")
    print_divider()

    url = get_input("Repository URL (or 'cancel'): ")

    if not url or url.lower() in ("cancel", "c", "back"):
        return False, "", None

    try:
        repo_info = auth.get_repo_info_from_url(url)
    except ValueError as e:
        print_error(str(e))
        return False, str(e), None

    target_dir = repo_info.name

    if Path(target_dir).exists():
        print_warning(f"Directory '{target_dir}' already exists")
        choice = get_choice(
            ["Use existing directory", "Choose different name", "Cancel"], "What to do"
        )

        if choice == "3" or choice.lower() == "cancel":
            return False, "Cancelled", None
        elif choice == "2":
            target_dir = get_input("Enter directory name: ")
            if not target_dir:
                return False, "Cancelled", None
            repo_info.name = target_dir

    token = auth.get_token()

    success, message = auth.clone_repo(repo_info.clone_url, target_dir, token)

    if success:
        return True, message, repo_info

    print_error(message)

    if "private" in message.lower() or "not found" in message.lower():
        print_info("This may be a private repository. Trying authentication...")

        new_token = get_input("GitHub Token (for private repo): ")
        if new_token:
            auth.token = new_token.strip()
            success, message = auth.clone_repo(repo_info.clone_url, target_dir, auth.token)

            if success:
                return True, message, repo_info

    return False, message, None


def scan_local_directory() -> tuple[bool, str, Optional[RepoInfo]]:
    """Scan local directory."""
    print()
    print_info("Scan local directory")
    print_divider()

    path = get_input("Directory path (or '.' for current): ")

    if not path or path == ".":
        path = "."

    target_path = Path(path).resolve()

    if not target_path.exists():
        print_error(f"Path does not exist: {path}")
        return False, "", None

    repo_info = None
    if (target_path / ".git").exists():
        auth = GitHubAuth()
        repo_info = auth.get_repo_info_from_path(str(target_path))

    return True, str(target_path), repo_info


# === Handlers for main interactive mode ===


def _handle_clone_repo(auth: GitHubAuth) -> Optional[int]:
    """Handle 'Clone a repository' option."""
    success, msg, repo_info = clone_repository(auth)

    if not success:
        if msg and msg != "Cancelled":
            print_error(msg)
        return None

    path = repo_info.name if repo_info else "."

    if success and auth.verify_connection():
        print_success(msg)
        continue_session = run_interactive_scan_menu(path, repo_info, auth)
        if not continue_session:
            return 0
    elif not auth.verify_connection():
        print_error("GitHub connection failed")
    return None


def _handle_scan_local(auth: GitHubAuth) -> Optional[int]:
    """Handle 'Scan local directory' option."""
    success, path, repo_info = scan_local_directory()

    if not success:
        return None

    # Check for existing token from non-interactive sources only.
    # The interactive prompt will happen later if user selects the PR option.
    if not auth.token:
        existing = auth.get_token(prefer_explicit=True)
        if existing:
            # Token stored only in memory for this session. Never persisted.
            auth.token = existing
            auth.verify_connection()

    continue_session = run_interactive_scan_menu(path, repo_info, auth)
    if not continue_session:
        return 0
    return None


def _handle_open_browser() -> Optional[int]:
    """Handle 'Open in browser' option."""
    print_info("Opening GitHub...")
    return None


def _handle_exit_main() -> int:
    """Handle 'Exit' option."""
    print_success("Goodbye!")
    return 0


def interactive_mode():
    """Main interactive mode (no LLM dependencies)."""
    clear_screen()
    print_banner()

    auth = GitHubAuth()

    print_info("Checking GitHub credentials...")

    if check_gh_authenticated():
        print_success("GitHub CLI authenticated")
    elif check_gh_installed():
        print_warning("GitHub CLI not authenticated")
    else:
        print_warning("GitHub CLI not installed")

    gh_available = check_gh_installed()

    while True:
        print()
        menu_options = [
            ("Clone a repository", _handle_clone_repo, {"auth": auth}),
            ("Scan local directory", _handle_scan_local, {"auth": auth}),
        ]

        if gh_available:
            menu_options.append(("Open in browser", _handle_open_browser, {}))

        menu_options.append(("Exit", _handle_exit_main, {}))

        _display_menu([opt[0] for opt in menu_options], "MAIN MENU")

        try:
            raw = get_input("\nSelect option")
        except KeyboardInterrupt:
            print()
            return 0

        if raw.lower() in ("q", "quit", "exit"):
            return 0

        if not raw.isdigit():
            print_warning("Invalid choice. Try again.")
            continue

        idx = int(raw) - 1
        if not (0 <= idx < len(menu_options)):
            print_warning("Invalid choice. Try again.")
            continue

        _, handler, kwargs = menu_options[idx]
        try:
            exit_code = handler(**kwargs)
            if exit_code is not None:
                return exit_code
        except KeyboardInterrupt:
            print()
            return 0
