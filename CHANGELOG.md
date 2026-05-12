# Changelog

All notable changes to Sylas will be documented in this file.

## [1.0.0] - 2026-05-13

### Added
- Complete rebrand to Sylas
- First public release
- Scanner-only architecture (no LLM)
- Automatic dependency remediation + PR creation

### Changed
- Full project rebrand: Security Remediation Agent → Sylas
- Version bumped to 1.0.0
- All banners, titles, and docstrings updated

## [0.9.0] - 2026-05-12 — Scanner Edition

### Added
- **GitleaksScanner**: New secret detection scanner using `gitleaks detect --no-git`
- Scanner summary in CLI: shows dependency, code, and secrets counts separately
- Recommendations section in vulnerability reports
- Secrets count tracking in JSON and text reports

### Removed
- **Entire LLM subsystem**: `agent/llm_handler.py` (356 lines) deleted
- **LLM prompt templates**: `configs/llm_prompts.yaml` (190 lines) deleted
- **SnykScanner**: Removed (was unreliable, rarely installed)
- **SafetyScanner**: Removed (redundant with Trivy + pip-audit)
- **Pattern-based scanner**: `remediator.scan_code_for_vulnerabilities()` removed
- **LLM configuration**: `--llm-endpoint` flag, `LLM_ENDPOINT` env var, LLM config section in YAML
- **All LLM Pydantic models**: `RemediationFix`, `DependencyFix`, `LLMResponse` removed from `scanner.py`
- **All LLM log methods**: `log_llm_request()`, `log_llm_response()`, etc. removed from `logger.py`

### Changed
- **remediator.py**: Stripped from 664 to ~70 lines — only handles dependency updates via DependencyManager
- **verifier.py**: Simplified to syntax checking + git diff stats (no more re-scan verification)
- **orchestrator.py**: No LLM endpoint management, simplified remediate() for deps only
- **scanners.py**: GitleaksScanner added, `run_all_scans()` runs 5 scanners in parallel (up from 4)
- **constants.py**: Version bumped to 0.9.0, all LLM/Snyk/Safety constants removed
- **cli.py**: Menu options renamed ("Scan + Fix Dependencies", "Scan + Fix Dependencies + Create PR")
- **main.py**: Cleaner argument parser, no --safety or --llm-endpoint flags
- **report.py**: Enhanced with secret counts, dependency/code breakdown, recommendations
- **utils.py**: Removed `llm_request()` function, kept `create_requests_session()` for GitHub API
- **agent_config.yaml**: LLM config section removed
- **security_guardrails.json**: Updated allowed scanners list, removed LLM network rules

### Fixed
- No more LLM timeouts, empty responses, or markdown-wrapped output
- Much faster execution (no LLM wait times)
- Higher reliability on dependency fixes

## [0.8.1] - 2024-04-27 — Legacy LLM version

### Added
- `scanner` field to `Vulnerability` dataclass for better tracking
- Thread-safe logger singleton with double-checked locking
- Dynamic CLI banner builder (handles version strings correctly)
- `--log-level` CLI argument for console log control
- Shared verification venv in `DependencyManager` (performance improvement)
- Lazy-loaded scanner registry (replaces `None` sentinel)
- `_get_head_sha()` helper for reliable SARIF upload
- `configparser`-based `.git/config` parsing

### Fixed
- **Fix 1**: `scan_code_for_vulnerabilities()` uses correct `vuln_type` (not literal "code_flaw")
- **Fix 2**: `update_dependency()` returns proper tuples `(bool, Optional[str])`
- **Fix 3**: `remediate_all()` skips already-fixed vulns on retry
- **Fix 4**: `run_tests()` uses separate pytest detection strategies (no marker filter bug)
- **Fix 5**: `trivy_integration.py` uses `self.trivy_cmd` instead of hardcoded `"trivy"`
- **Fix 6**: `--log-level` argument added to CLI parser
- **Fix 7**: Removed insecure askpass in `github_auth.py`, uses URL-embedded credentials
- **Fix 8**: LLM validator allows `subprocess.run()` fixes, blocks `shell=True`
- **Fix 9**: SARIF upload tries `main` branch first, queries default branch
- **Fix 10**: Temp Trivy scan files cleaned up with `finally` blocks
- **Fix 11**: `SecurityRemediationAgent` accepts `llm_endpoint` in constructor
- **Fix 12**: Renamed `_llm_refactor` to `refactor` (public API)
- **Fix 13**: `SCANNER_REGISTRY` uses lazy loader instead of `None` sentinel
- **Fix 14**: All scanners populate `scanner` field in `Vulnerability`
- **Fix 15**: Dynamic banner handles version strings of any length
- **Fix 16**: `.git/config` parsed with `configparser` (proper section boundaries)
- **Fix 17**: Logger singleton is thread-safe with double-checked locking
- **Fix 18**: Shared verification venv instead of one per package
- **Fix 19**: `run_all_scans()` uses `ThreadPoolExecutor` for parallel scans
- **Fix 20**: Bandit CWE mapping uses `issue_cwe` field correctly
- **Fix 21**: `_generate_diff_for_vuln()` has explicit `return None`

### Removed
- Insecure askpass mechanism in `github_auth.py`
- `None` sentinel in `SCANNER_REGISTRY`
- Dead code and junk files

### Changed
- `run_all_scans()` now runs scanners in parallel (3x faster)
- Dependency verification uses shared venv (10x faster for multi-package updates)
- `Vulnerability` dataclass now includes `scanner` field
- Report summary uses `scanner` field instead of ID prefix inference

## [0.8.0] - 2024-04-26 — Legacy LLM version

### Added
- Initial release with Trivy, Bandit, pip-audit scanners
- LLM-based code remediation (removed in v0.9.0)
- GitHub Advanced Security integration
- Auto-PR creation after verification
- Interactive mode (`--interactive`)
- Docker support
- Report generation (text + JSON)
