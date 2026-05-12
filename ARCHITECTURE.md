# Architecture Overview

Sylas v1.0.0 — Technical Design

## System Architecture

```
┌───────────────────────────────────────────────────┐
│                    CLI (main.py)                   │
│  ┌───────────────────────────────────────────┐    │
│  │          Orchestrator (orchestrator.py)    │    │
│  │                                             │    │
│  │  ┌──────────┐  ┌───────────┐               │    │
│  │  │ Scanner  │  │Remediator │   GitManager  │    │
│  │  │          │  │(deps only)│               │    │
│  │  └────┬─────┘  └─────┬─────┘               │    │
│  │       │               │                     │    │
│  │  ┌────▼──────────────▼──────────────────┐  │    │
│  │  │           Verifier (syntax + diff)    │  │    │
│  │  └───────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

## Core Components

### 1. Scanner Module (`scanner.py`, `scanners.py`, `trivy_integration.py`, `semgrep_scanner.py`)
- **Vulnerability**: Dataclass with `scanner` field for tracking origin
- **VulnerabilityScanner**: Deduplication and JSON report parsing
- **BaseScanner**: Common interface with `is_available()` and `scan()` methods
- **BanditScanner**: Python code security linting
- **PipAuditScanner**: Python dependency vulnerability scanning
- **SemgrepScanner**: Advanced pattern matching (p/security-audit config)
- **TrivyScanner**: Filesystem vulnerability scanning
- **GitleaksScanner** (new): Secret detection via `gitleaks detect --no-git`
- **ScannerResult**: Dataclass for scan results
- **SCANNER_REGISTRY**: Dynamic scanner registry
- **run_all_scans()**: Runs all available scanners in parallel using ThreadPoolExecutor (max 5 workers)

### 2. Remediator (`remediator.py`)
- **RemediationEngine**: Handles dependency updates only (no code-level auto-fixing)
  - `remediate_dependency()`: Updates requirements.txt / pyproject.toml
  - `remediate_all()`: Main loop, sorts by severity, delegates to DependencyManager

### 3. Utilities (`utils.py`)
- **create_requests_session()**: Configurable HTTP session with retry logic (for GitHub API)
- **safe_run()**: Subprocess execution with consistent error handling
- **run_tests()**: Test execution with multiple framework detection strategies
- **resolve_file_path()**: Path resolution relative to target
- **parse_requirement_line()**: Parses requirements.txt lines with extras support
- **parse_pyproject_toml()**: Extracts dependencies from pyproject.toml
- **update_pyproject_toml()**: Updates dependency versions in pyproject.toml

### 4. Orchestrator (`orchestrator.py`)
- **SecurityRemediationAgent**: Central coordinator
  - No LLM configuration — purely scanner-based
  - Manages scanner lifecycle
  - Coordinates dependency-only remediation workflow
  - Git operations coordination

### 5. Verification (`verifier.py`)
- **VerificationGate**: Post-remediation validation
  - Syntax checking of modified Python files
  - `get_git_diff_stats()`: Returns diff statistics
  - `get_changed_files()`: Lists modified files

### 6. Git Integration (`git_integration.py`)
- **GitManager**: Git operations with security guardrails
  - Branch creation with naming validation
  - Commit with secret detection
  - Push with protected branch checks
  - PR creation via GitHub API

### 7. GitHub Integration
- **github_security.py**: GitHub Advanced Security API integration
  - Code scanning alerts, secret scanning alerts, SARIF upload
- **github_auth.py**: Authentication and repo info/cloning
  - Token priority: CLI flag > env var > gh CLI > interactive prompt

### 8. CLI Module (`cli.py`)
- **Interactive Mode**: Menu-driven interface with Rich tables/panels (optional)
- **Options**: Clone repo, scan local directory, scan + fix deps, scan + fix deps + PR
- **Colorama Fallback**: For minimal environments without Rich

### 9. Logger (`logger.py`)
- **SecurityAgentLogger**: Dual-handler logging (colored console + JSON file)
- Thread-safe singleton with double-checked locking

### 10. Dependency Manager (`dependency_manager.py`)
- **DependencyManager**: Handles dependency updates
  - `update_dependency()`: Updates requirements.txt / pyproject.toml safely
  - `handle_dependency()`: Multi-strategy lookup (Trivy map, CVE-to-package map, file scan)
  - CVE-to-package mapping for 30+ common packages

### 11. Safety Module (`safety.py`)
- Path safety validation for delete and modify operations
- Prevents catastrophic deletions (system dirs, project root, protected dirs)

## Data Flow

```
1. Scan:  Target → 5 parallel Scanners → Vulnerability Objects (with dedup)
2. Fix:   Dependency vulns → DependencyManager → Updated requirements.txt / pyproject.toml
3. Report: All vulns → Text + JSON reports (severity breakdown + recommendations)
4. Git:   Changes → Branch → Commit → (Optional) PR
```

Code vulnerabilities and secrets are **reported only** — they flow through steps 1, 3, and 4 but are skipped in step 2.

## Scanner Registry

Scanners registered in `scanners.py`:
- **Bandit**: pip install bandit
- **Semgrep**: pip install semgrep
- **pip-audit**: pip install pip-audit
- **Trivy**: Install from [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy)
- **Gitleaks**: Install from [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)

All scanners implement `is_available()` and `scan()`, inheriting from `BaseScanner`.

## Security Model

- **Path Safety**: Safe delete/modify validation
- **Secret Detection**: Commit messages checked for exposed secrets
- **Protected Branches**: Blocks operations on main/master/develop
- **No Hardcoded Secrets**: Tokens in memory only, never written to disk
- **Dependency Verification**: Conflict checking before version updates

## Extension Points

1. **New Scanners**: Create class inheriting `BaseScanner`, implement `is_available()` and `scan()`, register in `SCANNER_REGISTRY`
2. **Report Formats**: Extend `VulnerabilityReport` class
3. **UI Themes**: Customize Rich/colorama output in `cli.py`

## Dependency File Support

- **requirements.txt**: Traditional Python dependencies
- **pyproject.toml**: Modern Python packaging (Poetry, uv, PDM)
  - Reads `[project.dependencies]` and `[project.optional-dependencies]`
  - Updates version specifiers while preserving extras
