# Sylas

### Autonomous Security Remediation (PROOF OF CONCEPT)

**Sylas** is a powerful, scanner-only security agent that automatically detects and remediates vulnerabilities in your codebase.

## Features

- **Multi-Scanner Support** — Runs Trivy, Semgrep, Bandit, pip-audit, and Gitleaks in parallel
- **Automatic Dependency Fixing** — Updates vulnerable packages with smart version resolution
- **Verification System** — Confirms fixes were successfully applied
- **GitHub PR Creation** — Automatically creates pull requests with fixes
- **Professional Reporting** — Generates detailed vulnerability reports

## Installation

```bash
pip install sylas
```

Or clone the repository:

```bash
git clone https://github.com/H-Sami/sylas.git
cd sylas
pip install -r requirements.txt
```

## Usage

### Interactive Mode (Recommended)

```bash
python -m sylas --interactive
```

### Command Line

```bash
# Scan and auto-fix dependencies
python -m sylas /path/to/project --all-scanners --auto-pr
```

### GitHub Actions

Add this to `.github/workflows/sylas.yml`:

```yaml
name: Sylas Security Scan
on:
  schedule:
    - cron: '0 0 * * 0'
  workflow_dispatch:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Sylas
        run: python -m sylas . --trivy --auto-pr
```

## How It Works

1. Scans your project using multiple security tools
2. Identifies vulnerable dependencies
3. Automatically updates them to secure versions
4. Verifies the fixes
5. Creates a pull request with all changes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
