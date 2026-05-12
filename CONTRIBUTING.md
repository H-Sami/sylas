# Contributing to Sylas

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

- Use the [GitHub Issues](https://github.com/H-Sami/sylas/issues) page
- Include steps to reproduce
- Specify your environment (OS, Python version, etc.)

### Suggesting Features

- Open an issue with the "enhancement" label
- Describe the use case and expected behavior

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/H-Sami/sylas.git
cd sylas

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with all optional dependencies
pip install -e ".[scanners,ui,dev]"

# Or install individually:
# pip install -e ".[scanners]"  # Scanner support
# pip install -e ".[ui]"        # Rich terminal UI
# pip install -e ".[dev]"        # Dev tools (pytest, black, flake8)
```

### Code Quality Tools

```bash
# Run linter
python3 -m flake8 agent/ --max-line-length=120

# Format code
black agent/

# Type checking (optional)
mypy agent/

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest --cov=agent tests/
```

## Code Style

- Follow PEP 8
- Use type hints where possible
- Run `black .` before committing
- Run `flake8` to check for issues

## Adding a New Scanner

1. Create a new scanner class in `agent/` (e.g., `my_scanner.py`) or add to `agent/scanners.py`
2. Inherit from `BaseScanner` and implement the standard interface:
   ```python
   class MyScanner(BaseScanner):
       def is_available(self) -> bool:
           # Check if scanner is installed
           return True

       def scan(self, output_file: str = "results.json") -> ScannerResult:
           # Return ScannerResult with vulnerabilities
           pass
   ```
3. Register in `agent/scanners.py` `SCANNER_REGISTRY`
4. Add to `run_all_scans()` in `agent/scanners.py`
5. Optionally add a `run_my_scan()` method to `agent/orchestrator.py`

## Testing

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=agent
```

## Documentation

- Update `README.md` for user-facing changes
- Update `ARCHITECTURE.md` for design changes
- Add docstrings to all public methods
- Update `CHANGELOG.md` with your changes

## Commit Messages

Follow conventional commits:

```
feat: add new scanner integration
fix: resolve deduplication issue
docs: update README with examples
refactor: simplify remediator code
test: add tests for verifier module
```

## Questions?

Feel free to open an issue or reach out via GitHub Discussions.

## Code of Conduct

Be respectful, inclusive, and considerate of others. We aim to foster a welcoming community for all contributors.
