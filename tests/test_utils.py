"""Tests for agent/utils.py"""

import sys
import os
import pytest
from pathlib import Path
from agent.utils import parse_requirement_line, create_requests_session, safe_run


class TestParseRequirementLine:
    """Test the parse_requirement_line function."""
    
    def test_simple_package_name(self):
        """Test parsing simple package name."""
        pkg, ver, extras = parse_requirement_line("flask")
        assert pkg == "flask"
        assert ver == ""
        assert extras is None
    
    def test_package_with_version(self):
        """Test parsing package with version specifier."""
        pkg, ver, extras = parse_requirement_line("flask>=2.0.0")
        assert pkg == "flask"
        assert ver == ">=2.0.0"
        assert extras is None
    
    def test_package_with_extras(self):
        """Test parsing package with extras."""
        pkg, ver, extras = parse_requirement_line("flask[dotenv]>=2.0.0")
        assert pkg == "flask"
        assert ver == ">=2.0.0"
        assert extras == "dotenv"
    
    def test_package_with_multiple_extras(self):
        """Test parsing package with multiple extras."""
        pkg, ver, extras = parse_requirement_line("django[argon2,rest]>=3.2")
        assert pkg == "django"
        assert ver == ">=3.2"
        assert extras == "argon2,rest"
    
    def test_empty_line(self):
        """Test parsing empty line."""
        result = parse_requirement_line("")
        assert result == (None, None, None)
    
    def test_comment_line(self):
        """Test parsing comment line."""
        result = parse_requirement_line("# This is a comment")
        assert result == (None, None, None)
    
    def test_line_with_environment_marker(self):
        """Test parsing line with environment marker."""
        pkg, ver, extras = parse_requirement_line(
            "package>=1.0; python_version > '3.6'"
        )
        assert pkg == "package"
        assert ver == ">=1.0"
        assert extras is None
    
    def test_complex_version_specifiers(self):
        """Test various version specifiers."""
        # Test basic operators
        pkg, ver, extras = parse_requirement_line("requests==2.28.0")
        assert pkg == "requests"
        assert ver == "==2.28.0"
        
        # Test multiple version specifiers
        pkg, ver, extras = parse_requirement_line("urllib3>=1.25.8,<2.0.0")
        assert pkg == "urllib3"
        assert ver == ">=1.25.8,<2.0.0"
        
        # Test ~= operator
        pkg, ver, extras = parse_requirement_line("package~=1.0")
        assert pkg == "package"
        assert ver == "~=1.0"
        
        # Test != operator
        pkg, ver, extras = parse_requirement_line("package!=1.5")
        assert pkg == "package"
        assert ver == "!=1.5"


class TestSafeRun:
    """Test the safe_run function."""
    
    def test_simple_command(self):
        """Test running a simple command."""
        result = safe_run([sys.executable, "--version"], capture_output=True, text=True)
        assert result.returncode == 0
    
    def test_command_with_cwd(self):
        """Test running command with working directory."""
        result = safe_run(
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            capture_output=True,
            text=True,
            cwd="/tmp"
        )
        assert result.returncode == 0
        assert "/tmp" in result.stdout
    
    def test_command_timeout(self):
        """Test command timeout."""
        import subprocess
        with pytest.raises(subprocess.TimeoutExpired):
            safe_run(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=1
            )
    
    def test_command_not_found(self):
        """Test command not found."""
        import subprocess
        with pytest.raises(FileNotFoundError):
            safe_run(["nonexistent_command_12345"])


class TestCreateRequestsSession:
    """Test the create_requests_session function."""
    
    def test_session_creation(self):
        """Test creating a session."""
        session = create_requests_session()
        assert session is not None
        assert hasattr(session, 'get')
        assert hasattr(session, 'post')
    
    def test_session_with_custom_retries(self):
        """Test session with custom retry count."""
        session = create_requests_session(retries=5, backoff_factor=0.5)
        assert session is not None
        # Check that retry logic is configured
        # The Retry object has a total attribute
        retry_obj = session.adapters['http://'].max_retries
        assert retry_obj.total == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
