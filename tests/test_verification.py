"""Tests for verification scope and file checking."""

import pytest
from pathlib import Path
from agent.remediator import RemediationEngine


class TestGetBrokenFiles:
    """Test _get_broken_files() method."""
    
    def setup_method(self):
        self.engine = RemediationEngine("/home/pc/Desktop/Security-Remediation-Agent-master")
    
    def test_exclude_git_and_pycache(self):
        """Test that .git and __pycache__ are excluded."""
        broken = self.engine._get_broken_files()
        # Check no .git or __pycache__ in results
        for f in broken:
            assert ".git" not in f
            assert "__pycache__" not in f
    
    def test_check_specific_files(self):
        """Test checking specific files."""
        # Create a temp file with syntax error
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("this is not valid python code {")
            temp_path = f.name
        
        try:
            broken = self.engine._get_broken_files(files_to_check=[temp_path])
            assert len(broken) > 0
            assert temp_path in broken
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_exclude_bad_and_good_dirs(self):
        """Test that /bad/ and /good/ directories are excluded by default."""
        # This test assumes the vulpy-master test project structure
        # The _get_broken_files() should NOT check files in /bad/ or /good/
        broken = self.engine._get_broken_files()
        
        for f in broken:
            assert "/bad/" not in f
            assert "/good/" not in f


class TestVerifyRemediationComplete:
    """Test verify_remediation_complete() method."""
    
    def setup_method(self):
        self.engine = RemediationEngine("/tmp/test_verification")
        # Ensure the target exists
        self.engine.target_path.mkdir(parents=True, exist_ok=True)
    
    def test_with_empty_vulnerabilities(self):
        """Test verification with no vulnerabilities."""
        result = self.engine.verify_remediation_complete([])
        assert result["success"] == True
        assert result["still_vulnerable"] == []
    
    def test_syntax_valid(self):
        """Test syntax validation."""
        # Create a valid Python file
        test_file = self.engine.target_path / "test_valid.py"
        with open(test_file, 'w') as f:
            f.write("x = 1\nprint(x)\n")
        
        try:
            result = self.engine._verify_syntax_valid()
            assert result == True
            broken = self.engine._get_broken_files()
            assert str(test_file) not in broken
        finally:
            test_file.unlink(missing_ok=True)
    
    def test_syntax_invalid(self):
        """Test syntax validation with invalid code."""
        test_file = self.engine.target_path / "test_invalid.py"
        with open(test_file, 'w') as f:
            f.write("this is not valid python {")
        
        try:
            result = self.engine._verify_syntax_valid()
            assert result == False
            broken = self.engine._get_broken_files()
            assert str(test_file) in broken
        finally:
            test_file.unlink(missing_ok=True)


class TestRunAllScannersForVerification:
    """Test _run_all_scanners_for_verification() method."""
    
    def setup_method(self):
        self.engine = RemediationEngine("/tmp/test_scan")
        self.engine.target_path.mkdir(parents=True, exist_ok=True)
    
    def test_returns_list(self):
        """Test that it returns a list."""
        result = self.engine._run_all_scanners_for_verification()
        assert isinstance(result, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
