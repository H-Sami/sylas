"""Tests for resolve_file_path function from utils.py."""

import pytest
from pathlib import Path
from agent.utils import resolve_file_path


class TestResolveFilePath:
    """Test resolve_file_path() function."""
    
    def setup_method(self):
        self.target_path = Path("/home/pc/Desktop/Security-Remediation-Agent-master")
    
    def test_relative_path(self):
        """Test resolving relative path."""
        result = resolve_file_path(self.target_path, "agent/remediator.py")
        assert result.is_absolute()
        assert "agent/remediator.py" in str(result)
        assert str(result).startswith(str(self.target_path))
    
    def test_absolute_path_within_target(self):
        """Test absolute path within target_path."""
        abs_path = str(self.target_path / "agent" / "remediator.py")
        result = resolve_file_path(self.target_path, abs_path)
        assert result.is_absolute()
        assert str(result).startswith(str(self.target_path))
    
    def test_absolute_path_outside_target(self):
        """Test absolute path outside target_path."""
        result = resolve_file_path(self.target_path, "/tmp/test_file.py")
        # Should fall back to filename only with warning
        assert result.is_absolute()
        assert result.name == "test_file.py"
        assert str(result).startswith(str(self.target_path))
    
    def test_nonexistent_relative(self):
        """Test non-existent relative path."""
        result = resolve_file_path(self.target_path, "nonexistent/file.py")
        # Should return target_path / filename
        assert result.is_absolute()
        assert result.name == "file.py"
        assert str(result).startswith(str(self.target_path))
    
    def test_simple_filename(self):
        """Test simple filename without path."""
        result = resolve_file_path(self.target_path, "remediator.py")
        assert result.is_absolute()
        assert result.name == "remediator.py"
        assert str(result).startswith(str(self.target_path))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
