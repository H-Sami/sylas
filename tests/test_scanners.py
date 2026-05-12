"""Tests for agent/scanners.py with BaseScanner class."""

import sys
import pytest
from pathlib import Path
from agent.scanners import (
    BaseScanner, BanditScanner, PipAuditScanner, SafetyScanner,
    ScannerResult, run_all_scans, get_scanner, list_available_scanners
)


class TestBaseScanner:
    """Test the BaseScanner class."""
    
    def test_init(self):
        """Test BaseScanner initialization."""
        scanner = BaseScanner("/tmp")
        assert scanner.target_path == Path("/tmp")
    
    def test_is_available_not_implemented(self):
        """Test that is_available raises NotImplementedError."""
        scanner = BaseScanner("/tmp")
        with pytest.raises(NotImplementedError):
            scanner.is_available()
    
    def test_scan_not_implemented(self):
        """Test that scan raises NotImplementedError."""
        scanner = BaseScanner("/tmp")
        with pytest.raises(NotImplementedError):
            scanner.scan()
    
    def test_run_check_version(self):
        """Test _run_check_version method."""
        scanner = BaseScanner("/tmp")
        # Test with Python executable (should be available)
        result = scanner._run_check_version(
            [sys.executable, "--version"],
            timeout=10
        )
        assert isinstance(result, bool)
    
    def test_parse_json_file_exists(self, tmp_path):
        """Test _parse_json_file with existing file."""
        import json
        test_data = {"test": "data", "numbers": [1, 2, 3]}
        json_file = tmp_path / "test.json"
        with open(json_file, 'w') as f:
            json.dump(test_data, f)
        
        scanner = BaseScanner(str(tmp_path))
        result = scanner._parse_json_file(json_file)
        assert result == test_data
    
    def test_parse_json_file_not_exists(self):
        """Test _parse_json_file with non-existent file."""
        scanner = BaseScanner("/tmp")
        result = scanner._parse_json_file(Path("/nonexistent/file.json"))
        assert result == {}


class TestBanditScanner:
    """Test BanditScanner class."""
    
    def test_init(self):
        """Test BanditScanner initialization."""
        scanner = BanditScanner("/tmp")
        assert scanner.target_path == Path("/tmp")
        assert isinstance(scanner, BaseScanner)
    
    def test_is_available(self):
        """Test availability check."""
        scanner = BanditScanner("/tmp")
        result = scanner.is_available()
        assert isinstance(result, bool)
    
    def test_scan_result_type(self):
        """Test that scan returns ScannerResult."""
        scanner = BanditScanner("/tmp")
        result = scanner.scan()
        assert isinstance(result, ScannerResult)
        assert hasattr(result, 'scanner')
        assert hasattr(result, 'vulnerabilities')
        assert hasattr(result, 'success')


class TestPipAuditScanner:
    """Test PipAuditScanner class."""
    
    def test_init(self):
        """Test PipAuditScanner initialization."""
        scanner = PipAuditScanner("/tmp")
        assert scanner.target_path == Path("/tmp")
        assert isinstance(scanner, BaseScanner)
    
    def test_is_available(self):
        """Test availability check."""
        scanner = PipAuditScanner("/tmp")
        result = scanner.is_available()
        assert isinstance(result, bool)


class TestSafetyScanner:
    """Test SafetyScanner class."""
    
    def test_init(self):
        """Test SafetyScanner initialization."""
        scanner = SafetyScanner("/tmp")
        assert scanner.target_path == Path("/tmp")
        assert isinstance(scanner, BaseScanner)
    
    def test_is_available(self):
        """Test availability check."""
        scanner = SafetyScanner("/tmp")
        result = scanner.is_available()
        assert isinstance(result, bool)


class TestScannerRegistry:
    """Test scanner registry functions."""
    
    def test_get_scanner_valid(self):
        """Test getting a valid scanner."""
        scanner = get_scanner("bandit", "/tmp")
        if scanner and scanner.is_available():
            assert isinstance(scanner, BanditScanner)
    
    def test_get_scanner_invalid(self):
        """Test getting an invalid scanner."""
        scanner = get_scanner("nonexistent", "/tmp")
        assert scanner is None
    
    def test_list_available_scanners(self):
        """Test listing available scanners."""
        available = list_available_scanners("/tmp")
        assert isinstance(available, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
