"""Tests for LLM prompt loading and vulnerability type matching."""

import pytest
import sys
from pathlib import Path
from agent.semgrep_scanner import SemgrepScanner
from agent.llm_handler import LLMHandler


class TestMapVulnType:
    """Test _map_vuln_type() method."""
    
    def setup_method(self):
        self.scanner = SemgrepScanner(".")
    
    def test_sql_injection(self):
        """Test SQL injection mapping."""
        result = self.scanner._map_vuln_type("python.sql_injection")
        assert result == "sql_injection"
    
    def test_sql_injection_full_path(self):
        """Test SQL injection with full path."""
        result = self.scanner._map_vuln_type("python.lang.security.sql_injection.sql_injection")
        assert result == "sql_injection"
    
    def test_xss(self):
        """Test XSS mapping."""
        result = self.scanner._map_vuln_type("python.xss")
        assert result == "xss"
    
    def test_hardcoded_secret(self):
        """Test hardcoded secret mapping."""
        result = self.scanner._map_vuln_type("python.hardcoded_secret")
        assert result == "hardcoded_secret"
    
    def test_missing_integrity(self):
        """Test missing-integrity mapping."""
        result = self.scanner._map_vuln_type("html.missing-integrity")
        assert result == "missing-integrity"
    
    def test_django_no_csrf_token(self):
        """Test django-no-csrf-token mapping."""
        result = self.scanner._map_vuln_type("python.django.security.django-no-csrf-token.django-no-csrf-token")
        assert result == "django-no-csrf-token"
    
    def test_avoid_using_app_run_directly(self):
        """Test avoid_using_app_run_directly mapping."""
        result = self.scanner._map_vuln_type("python.flask.security.audit.app-run-security-config.avoid_using_app_run_directly")
        assert result == "avoid_using_app_run_directly"
    
    def test_request_with_http(self):
        """Test request-with-http mapping."""
        result = self.scanner._map_vuln_type("python.request-with-http")
        assert result == "request-with-http"
    
    def test_unknown_type(self):
        """Test unknown type falls back to code_flaw (has dedicated prompt)."""
        result = self.scanner._map_vuln_type("python.unknown.vulnerability")
        assert result == "code_flaw"


class TestLoadPrompts:
    """Test prompt loading from YAML."""
    
    def setup_method(self):
        self.handler = LLMHandler(".", "http://127.0.0.1:1234", None)
    
    def test_load_prompts_yaml(self):
        """Test loading prompts from YAML file."""
        prompts = self.handler._load_prompts()
        
        assert "sql_injection" in prompts
        assert "missing-integrity" in prompts
        assert "django-no-csrf-token" in prompts
        assert "avoid_using_app_run_directly" in prompts
        assert "request-with-http" in prompts
        assert "xss" in prompts
        assert "hardcoded_secret" in prompts
        assert "default" in prompts
    
    def test_prompt_format(self):
        """Test prompt formatting with code."""
        handler = LLMHandler(".", "http://127.0.0.1:1234", None)
        prompts = handler._load_prompts()
        
        # Test that prompts can be formatted with code
        test_code = "SELECT * FROM users WHERE id = input"
        prompt = prompts["sql_injection"].format(code=test_code)
        assert test_code in prompt
        assert "VULNERABLE CODE:" in prompt
    
    def test_fallback_prompts(self):
        """Test fallback to embedded prompts if YAML not found."""
        # Temporarily rename the YAML file
        yaml_file = Path("configs/llm_prompts.yaml")
        backup = None
        if yaml_file.exists():
            backup = yaml_file.rename("configs/llm_prompts.yaml.bak")
        
        try:
            handler = LLMHandler(".", "http://127.0.0.1:1234", None)
            prompts = handler._load_prompts()
            assert len(prompts) > 0
            assert "default" in prompts
        finally:
            # Restore the YAML file
            if backup and backup.exists():
                backup.rename("configs/llm_prompts.yaml")


class TestPromptKeysMatchVulnType:
    """Test that prompt keys match what _map_vuln_type returns."""
    
    def setup_method(self):
        self.scanner = SemgrepScanner(".")
        self.handler = LLMHandler(".", "http://127.0.0.1:1234", None)
    
    def test_all_known_types_have_prompts(self):
        """Test that all known vulnerability types have prompts."""
        prompts = self.handler._load_prompts()
        
        # Test cases: (check_id, expected_type)
        test_cases = [
            ("python.sql_injection", "sql_injection"),
            ("html.missing-integrity", "missing-integrity"),
            ("python.django.security.django-no-csrf-token.django-no-csrf-token", "django-no-csrf-token"),
            ("python.flask.security.audit.app-run-security-config.avoid_using_app_run_directly", "avoid_using_app_run_directly"),
            ("python.request-with-http", "request-with-http"),
        ]
        
        for check_id, expected_type in test_cases:
            assert expected_type in prompts, f"Missing prompt for {expected_type}"
            
            # Verify the prompt can be retrieved
            prompt = prompts[expected_type]
            assert len(prompt) > 0
            assert "{code}" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
