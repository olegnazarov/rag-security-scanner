"""
Tests for payload loading and validation
"""

import pytest
import json
from pathlib import Path
from src.payloads.init import load_payloads

class TestPayloads:
    
    def test_load_payloads(self):
        """Test payload loading function"""
        payloads = load_payloads()
        
        assert isinstance(payloads, dict)
        assert len(payloads) > 0
        
        # Check expected categories
        expected_categories = [
            "prompt_injection",
            "data_leakage", 
            "function_abuse"
        ]
        
        for category in expected_categories:
            assert category in payloads
            assert isinstance(payloads[category], list)
            assert len(payloads[category]) > 0
    
    def test_payload_file_structure(self):
        """Test individual payload files"""
        payloads_dir = Path(__file__).parent.parent / "src" / "payloads"
        
        for payload_file in payloads_dir.glob("*.json"):
            if payload_file.name == "__init__.py":
                continue
                
            with open(payload_file, 'r') as f:
                data = json.load(f)
                
            assert isinstance(data, dict)
            
            # Each category should have lists of strings
            for category, payloads in data.items():
                assert isinstance(payloads, list)
                assert len(payloads) > 0
                
                for payload in payloads:
                    assert isinstance(payload, str)
                    assert len(payload.strip()) > 0
    
    def test_prompt_injection_payloads(self):
        """Test prompt injection payloads specifically"""
        payloads = load_payloads()
        
        if "prompt_injection" in payloads:
            pi_payloads = payloads["prompt_injection"]
            
            # Should have various attack types
            payload_text = " ".join(pi_payloads).lower()
            
            # Check for key attack patterns
            assert "ignore" in payload_text
            assert "instruction" in payload_text or "prompt" in payload_text
            assert "system" in payload_text
    
    def test_data_leakage_payloads(self):
        """Test data leakage payloads"""
        payloads = load_payloads()
        
        if "data_leakage" in payloads:
            dl_payloads = payloads["data_leakage"]
            
            payload_text = " ".join(dl_payloads).lower()
            
            # Check for data extraction patterns
            assert "data" in payload_text or "information" in payload_text
            assert "show" in payload_text or "list" in payload_text
    
    def test_function_abuse_payloads(self):
        """Test function abuse payloads"""
        payloads = load_payloads()
        
        if "function_abuse" in payloads:
            fa_payloads = payloads["function_abuse"]
            
            payload_text = " ".join(fa_payloads).lower()
            
            # Check for function-related patterns
            assert "function" in payload_text or "call" in payload_text or "api" in payload_text

if __name__ == "__main__":
    pytest.main([__file__])