"""
Tests for integration functionality
"""

import pytest
from unittest.mock import Mock, patch
from src.utils.integrations import RAGIntegration

class TestRAGIntegration:
    
    @patch('src.utils.integrations.requests.post')
    def test_openai_integration(self, mock_post):
        """Test OpenAI integration"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Test response"}}]
        }
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_post.return_value = mock_response
        
        scanner = RAGIntegration.create_openai_scanner("test-key")
        success, response, time_taken = scanner._make_request("test payload")
        
        assert success is True
        assert response == "Test response"
        assert time_taken == 0.5
    
    @patch('src.utils.integrations.requests.post')
    def test_huggingface_integration(self, mock_post):
        """Test HuggingFace integration"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"generated_text": "HF response"}]
        mock_response.elapsed.total_seconds.return_value = 1.0
        mock_post.return_value = mock_response
        
        scanner = RAGIntegration.create_huggingface_scanner("test-model")
        success, response, time_taken = scanner._make_request("test")
        
        assert success is True
        assert response == "HF response"
        assert time_taken == 1.0
    
    @patch('src.utils.integrations.requests.post')
    def test_custom_integration(self, mock_post):
        """Test custom endpoint integration"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "Custom response"}
        mock_response.elapsed.total_seconds.return_value = 0.3
        mock_post.return_value = mock_response
        
        scanner = RAGIntegration.create_custom_scanner(
            "https://custom-api.com/chat",
            request_format="simple",
            headers={"Authorization": "Bearer token"}
        )
        
        success, response, time_taken = scanner._make_request("test")
        
        assert success is True
        assert response == "Custom response"
    
    def test_integration_error_handling(self):
        """Test error handling in integrations"""
        with patch('src.utils.integrations.requests.post') as mock_post:
            mock_post.side_effect = Exception("Network error")
            
            scanner = RAGIntegration.create_openai_scanner("test-key")
            success, response, time_taken = scanner._make_request("test")
            
            assert success is False
            assert "Network error" in response

if __name__ == "__main__":
    pytest.main([__file__])
