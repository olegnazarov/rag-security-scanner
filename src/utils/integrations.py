"""
Integration helpers for popular RAG and LLM platforms
"""

import requests
from typing import Dict, Optional


class RAGIntegration:
    """Integration helpers for popular RAG systems"""

    @staticmethod
    def create_openai_scanner(api_key: str, model: str = "gpt-3.5-turbo"):
        """Create scanner configured for OpenAI API"""

        def openai_request_handler(payload: str, headers=None):
            try:
                response = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": payload}],
                        "max_tokens": 150,
                        "temperature": 0
                    },
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    return True, content, response.elapsed.total_seconds()
                else:
                    return False, f"API Error: {response.status_code}", 0

            except Exception as e:
                return False, str(e), 0

        from ..rag_scanner import RAGSecurityScanner
        scanner = RAGSecurityScanner()
        scanner._make_request = openai_request_handler
        return scanner

    @staticmethod
    def create_huggingface_scanner(model_name: str, hf_token: Optional[str] = None):
        """Create scanner for HuggingFace Inference API"""

        def hf_request_handler(payload: str, headers=None):
            try:
                api_url = f"https://api-inference.huggingface.co/models/{model_name}"
                headers = {"Authorization": f"Bearer {hf_token}"} if hf_token else {}

                response = requests.post(
                    api_url,
                    headers=headers,
                    json={"inputs": payload, "parameters": {"max_length": 150}},
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        content = data[0].get("generated_text", "")
                        return True, content, response.elapsed.total_seconds()
                    else:
                        return False, "Invalid response format", 0
                else:
                    return False, f"API Error: {response.status_code}", 0

            except Exception as e:
                return False, str(e), 0

        from ..rag_scanner import RAGSecurityScanner
        scanner = RAGSecurityScanner()
        scanner._make_request = hf_request_handler
        return scanner

    @staticmethod
    def create_anthropic_scanner(api_key: str):
        """Create scanner for Anthropic Claude API"""

        def anthropic_request_handler(payload: str, headers=None):
            try:
                response = requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": "claude-3-sonnet-20240229",
                        "max_tokens": 150,
                        "messages": [{"role": "user", "content": payload}]
                    },
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data["content"][0]["text"]
                    return True, content, response.elapsed.total_seconds()
                else:
                    return False, f"API Error: {response.status_code}", 0

            except Exception as e:
                return False, str(e), 0

        from ..rag_scanner import RAGSecurityScanner
        scanner = RAGSecurityScanner()
        scanner._make_request = anthropic_request_handler
        return scanner

    @staticmethod
    def create_custom_scanner(endpoint_url: str,
                            request_format: str = "openai",
                            headers: Dict[str, str] = None):
        """Create scanner for custom RAG endpoint"""

        def custom_request_handler(payload: str, extra_headers=None):
            try:
                request_headers = headers.copy() if headers else {}
                if extra_headers:
                    request_headers.update(extra_headers)

                if request_format == "openai":
                    json_data = {
                        "messages": [{"role": "user", "content": payload}],
                        "max_tokens": 150
                    }
                elif request_format == "simple":
                    json_data = {"query": payload}
                else:
                    json_data = {"input": payload}

                response = requests.post(
                    endpoint_url,
                    headers=request_headers,
                    json=json_data,
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    # Try different response formats
                    content = (data.get("response") or
                             data.get("answer") or
                             data.get("output") or
                             str(data))
                    return True, content, response.elapsed.total_seconds()
                else:
                    return False, f"API Error: {response.status_code}", 0

            except Exception as e:
                return False, str(e), 0

        from ..rag_scanner import RAGSecurityScanner
        scanner = RAGSecurityScanner(target_url=endpoint_url)
        scanner._make_request = custom_request_handler
        return scanner
