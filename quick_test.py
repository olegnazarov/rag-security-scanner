#!/usr/bin/env python3
"""Quick OpenAI security test"""

import os
from src.rag_scanner import RAGSecurityScanner

def quick_test():
    """Run quick security test"""
    
    # Get and clean API key
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("ERROR: OPENAI_API_KEY environment variable not set")
        return
    
    api_key = ''.join(api_key.split())
    
    print("Quick RAG Security Scanner test against OpenAI")
    print("=" * 50)
    
    # Create scanner
    scanner = RAGSecurityScanner(delay_between_requests=0.5)
    
    # Set up OpenAI integration  
    import openai
    client = openai.OpenAI(api_key=api_key)
    
    def openai_request_handler(payload: str, headers=None):
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": payload}],
                max_tokens=150
            )
            return True, response.choices[0].message.content, 0.5
        except Exception as e:
            return False, str(e), 0.5
    
    scanner._make_request = openai_request_handler
    
    # Test only prompt injection (first 5 payloads)
    payloads = scanner.payloads["prompt_injection"][:5]
    
    print(f"Testing {len(payloads)} prompt injection payloads...")
    
    threats = []
    for i, payload in enumerate(payloads):
        print(f"\n[{i+1}/{len(payloads)}] Testing: {payload[:60]}...")
        
        success, response, _ = scanner._make_request(payload)
        
        if success:
            print(f"Response: {response[:100]}...")
            
            threat = scanner._analyze_response(payload, response, "prompt_injection")
            if threat:
                threats.append(threat)
                print(f"THREAT DETECTED: {threat.severity} severity (confidence: {threat.confidence:.2f})")
            else:
                print("No threat detected")
        else:
            print(f"Request failed: {response}")
    
    print(f"\nRESULTS: {len(threats)} threats found out of {len(payloads)} tests")
    
    for threat in threats:
        print(f"\n[{threat.severity.upper()}] {threat.category}")
        print(f"   Payload: {threat.payload}")
        print(f"   Response: {threat.response[:150]}...")
        print(f"   Confidence: {threat.confidence:.2f}")

if __name__ == "__main__":
    quick_test()