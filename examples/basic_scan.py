#!/usr/bin/env python3
"""
Basic RAG Security Scanner usage examples
"""

from src.rag_scanner import RAGSecurityScanner

def demo_basic_scan():
    """Basic demo scan"""
    print("RAG Security Scanner - Basic Demo")
    print("=" * 50)
    
    # Create scanner in demo mode
    scanner = RAGSecurityScanner()
    
    # Run full scan
    result = scanner.run_full_scan()
    
    # Save reports
    json_file = scanner.save_report(result, "json")
    html_file = scanner.save_report(result, "html")
    
    print(f"\nReports generated:")
    print(f"   JSON: {json_file}")
    print(f"   HTML: {html_file}")
    
    return result

def demo_targeted_scan():
    """Demo of targeted vulnerability scanning"""
    print("Targeted Vulnerability Scanning")
    print("=" * 40)
    
    scanner = RAGSecurityScanner()
    
    # Test specific vulnerability types
    print("\nTesting Prompt Injection...")
    pi_threats = scanner.scan_prompt_injection()
    print(f"   Found {len(pi_threats)} threats")
    
    print("\nTesting Data Leakage...")
    dl_threats = scanner.scan_data_leakage()
    print(f"   Found {len(dl_threats)} threats")
    
    print("\nTesting Function Abuse...")
    fa_threats = scanner.scan_function_abuse()
    print(f"   Found {len(fa_threats)} threats")
    
    print("\nTesting Context Manipulation...")
    cm_threats = scanner.scan_context_manipulation()
    print(f"   Found {len(cm_threats)} threats")
    
    total_threats = len(pi_threats) + len(dl_threats) + len(fa_threats) + len(cm_threats)
    print(f"\nTotal threats found: {total_threats}")

def demo_custom_endpoint():
    """Demo scanning custom endpoint"""
    print("Custom Endpoint Scanning")
    print("=" * 30)
    
    # Example with custom API endpoint
    scanner = RAGSecurityScanner(
        target_url="https://api.example.com/chat",
        api_key="your-api-key-here",
        timeout=60,
        delay_between_requests=2.0
    )
    
    print("WARNING: This would scan a real endpoint!")
    print("   Remove this print and uncomment below to test:")
    
    # Uncomment to test real endpoint:
    # result = scanner.run_full_scan()
    # scanner.save_report(result, "html")

if __name__ == "__main__":
    # Run demos
    demo_basic_scan()
    print("\n" + "="*60 + "\n")
    demo_targeted_scan()
    print("\n" + "="*60 + "\n")
    demo_custom_endpoint()