#!/usr/bin/env python3
"""
Quick SAST API test
"""

import requests
import json
import tempfile
import os

def test_sast_api():
    """Test SAST API endpoint"""
    # Create a simple test project
    test_dir = tempfile.mkdtemp(prefix="sast_api_test_")
    
    # Create a vulnerable Python file
    vulnerable_code = '''
import os
import subprocess

# Vulnerable code
def execute_user_command(cmd):
    os.system(cmd)  # Command injection
    
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"  # SQL injection
    return query

# Hardcoded secret
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
'''
    
    with open(os.path.join(test_dir, "vulnerable.py"), "w") as f:
        f.write(vulnerable_code)
    
    try:
        # Test the API
        response = requests.post("http://localhost:8002/sast/scan", json={
            "project_path": test_dir,
            "exclude_patterns": ["*/node_modules/*"],
            "config": {"test": True}
        }, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ SAST API Test Successful!")
            print(f"   Vulnerabilities Found: {data['scan_info']['total_vulnerabilities']}")
            print(f"   Scan Time: {data['scan_info']['scan_time']:.2f}s")
            print(f"   Risk Score: {data['metrics']['risk_score']}")
            
            if data['vulnerabilities']:
                print("\\n🚨 Sample Vulnerabilities:")
                for i, vuln in enumerate(data['vulnerabilities'][:3], 1):
                    print(f"   {i}. {vuln['title']} (Severity: {vuln['severity'].upper()})")
                    
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ API Test Failed: {e}")
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    test_sast_api()