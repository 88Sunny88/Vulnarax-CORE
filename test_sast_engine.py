#!/usr/bin/env python3
"""
Comprehensive test suite for VulnaraX SAST (Static Application Security Testing) engine
Tests multiple vulnerability types and code patterns
"""

import os
import sys
import tempfile
import shutil
import json
import requests
from pathlib import Path

# Test the SAST engine directly
sys.path.append('/Users/alexandervidenov/Desktop/Vulnarax-core')
from vulnaraX.sast_engine import scan_code_security

def create_test_project():
    """Create a test project with various vulnerability patterns"""
    test_dir = tempfile.mkdtemp(prefix="vulnarax_sast_test_")
    print(f"📁 Creating test project in: {test_dir}")
    
    # Python vulnerable code examples
    python_vulnerable = '''#!/usr/bin/env python3
"""
Intentionally vulnerable Python code for SAST testing
"""

import os
import subprocess
import pickle
import yaml
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secrets (CWE-798)
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
DATABASE_PASSWORD = "admin123password"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SQL Injection vulnerability (CWE-89)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Vulnerable: Direct string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(query)
    return cursor.fetchall()

# Command Injection vulnerability (CWE-78)
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # Vulnerable: Using os.system with user input
    result = os.system(f"ping -c 1 {host}")
    return f"Ping result: {result}"

# Unsafe deserialization (CWE-502)
@app.route('/load_data')
def load_user_data():
    data = request.get_data()
    # Vulnerable: Using pickle.loads on user input
    user_data = pickle.loads(data)
    return user_data

# Unsafe reflection (CWE-95)
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # Vulnerable: Using eval on user input
    result = eval(expression)
    return f"Result: {result}"

# Weak cryptography (CWE-327)
import hashlib
import md5

def hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return md5.new(password.encode()).hexdigest()

def weak_hash(data):
    # Vulnerable: Using SHA1
    return hashlib.sha1(data.encode()).hexdigest()

# More command injection patterns
def backup_files(directory):
    # Vulnerable: subprocess with shell=True
    subprocess.call(f"tar -czf backup.tar.gz {directory}", shell=True)
    
def execute_command(cmd):
    # Vulnerable: Using subprocess.run with user input
    subprocess.run(cmd, shell=True)

# Additional vulnerable patterns
def unsafe_yaml_load(yaml_content):
    # Vulnerable: Using yaml.load instead of yaml.safe_load
    return yaml.load(yaml_content)

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production
'''
    
    # JavaScript vulnerable code examples
    javascript_vulnerable = '''/**
 * Intentionally vulnerable JavaScript code for SAST testing
 */

const express = require('express');
const { exec } = require('child_process');
const app = express();

// Hardcoded secrets
const API_KEY = "sk-1234567890abcdef1234567890abcdef12345678";
const github_token = "ghp_1234567890abcdef1234567890abcdef123456";

// XSS vulnerability via innerHTML
app.get('/profile', (req, res) => {
    const username = req.query.username;
    // Vulnerable: Direct insertion into innerHTML
    const html = `<h1>Welcome, ${username}!</h1>`;
    document.getElementById('profile').innerHTML = html;
});

// Command injection
app.get('/system', (req, res) => {
    const command = req.query.cmd;
    // Vulnerable: Executing user input as system command
    exec(command, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// Unsafe eval usage
app.get('/calculate', (req, res) => {
    const expression = req.query.expr;
    try {
        // Vulnerable: Using eval on user input
        const result = eval(expression);
        res.json({ result: result });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// DOM-based XSS
function updatePage(userInput) {
    // Vulnerable: Direct DOM manipulation with user input
    document.write(`<div>${userInput}</div>`);
}

// More XSS patterns
function displayMessage(message) {
    // Vulnerable: innerHTML with concatenation
    document.getElementById('messages').innerHTML += '<p>' + message + '</p>';
}

// Prototype pollution potential
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: No prototype protection
        target[key] = source[key];
    }
    return target;
}

// Client-side secrets (should be detected)
const stripe_secret = "sk_test_1234567890abcdef1234567890abcdef";
const aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
'''
    
    # Safe code example (should have minimal findings)
    python_safe = '''#!/usr/bin/env python3
"""
Secure Python code example with proper practices
"""

import os
import sqlite3
import hashlib
import secrets
from flask import Flask, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# Secure: Environment variables for secrets
API_KEY = os.environ.get('API_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')

# Secure: Parameterized query
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    if not user_id or not user_id.isdigit():
        return {'error': 'Invalid user ID'}, 400
    
    # Secure: Using parameterized query
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchall()
    conn.close()
    return {'users': result}

# Secure: Input validation and sanitization
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    if not host or not is_valid_hostname(host):
        return {'error': 'Invalid hostname'}, 400
    
    # Secure: Using subprocess with argument list
    import subprocess
    try:
        result = subprocess.run(['ping', '-c', '1', host], 
                              capture_output=True, text=True, timeout=5)
        return {'output': result.stdout}
    except subprocess.TimeoutExpired:
        return {'error': 'Timeout'}, 408

def is_valid_hostname(hostname):
    """Validate hostname format"""
    import re
    pattern = r'^[a-zA-Z0-9.-]+$'
    return re.match(pattern, hostname) and len(hostname) <= 255

# Secure: Strong password hashing
def hash_password(password):
    # Secure: Using bcrypt-equivalent
    return generate_password_hash(password)

if __name__ == '__main__':
    app.run(debug=False)  # Production mode
'''
    
    # Create test files
    test_files = {
        'vulnerable_app.py': python_vulnerable,
        'vulnerable_client.js': javascript_vulnerable,
        'secure_app.py': python_safe,
        'package.json': json.dumps({
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0"
            }
        }, indent=2),
        'README.md': '# Test Project for SAST Scanning',
    }
    
    for filename, content in test_files.items():
        file_path = os.path.join(test_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
    
    return test_dir

def test_sast_engine_direct():
    """Test SAST engine directly"""
    print("\\n🔍 Testing SAST Engine Directly")
    print("=" * 50)
    
    test_project = create_test_project()
    
    try:
        # Run SAST scan
        results = scan_code_security(test_project)
        
        print(f"✅ SAST scan completed successfully")
        print(f"   📊 Scan Results:")
        print(f"      Project Path: {results['scan_info']['project_path']}")
        print(f"      Scan Time: {results['scan_info']['scan_time']:.2f} seconds")
        print(f"      Total Vulnerabilities: {results['scan_info']['total_vulnerabilities']}")
        print(f"      Files Scanned: {len(results['files_scanned'])}")
        
        # Print summary
        summary = results['summary']
        print(f"\\n   📈 Vulnerability Summary:")
        print(f"      Severity Distribution:")
        for severity, count in summary['severity_distribution'].items():
            print(f"        {severity.upper()}: {count}")
        
        print(f"\\n      Vulnerability Types:")
        for vuln_type, count in summary['vulnerability_types'].items():
            print(f"        {vuln_type.replace('_', ' ').title()}: {count}")
        
        # Show top vulnerabilities
        vulnerabilities = results['vulnerabilities']
        if vulnerabilities:
            print(f"\\n   🚨 Top Vulnerabilities Found:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                location = vuln['location']
                print(f"      {i}. {vuln['title']}")
                print(f"         Severity: {vuln['severity'].upper()}")
                print(f"         File: {Path(location['file_path']).name}:{location['line_number']}")
                print(f"         Type: {vuln['vulnerability_type'].replace('_', ' ').title()}")
                if vuln.get('cwe_id'):
                    print(f"         CWE: {vuln['cwe_id']}")
                print()
        
        # Metrics
        metrics = results['metrics']
        print(f"   📊 Scan Metrics:")
        print(f"      Risk Score: {metrics['risk_score']}")
        print(f"      Average Confidence: {metrics['confidence_avg']}")
        print(f"      High Confidence Findings: {metrics['high_confidence_count']}")
        
        return True
        
    except Exception as e:
        print(f"❌ SAST scan failed: {e}")
        return False
    finally:
        # Cleanup
        shutil.rmtree(test_project, ignore_errors=True)

def test_sast_api():
    """Test SAST engine via API"""
    print("\\n🌐 Testing SAST API Endpoint")
    print("=" * 50)
    
    base_url = "http://localhost:8000"
    test_project = create_test_project()
    
    try:
        # Test SAST API endpoint
        response = requests.post(f"{base_url}/sast/scan", json={
            "project_path": test_project,
            "exclude_patterns": ["*/node_modules/*", "*/.git/*"],
            "config": {
                "enable_experimental": True
            }
        }, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SAST API request successful")
            print(f"   📊 API Response:")
            print(f"      Total Vulnerabilities: {data['scan_info']['total_vulnerabilities']}")
            print(f"      Scan Time: {data['scan_info']['scan_time']:.2f} seconds")
            print(f"      Risk Score: {data['metrics']['risk_score']}")
            
            # Show vulnerability breakdown
            summary = data['summary']
            if summary['severity_distribution']:
                print(f"\\n   📈 Severity Breakdown:")
                for severity, count in summary['severity_distribution'].items():
                    print(f"      {severity.upper()}: {count}")
            
            return True
        else:
            print(f"❌ SAST API request failed")
            print(f"   Status Code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ SAST API connection failed: {e}")
        print(f"   Make sure the VulnaraX server is running on {base_url}")
        return False
    except Exception as e:
        print(f"❌ SAST API test failed: {e}")
        return False
    finally:
        # Cleanup
        shutil.rmtree(test_project, ignore_errors=True)

def test_vulnerability_detection_accuracy():
    """Test accuracy of vulnerability detection"""
    print("\\n🎯 Testing Vulnerability Detection Accuracy")
    print("=" * 50)
    
    # Create minimal test files for specific vulnerabilities
    test_dir = tempfile.mkdtemp(prefix="vulnarax_accuracy_test_")
    
    try:
        # Test cases with expected findings
        test_cases = [
            {
                'filename': 'sql_injection.py',
                'code': '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return execute_query(query)
''',
                'expected_types': ['sql_injection']
            },
            {
                'filename': 'command_injection.py',
                'code': '''
import os
def ping_host(host):
    os.system(f"ping {host}")
''',
                'expected_types': ['command_injection']
            },
            {
                'filename': 'hardcoded_secrets.py',
                'code': '''
api_key = "sk-1234567890abcdef1234567890abcdef12345678"
password = "admin123password"
''',
                'expected_types': ['hardcoded_secrets']
            },
            {
                'filename': 'unsafe_eval.py',
                'code': '''
def calculate(expr):
    return eval(expr)
''',
                'expected_types': ['unsafe_reflection']
            }
        ]
        
        detection_results = []
        
        for test_case in test_cases:
            # Create test file
            file_path = os.path.join(test_dir, test_case['filename'])
            with open(file_path, 'w') as f:
                f.write(test_case['code'])
            
            # Scan the single file
            results = scan_code_security(test_dir)
            vulnerabilities = results['vulnerabilities']
            
            # Check detection
            found_types = [v['vulnerability_type'] for v in vulnerabilities 
                          if Path(v['location']['file_path']).name == test_case['filename']]
            
            expected = set(test_case['expected_types'])
            found = set(found_types)
            
            detection_rate = len(expected & found) / len(expected) if expected else 0
            
            detection_results.append({
                'test_case': test_case['filename'],
                'expected': expected,
                'found': found,
                'detection_rate': detection_rate,
                'vulnerabilities_found': len(found_types)
            })
            
            print(f"   📝 {test_case['filename']}:")
            print(f"      Expected: {', '.join(expected)}")
            print(f"      Found: {', '.join(found)}")
            print(f"      Detection Rate: {detection_rate:.1%}")
            print(f"      Total Findings: {len(found_types)}")
            print()
        
        # Calculate overall accuracy
        total_detection_rate = sum(r['detection_rate'] for r in detection_results) / len(detection_results)
        print(f"🎯 Overall Detection Accuracy: {total_detection_rate:.1%}")
        
        return total_detection_rate > 0.8  # 80% accuracy threshold
        
    except Exception as e:
        print(f"❌ Accuracy test failed: {e}")
        return False
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def main():
    """Run comprehensive SAST engine tests"""
    print("🚀 VulnaraX SAST Engine Comprehensive Testing")
    print("=" * 60)
    
    test_results = []
    
    # Test 1: Direct engine testing
    test_results.append(test_sast_engine_direct())
    
    # Test 2: API endpoint testing
    test_results.append(test_sast_api())
    
    # Test 3: Vulnerability detection accuracy
    test_results.append(test_vulnerability_detection_accuracy())
    
    # Summary
    print("\\n📊 Test Summary")
    print("=" * 30)
    
    tests = [
        "SAST Engine Direct Test",
        "SAST API Endpoint Test", 
        "Vulnerability Detection Accuracy"
    ]
    
    for i, (test_name, result) in enumerate(zip(tests, test_results)):
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{i+1}. {test_name}: {status}")
    
    success_rate = sum(test_results) / len(test_results)
    print(f"\\n🎯 Overall Success Rate: {success_rate:.1%}")
    
    if success_rate >= 0.8:
        print("\\n🎉 SAST Engine is working excellently!")
        print("✨ VulnaraX now has enterprise-grade static analysis capabilities")
    else:
        print("\\n⚠️  Some tests failed. Review the implementation.")
        
    return success_rate >= 0.8

if __name__ == "__main__":
    main()