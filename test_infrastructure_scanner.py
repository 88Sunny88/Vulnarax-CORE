#!/usr/bin/env python3
"""
Comprehensive test suite for Infrastructure Security Scanner
Tests Docker, Kubernetes, Terraform, and Docker Compose security configurations
"""

import os
import sys
import tempfile
import shutil
import json
from pathlib import Path

# Test the infrastructure scanner directly
sys.path.append('/Users/alexandervidenov/Desktop/Vulnarax-core')
from vulnaraX.infrastructure_scanner import scan_infrastructure_security

def create_infrastructure_test_project():
    """Create test project with various infrastructure files"""
    test_dir = tempfile.mkdtemp(prefix="vulnarax_infra_test_")
    print(f"📁 Creating infrastructure test project in: {test_dir}")
    
    # Vulnerable Dockerfile
    dockerfile_vulnerable = '''FROM node:latest

# Running as root (vulnerable)
USER root

# Using ADD with HTTP (vulnerable)
ADD http://example.com/file.txt /tmp/

# Hardcoded secret in ENV (vulnerable)
ENV API_KEY=sk-1234567890abcdef1234567890abcdef12345678
ENV DATABASE_PASSWORD=admin123

# No HEALTHCHECK (best practice violation)
COPY . /app
WORKDIR /app

# Using sudo in RUN (vulnerable)
RUN sudo apt-get update && apt-get install -y curl

EXPOSE 3000
CMD ["node", "server.js"]
'''
    
    # Secure Dockerfile example
    dockerfile_secure = '''FROM node:18.17-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \\
    adduser -S nextjs -u 1001

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .

# Use non-root user
USER nextjs

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["node", "server.js"]
'''
    
    # Vulnerable Kubernetes manifest
    k8s_vulnerable = '''apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
  namespace: default
spec:
  # Host network (vulnerable)
  hostNetwork: true
  # Host PID (vulnerable)  
  hostPID: true
  
  containers:
  - name: app
    image: nginx:latest
    # Privileged container (vulnerable)
    securityContext:
      privileged: true
      runAsUser: 0  # Running as root (vulnerable)
      allowPrivilegeEscalation: true  # Privilege escalation (vulnerable)
    ports:
    - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      containers:
      - name: app
        image: myapp:latest
        # Missing security context (vulnerable)
        ports:
        - containerPort: 8080
'''
    
    # Secure Kubernetes manifest
    k8s_secure = '''apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    
  containers:
  - name: app
    image: nginx:1.21-alpine
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
      readOnlyRootFilesystem: true
    ports:
    - containerPort: 80
    resources:
      limits:
        memory: "128Mi"
        cpu: "100m"
      requests:
        memory: "64Mi" 
        cpu: "50m"
'''
    
    # Vulnerable Terraform configuration
    terraform_vulnerable = '''# Vulnerable AWS resources
resource "aws_security_group" "web" {
  name_prefix = "web-"
  
  # Allows access from anywhere (vulnerable)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Vulnerable
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Vulnerable
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # Public read access (vulnerable)
  acl    = "public-read"
}

resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  
  # Gets public IP automatically (vulnerable)
  associate_public_ip_address = true
  
  security_groups = [aws_security_group.web.name]
}
'''
    
    # Secure Terraform configuration
    terraform_secure = '''# Secure AWS resources
resource "aws_security_group" "web" {
  name_prefix = "web-secure-"
  
  # Restricted access
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Private network only
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-secure-data-bucket"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data_pab" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.private.id
  
  # No public IP
  associate_public_ip_address = false
  
  vpc_security_group_ids = [aws_security_group.web.id]
}
'''
    
    # Vulnerable Docker Compose
    docker_compose_vulnerable = '''version: '3.8'

services:
  web:
    image: nginx:latest
    # Privileged mode (vulnerable)
    privileged: true
    # Host network mode (vulnerable)
    network_mode: host
    ports:
      - "80:80"
    environment:
      # Hardcoded secrets (vulnerable)
      - DB_PASSWORD=admin123
      - API_KEY=sk-1234567890abcdef
    volumes:
      # Mounting sensitive host paths (vulnerable)
      - /:/host-root
      - /var/run/docker.sock:/var/run/docker.sock

  database:
    image: postgres:latest
    privileged: true  # Vulnerable
    environment:
      - POSTGRES_PASSWORD=weak_password
    volumes:
      - /etc/passwd:/etc/passwd:ro  # Mounting host passwd file
'''
    
    # Create test files
    test_files = {
        'Dockerfile.vulnerable': dockerfile_vulnerable,
        'Dockerfile.secure': dockerfile_secure,
        'k8s/vulnerable-manifest.yaml': k8s_vulnerable,
        'k8s/secure-manifest.yaml': k8s_secure,
        'terraform/vulnerable.tf': terraform_vulnerable,
        'terraform/secure.tf': terraform_secure,
        'docker-compose.vulnerable.yml': docker_compose_vulnerable,
        'README.md': '# Infrastructure Security Test Project',
    }
    
    for filename, content in test_files.items():
        file_path = os.path.join(test_dir, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(content)
    
    return test_dir

def test_infrastructure_scanner_direct():
    """Test infrastructure scanner directly"""
    print("\\n🔍 Testing Infrastructure Scanner Directly")
    print("=" * 55)
    
    test_project = create_infrastructure_test_project()
    
    try:
        # Run infrastructure scan
        results = scan_infrastructure_security(test_project)
        
        print(f"✅ Infrastructure scan completed successfully")
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
        
        if summary.get('compliance_frameworks'):
            print(f"\\n      Compliance Frameworks:")
            for framework, count in summary['compliance_frameworks'].items():
                print(f"        {framework}: {count} violations")
        
        # Show sample vulnerabilities by category
        vulnerabilities = results['vulnerabilities']
        if vulnerabilities:
            print(f"\\n   🚨 Sample Infrastructure Vulnerabilities:")
            
            # Group by file type
            dockerfile_vulns = [v for v in vulnerabilities if 'Dockerfile' in v['file_path']]
            k8s_vulns = [v for v in vulnerabilities if '.yaml' in v['file_path'] or '.yml' in v['file_path']]
            terraform_vulns = [v for v in vulnerabilities if '.tf' in v['file_path']]
            
            if dockerfile_vulns:
                print(f"\\n      🐳 Dockerfile Issues ({len(dockerfile_vulns)}):")
                for i, vuln in enumerate(dockerfile_vulns[:3], 1):
                    print(f"        {i}. {vuln['title']} (Severity: {vuln['severity'].upper()})")
                    if vuln.get('line_number'):
                        print(f"           Line {vuln['line_number']}: {Path(vuln['file_path']).name}")
            
            if k8s_vulns:
                print(f"\\n      ☸️  Kubernetes Issues ({len(k8s_vulns)}):")
                for i, vuln in enumerate(k8s_vulns[:3], 1):
                    print(f"        {i}. {vuln['title']} (Severity: {vuln['severity'].upper()})")
                    if vuln.get('resource_name'):
                        print(f"           Resource: {vuln['resource_name']}")
            
            if terraform_vulns:
                print(f"\\n      🏗️  Terraform Issues ({len(terraform_vulns)}):")
                for i, vuln in enumerate(terraform_vulns[:3], 1):
                    print(f"        {i}. {vuln['title']} (Severity: {vuln['severity'].upper()})")
                    if vuln.get('resource_name'):
                        print(f"           Resource: {vuln['resource_name']}")
        
        # Metrics
        metrics = results['metrics']
        print(f"\\n   📊 Scan Metrics:")
        print(f"      Risk Score: {metrics['risk_score']}")
        print(f"      Average Confidence: {metrics['confidence_avg']}")
        print(f"      High Confidence Findings: {metrics['high_confidence_count']}")
        if metrics.get('compliance_violations'):
            print(f"      Compliance Violations: {metrics['compliance_violations']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Infrastructure scan failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        shutil.rmtree(test_project, ignore_errors=True)

def test_specific_vulnerability_detection():
    """Test detection of specific vulnerability types"""
    print("\\n🎯 Testing Specific Vulnerability Detection")
    print("=" * 50)
    
    # Create targeted test cases
    test_dir = tempfile.mkdtemp(prefix="vulnarax_targeted_test_")
    
    try:
        test_cases = [
            {
                'filename': 'Dockerfile.root',
                'content': 'FROM ubuntu:20.04\\nUSER root\\nRUN apt-get update',
                'expected_types': ['privilege_escalation']
            },
            {
                'filename': 'k8s-privileged.yaml',
                'content': '''apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
''',
                'expected_types': ['privilege_escalation']
            },
            {
                'filename': 'terraform-open-sg.tf',
                'content': '''resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 22
  }
}''',
                'expected_types': ['network_exposure']
            },
            {
                'filename': 'docker-compose-privileged.yml',
                'content': '''version: '3'
services:
  web:
    image: nginx
    privileged: true
''',
                'expected_types': ['privilege_escalation']
            }
        ]
        
        detection_results = []
        
        for test_case in test_cases:
            # Create subdirectory if needed
            file_path = os.path.join(test_dir, test_case['filename'])
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(test_case['content'])
            
            # Scan the file
            results = scan_infrastructure_security(test_dir)
            vulnerabilities = results['vulnerabilities']
            
            # Check detection for this specific file
            found_types = [v['vulnerability_type'] for v in vulnerabilities 
                          if Path(v['file_path']).name == test_case['filename']]
            
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
            
            # Clean up file for next test
            os.remove(file_path)
        
        # Calculate overall accuracy
        total_detection_rate = sum(r['detection_rate'] for r in detection_results) / len(detection_results)
        print(f"🎯 Overall Detection Accuracy: {total_detection_rate:.1%}")
        
        return total_detection_rate > 0.75  # 75% accuracy threshold
        
    except Exception as e:
        print(f"❌ Targeted detection test failed: {e}")
        return False
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def test_file_type_coverage():
    """Test coverage of different infrastructure file types"""
    print("\\n📋 Testing File Type Coverage")
    print("=" * 35)
    
    test_dir = tempfile.mkdtemp(prefix="vulnarax_coverage_test_")
    
    try:
        # Test different file types
        file_types = {
            'Dockerfile': 'FROM ubuntu:latest\\nUSER root',
            'Dockerfile.dev': 'FROM node:latest\\nUSER 0',
            'deployment.yaml': '''apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
''',
            'service.yml': '''apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  type: NodePort
  ports:
  - port: 80
''',
            'main.tf': '''resource "aws_security_group" "test" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
            'variables.tf': '# Terraform variables file',
            'docker-compose.yaml': '''version: '3'
services:
  web:
    image: nginx
    privileged: true
''',
            'docker-compose.yml': '''version: '3'
services:
  db:
    image: postgres
    network_mode: host
'''
        }
        
        # Create all test files
        for filename, content in file_types.items():
            file_path = os.path.join(test_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Run scan
        results = scan_infrastructure_security(test_dir)
        
        # Check which files were analyzed
        scanned_files = [Path(f).name for f in results['files_scanned']]
        total_vulns = results['scan_info']['total_vulnerabilities']
        
        print(f"   📁 Files Created: {len(file_types)}")
        print(f"   🔍 Files Scanned: {len(scanned_files)}")
        print(f"   🚨 Total Vulnerabilities: {total_vulns}")
        
        print(f"\\n   📋 File Type Analysis:")
        for filename in file_types.keys():
            was_scanned = filename in scanned_files
            status = "✅ Scanned" if was_scanned else "⏭️  Skipped"
            print(f"      {filename}: {status}")
        
        # Calculate coverage
        coverage = len(scanned_files) / len(file_types)
        print(f"\\n   📊 Scan Coverage: {coverage:.1%}")
        
        return coverage > 0.6 and total_vulns > 0  # 60% coverage with findings
        
    except Exception as e:
        print(f"❌ Coverage test failed: {e}")
        return False
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def main():
    """Run comprehensive infrastructure scanner tests"""
    print("🚀 VulnaraX Infrastructure Security Scanner Testing")
    print("=" * 65)
    
    test_results = []
    
    # Test 1: Direct scanner testing
    test_results.append(test_infrastructure_scanner_direct())
    
    # Test 2: Specific vulnerability detection
    test_results.append(test_specific_vulnerability_detection())
    
    # Test 3: File type coverage
    test_results.append(test_file_type_coverage())
    
    # Summary
    print("\\n📊 Test Summary")
    print("=" * 30)
    
    tests = [
        "Infrastructure Scanner Direct Test",
        "Specific Vulnerability Detection",
        "File Type Coverage Test"
    ]
    
    for i, (test_name, result) in enumerate(zip(tests, test_results)):
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{i+1}. {test_name}: {status}")
    
    success_rate = sum(test_results) / len(test_results)
    print(f"\\n🎯 Overall Success Rate: {success_rate:.1%}")
    
    if success_rate >= 0.8:
        print("\\n🎉 Infrastructure Scanner is working excellently!")
        print("✨ VulnaraX now has enterprise-grade infrastructure security scanning")
        print("🔧 Supports Docker, Kubernetes, Terraform, and Docker Compose")
    else:
        print("\\n⚠️  Some tests failed. Review the implementation.")
        
    return success_rate >= 0.8

if __name__ == "__main__":
    main()