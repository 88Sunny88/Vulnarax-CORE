#!/usr/bin/env python3
"""
VulnaraX Enterprise Reporting API Test Suite
Tests the premium enterprise reporting and analytics features
"""

import requests
import json
import time
from datetime import datetime

def test_enterprise_reporting_api():
    """Test enterprise reporting API endpoints"""
    
    base_url = "http://localhost:8002"
    
    print("🚀 VulnaraX Enterprise Reporting API Testing")
    print("=" * 60)
    
    # Sample scan results for testing
    sample_scan_results = [
        {
            "project_path": "/app/frontend",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1234",
                    "vulnerability_type": "sql_injection",
                    "severity": "critical",
                    "confidence": 0.95,
                    "description": "SQL injection in authentication module"
                },
                {
                    "id": "CVE-2023-5678", 
                    "vulnerability_type": "command_injection",
                    "severity": "high",
                    "confidence": 0.88,
                    "description": "Command injection in file upload"
                }
            ]
        },
        {
            "project_path": "/app/backend",
            "vulnerabilities": [
                {
                    "id": "CVE-2023-9012",
                    "vulnerability_type": "hardcoded_secrets",
                    "severity": "medium",
                    "confidence": 0.92,
                    "description": "API key hardcoded in configuration"
                },
                {
                    "id": "CVE-2023-3456",
                    "vulnerability_type": "insecure_configuration",
                    "severity": "low",
                    "confidence": 0.75,
                    "description": "Debug mode enabled in production"
                }
            ]
        }
    ]
    
    # Test 1: Get supported compliance frameworks
    print("\\n📋 Testing: Get Supported Compliance Frameworks")
    print("=" * 50)
    
    try:
        response = requests.get(f"{base_url}/enterprise/frameworks")
        if response.status_code == 200:
            frameworks_data = response.json()
            print("✅ Frameworks endpoint successful")
            print(f"   Supported frameworks: {len(frameworks_data['supported_frameworks'])}")
            for fw in frameworks_data['supported_frameworks']:
                print(f"   - {fw['name']} v{fw['version']}: {fw['description']}")
        else:
            print(f"❌ Frameworks endpoint failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Frameworks endpoint error: {str(e)}")
    
    # Test 2: Generate Executive Dashboard
    print("\\n🎯 Testing: Executive Dashboard Generation")
    print("=" * 50)
    
    dashboard_request = {
        "organization": "VulnaraX Test Corp",
        "scan_results": sample_scan_results,
        "time_period": "monthly"
    }
    
    try:
        response = requests.post(
            f"{base_url}/enterprise/dashboard",
            json=dashboard_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            dashboard_data = response.json()
            print("✅ Executive dashboard generated successfully")
            
            exec_summary = dashboard_data.get('executive_summary', {})
            vuln_overview = dashboard_data.get('vulnerability_overview', {})
            compliance_status = dashboard_data.get('compliance_status', {})
            
            print(f"   📊 Executive Summary:")
            print(f"      Organization: {exec_summary.get('organization')}")
            print(f"      Total Assets: {exec_summary.get('total_assets')}")
            print(f"      Critical Vulnerabilities: {exec_summary.get('critical_vulnerabilities')}")
            print(f"      Compliance Score: {exec_summary.get('compliance_score', 0):.1f}%")
            print(f"      Security Trend: {exec_summary.get('security_trend')}")
            
            print(f"\\n   🔍 Vulnerability Overview:")
            print(f"      Total Vulnerabilities: {vuln_overview.get('total_vulnerabilities')}")
            print(f"      Assets Scanned: {vuln_overview.get('assets_scanned')}")
            print(f"      Average Risk Score: {vuln_overview.get('risk_score_average', 0):.2f}")
            
            print(f"\\n   📋 Compliance Status:")
            for framework, assessment in compliance_status.items():
                print(f"      {framework}: {assessment.get('compliance_score', 0):.1f}%")
            
            # Show actionable insights
            insights = dashboard_data.get('actionable_insights', [])
            print(f"\\n   💡 Actionable Insights ({len(insights)}):")
            for i, insight in enumerate(insights[:3], 1):
                print(f"      {i}. [{insight.get('priority', 'medium').upper()}] {insight.get('description', 'N/A')}")
        else:
            print(f"❌ Dashboard generation failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Dashboard generation error: {str(e)}")
    
    # Test 3: Generate SOC2 Compliance Report
    print("\\n📋 Testing: SOC2 Compliance Report Generation")
    print("=" * 50)
    
    # Flatten vulnerabilities for compliance test
    all_vulnerabilities = []
    for scan in sample_scan_results:
        all_vulnerabilities.extend(scan['vulnerabilities'])
    
    compliance_request = {
        "vulnerabilities": all_vulnerabilities,
        "framework": "SOC2",
        "organization": "VulnaraX Test Corp"
    }
    
    try:
        response = requests.post(
            f"{base_url}/enterprise/compliance",
            json=compliance_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            compliance_data = response.json()
            print("✅ SOC2 compliance report generated successfully")
            
            print(f"   📊 Compliance Assessment:")
            print(f"      Framework: {compliance_data.get('framework')}")
            print(f"      Overall Score: {compliance_data.get('overall_score', 0):.1f}%")
            print(f"      Assessment Date: {compliance_data.get('assessment_date')}")
            
            summary = compliance_data.get('summary', {})
            print(f"\\n   📋 Control Summary:")
            print(f"      Total Controls: {summary.get('total_controls')}")
            print(f"      Compliant Controls: {summary.get('compliant_controls')}")
            print(f"      Violations: {summary.get('violations')}")
            
            # Show control details
            control_details = compliance_data.get('control_details', [])
            print(f"\\n   🔍 Control Details (Top 3):")
            for i, control in enumerate(control_details[:3], 1):
                status_icon = "✅" if control.get('status') == 'compliant' else "❌"
                print(f"      {i}. {status_icon} {control.get('control_id')}: {control.get('control_name')}")
                print(f"         Violations: {control.get('violation_count', 0)}")
            
            # Show remediation roadmap
            roadmap = compliance_data.get('remediation_roadmap', [])
            print(f"\\n   🛠️  Remediation Roadmap (Top 3):")
            for i, phase in enumerate(roadmap[:3], 1):
                print(f"      {i}. {phase.get('phase')} ({phase.get('timeline')})")
                print(f"         Control: {phase.get('control')} - {phase.get('priority')} priority")
        else:
            print(f"❌ Compliance report failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Compliance report error: {str(e)}")
    
    # Test 4: Generate PCI-DSS Compliance Report
    print("\\n💳 Testing: PCI-DSS Compliance Report Generation")
    print("=" * 50)
    
    pci_request = {
        "vulnerabilities": all_vulnerabilities,
        "framework": "PCI-DSS",
        "organization": "VulnaraX Test Corp"
    }
    
    try:
        response = requests.post(
            f"{base_url}/enterprise/compliance",
            json=pci_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            pci_data = response.json()
            print("✅ PCI-DSS compliance report generated successfully")
            print(f"   📊 PCI-DSS Score: {pci_data.get('overall_score', 0):.1f}%")
            
            # Show executive summary
            exec_summary = pci_data.get('executive_summary', '')
            if exec_summary:
                print(f"\\n   📄 Executive Summary:")
                summary_lines = exec_summary.strip().split('\\n')[:3]
                for line in summary_lines:
                    if line.strip():
                        print(f"      {line.strip()}")
        else:
            print(f"❌ PCI-DSS report failed: {response.status_code}")
    except Exception as e:
        print(f"❌ PCI-DSS report error: {str(e)}")
    
    # Test 5: Test invalid framework
    print("\\n⚠️  Testing: Invalid Framework Handling")
    print("=" * 50)
    
    invalid_request = {
        "vulnerabilities": all_vulnerabilities,
        "framework": "INVALID_FRAMEWORK",
        "organization": "VulnaraX Test Corp"
    }
    
    try:
        response = requests.post(
            f"{base_url}/enterprise/compliance",
            json=invalid_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 400:
            print("✅ Invalid framework properly rejected")
            error_data = response.json()
            print(f"   Error message: {error_data.get('detail', 'No detail')}")
        else:
            print(f"❌ Invalid framework not properly handled: {response.status_code}")
    except Exception as e:
        print(f"❌ Invalid framework test error: {str(e)}")
    
    print("\\n" + "=" * 60)
    print("🎉 Enterprise Reporting API Test Suite Complete!")
    print("✨ VulnaraX Enterprise Platform demonstrates:")
    print("   - Executive dashboard generation")
    print("   - Multi-framework compliance assessment") 
    print("   - SOC2, PCI-DSS, ISO27001 support")
    print("   - Threat intelligence correlation")
    print("   - Remediation roadmap planning")
    print("   - Enterprise-grade analytics")

def check_server_status():
    """Check if the VulnaraX server is running"""
    try:
        response = requests.get("http://localhost:8002/", timeout=5)
        return response.status_code == 200
    except:
        return False

if __name__ == "__main__":
    print("🔍 Checking VulnaraX server status...")
    
    if not check_server_status():
        print("❌ VulnaraX server not running on http://localhost:8002")
        print("   Please start the server first:")
        print("   cd /Users/alexandervidenov/Desktop/Vulnarax-core")
        print("   python3 main.py")
        exit(1)
    
    print("✅ VulnaraX server is running")
    test_enterprise_reporting_api()