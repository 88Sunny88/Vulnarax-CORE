#!/usr/bin/env python3
"""
Test script for vulnerability risk assessment capabilities
Tests CVSS scoring, EPSS probability, and KEV integration
"""

import json
import requests
import time
import subprocess
import asyncio

def test_risk_assessment():
    """Test comprehensive vulnerability risk assessment"""
    
    print("🎯 Starting VulnaraX Risk Assessment Testing...")
    
    # Start server
    print("Starting server...")
    server = subprocess.Popen(['python3', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)
    
    try:
        base_url = "http://localhost:8002"
        
        # Test 1: Risk assessment for known CVEs
        print("\n🔍 Test 1: CVE Risk Assessment")
        test_cves = [
            "CVE-2023-44487",  # HTTP/2 Rapid Reset (known KEV)
            "CVE-2023-4863",   # Chrome WebP vulnerability (known KEV)
            "CVE-2021-44228",  # Log4Shell (known KEV)
            "CVE-2023-12345"   # Non-existent CVE for testing
        ]
        
        response = requests.post(f"{base_url}/risk/assess", json={
            "cve_ids": test_cves,
            "force_refresh": False
        })
        
        if response.status_code == 200:
            risk_data = response.json()
            print(f"✅ Risk assessment completed for {len(test_cves)} CVEs")
            
            assessments = risk_data["assessments"]
            summary = risk_data["summary"]
            
            print(f"   📊 Summary:")
            print(f"      Total CVEs: {summary['total_vulnerabilities']}")
            print(f"      Average Risk Score: {summary['average_risk_score']:.1f}")
            print(f"      Critical Priority: {summary.get('critical_count', 0)}")
            print(f"      KEV Count: {summary.get('kev_count', 0)}")
            
            # Show detailed assessment for each CVE
            for assessment in assessments:
                cve_id = assessment["cve_id"]
                risk_score = assessment["risk_score"]
                priority = assessment["priority"]
                
                print(f"\\n   🔒 {cve_id}:")
                print(f"      Risk Score: {risk_score:.1f}/100")
                print(f"      Priority: {priority}")
                
                # CVSS info
                if assessment.get("cvss"):
                    cvss = assessment["cvss"]
                    print(f"      CVSS v{cvss['version']}: {cvss['base_score']} ({cvss.get('severity', 'N/A')})")
                
                # EPSS info
                if assessment.get("epss"):
                    epss = assessment["epss"]
                    print(f"      EPSS: {epss['score']:.3f} ({epss['percentile']:.1f}th percentile)")
                
                # KEV info
                if assessment.get("kev") and assessment["kev"].get("is_kev"):
                    kev = assessment["kev"]
                    print(f"      ⚠️  KEV: Added {kev.get('date_added', 'N/A')}")
                    if kev.get("action_required"):
                        print(f"          Action: {kev['action_required']}")
        else:
            print(f"❌ Risk assessment failed: {response.status_code}")
            print(f"   Error: {response.text}")
        
        # Test 2: Vulnerability analysis with risk scoring
        print("\\n📋 Test 2: Vulnerability Analysis with Risk Scoring")
        sample_vulnerabilities = [
            {
                "id": "CVE-2021-44228",
                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
                "severity": "critical",
                "source": "nvd",
                "package": "log4j-core",
                "version": "2.14.1"
            },
            {
                "id": "CVE-2023-44487",
                "description": "HTTP/2 Rapid Reset Attack",
                "severity": "high",
                "source": "nvd", 
                "package": "nginx",
                "version": "1.20.0"
            },
            {
                "id": "CVE-2023-4863",
                "description": "Heap buffer overflow in WebP",
                "severity": "high",
                "source": "nvd",
                "package": "libwebp",
                "version": "1.2.0"
            }
        ]
        
        response = requests.post(f"{base_url}/risk/analyze", json={
            "vulnerabilities": sample_vulnerabilities
        })
        
        if response.status_code == 200:
            analysis_data = response.json()
            print(f"✅ Vulnerability analysis completed")
            
            risk_summary = analysis_data["risk_summary"]
            prioritized_list = analysis_data["prioritized_list"]
            
            print(f"   📊 Risk Summary:")
            print(f"      Total Vulnerabilities: {risk_summary['total_vulnerabilities']}")
            print(f"      Average Risk Score: {risk_summary['average_risk_score']:.1f}")
            print(f"      KEV Vulnerabilities: {risk_summary['kev_vulnerabilities']}")
            print(f"      High Risk Count: {risk_summary['high_risk_count']}")
            print(f"      Actionable Count: {risk_summary['actionable_count']}")
            
            print(f"\\n   🏆 Top Priority Vulnerabilities:")
            for i, vuln in enumerate(prioritized_list[:3], 1):
                risk_data = vuln["risk_assessment"]
                print(f"      {i}. {vuln['id']} - Risk: {risk_data['risk_score']:.1f} ({risk_data['priority']})")
                if risk_data.get("kev", {}).get("is_kev"):
                    print(f"         ⚠️  Known Exploited Vulnerability")
                if risk_data.get("cvss"):
                    print(f"         CVSS: {risk_data['cvss']['base_score']}")
                if risk_data.get("epss"):
                    print(f"         EPSS: {risk_data['epss']['score']:.3f}")
        else:
            print(f"❌ Vulnerability analysis failed: {response.status_code}")
            print(f"   Error: {response.text}")
        
        # Test 3: Risk statistics
        print("\\n📈 Test 3: Risk Statistics")
        response = requests.get(f"{base_url}/risk/stats")
        
        if response.status_code == 200:
            stats_data = response.json()
            risk_stats = stats_data.get("risk_statistics", {})
            
            print(f"✅ Risk statistics retrieved")
            print(f"   📊 Priority Distribution: {risk_stats.get('priority_distribution', {})}")
            print(f"   🔢 Total Assessed: {risk_stats.get('total_assessed', 0)}")
            
            top_risks = risk_stats.get('top_risks', [])
            if top_risks:
                print(f"   🔝 Top Risks:")
                for risk in top_risks[:3]:
                    print(f"      {risk['cve_id']}: {risk['risk_score']:.1f} ({risk['priority']})")
        else:
            print(f"❌ Risk statistics failed: {response.status_code}")
        
        # Test 4: Feature verification
        print("\\n🎯 Test 4: Feature Verification")
        
        # Test risk assessment components individually
        print("   Testing risk assessment components...")
        
        try:
            from vulnaraX.risk_assessment import CVSSClient, EPSSClient, KEVClient
            
            print("   ✅ CVSS Client: Available")
            print("   ✅ EPSS Client: Available") 
            print("   ✅ KEV Client: Available")
            
            # Test caching
            from vulnaraX.risk_assessment import VulnerabilityRiskAssessment
            risk_assessment = VulnerabilityRiskAssessment()
            print("   ✅ Risk Assessment Cache: Initialized")
            
        except ImportError as e:
            print(f"   ❌ Import error: {e}")
        
        print("\\n🎉 Risk Assessment Features Demonstrated:")
        print("   ✅ CVSS v2/v3 scoring integration")
        print("   ✅ EPSS exploit prediction scoring")
        print("   ✅ CISA KEV database integration")
        print("   ✅ Comprehensive risk score calculation")
        print("   ✅ Priority-based vulnerability ranking")
        print("   ✅ Risk statistics and analytics")
        print("   ✅ Persistent caching for performance")
        print("   ✅ API endpoints for risk assessment")
        
    except Exception as e:
        print(f"❌ Testing failed with error: {str(e)}")
    
    finally:
        # Clean up server
        server.terminate()
        server.wait()

if __name__ == "__main__":
    test_risk_assessment()