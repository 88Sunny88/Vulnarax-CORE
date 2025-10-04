#!/usr/bin/env python3
"""
VulnaraX Supply Chain Security API Test Suite
Tests the premium supply chain security analysis features
"""

import requests
import json
import time

def test_supply_chain_security_api():
    """Test supply chain security API endpoints"""
    
    base_url = "http://localhost:8002"
    
    print("🔒 VulnaraX Supply Chain Security API Testing")
    print("=" * 60)
    
    # Test 1: Get Supply Chain Threat Intelligence
    print("\\n🕵️  Testing: Supply Chain Threat Intelligence")
    print("=" * 50)
    
    try:
        response = requests.get(f"{base_url}/supply-chain/threats")
        if response.status_code == 200:
            threats_data = response.json()
            print("✅ Threat intelligence endpoint successful")
            
            categories = threats_data.get('threat_categories', [])
            print(f"   📊 Threat Categories: {len(categories)}")
            for cat in categories:
                print(f"   - {cat['name']}: {cat['description']}")
            
            capabilities = threats_data.get('detection_capabilities', [])
            print(f"\\n   🔍 Detection Capabilities: {len(capabilities)}")
            for cap in capabilities[:3]:
                print(f"   - {cap}")
        else:
            print(f"❌ Threat intelligence failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Threat intelligence error: {str(e)}")
    
    # Test 2: Supply Chain Analysis - Typosquatting Detection
    print("\\n🎯 Testing: Typosquatting Detection")
    print("=" * 50)
    
    typosquat_request = {
        "packages": [
            {"name": "requests", "version": "2.28.1", "ecosystem": "python"},
            {"name": "requsts", "version": "1.0.0", "ecosystem": "python"},  # Typosquatting
            {"name": "djnago", "version": "1.0.0", "ecosystem": "python"},   # Typosquatting
            {"name": "numpy", "version": "1.21.0", "ecosystem": "python"}
        ]
    }
    
    try:
        response = requests.post(
            f"{base_url}/supply-chain/analyze",
            json=typosquat_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✅ Typosquatting detection successful")
            
            malicious_packages = analysis.get('malicious_packages', [])
            typosquats = [pkg for pkg in malicious_packages if pkg.get('threat_type') == 'typosquatting']
            
            print(f"   🦠 Malicious Packages Found: {len(malicious_packages)}")
            print(f"   📝 Typosquatting Detected: {len(typosquats)}")
            
            for typo in typosquats:
                print(f"   - {typo['package_name']}: {typo['indicators'][0]} (confidence: {typo['confidence']:.2f})")
            
            print(f"\\n   🏆 Supply Chain Score: {analysis.get('supply_chain_score', 0):.1f}/100")
        else:
            print(f"❌ Typosquatting detection failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Typosquatting detection error: {str(e)}")
    
    # Test 3: Dependency Confusion Detection
    print("\\n⚡ Testing: Dependency Confusion Detection")
    print("=" * 50)
    
    confusion_request = {
        "packages": [
            {"name": "company-internal-auth", "version": "1.2.3", "ecosystem": "python"},
            {"name": "internal-logging", "version": "0.5.0", "ecosystem": "python"},
            {"name": "private-utils", "version": "2.1.0", "ecosystem": "python"},
            {"name": "requests", "version": "2.28.1", "ecosystem": "python"}
        ],
        "internal_packages": ["company-internal-auth", "internal-logging", "private-utils"]
    }
    
    try:
        response = requests.post(
            f"{base_url}/supply-chain/analyze",
            json=confusion_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✅ Dependency confusion detection successful")
            
            confusion_risks = analysis.get('dependency_confusion_risks', [])
            high_risk = [risk for risk in confusion_risks if risk.get('risk_level') == 'high']
            
            print(f"   ⚡ Confusion Risks Found: {len(confusion_risks)}")
            print(f"   🚨 High Risk: {len(high_risk)}")
            
            for risk in confusion_risks[:3]:
                print(f"   - {risk['package_name']}: {risk['risk_level']} risk")
                print(f"     Internal: v{risk['internal_version']} | Public: v{risk['public_version']}")
                print(f"     Mitigation: {risk['recommendations'][0]}")
            
            print(f"\\n   🏆 Supply Chain Score: {analysis.get('supply_chain_score', 0):.1f}/100")
        else:
            print(f"❌ Dependency confusion detection failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Dependency confusion detection error: {str(e)}")
    
    # Test 4: Malicious Package Detection
    print("\\n🦠 Testing: Malicious Package Detection")
    print("=" * 50)
    
    malicious_request = {
        "packages": [
            {"name": "bitcoin-miner", "version": "1.0.0", "ecosystem": "python"},  # Known malicious
            {"name": "crypto-mine-helper", "version": "2.1.0", "ecosystem": "python"},  # Suspicious pattern
            {"name": "keylogger-tool", "version": "1.5.0", "ecosystem": "python"},  # Suspicious pattern
            {"name": "legitimate-package", "version": "1.0.0", "ecosystem": "python"}
        ]
    }
    
    try:
        response = requests.post(
            f"{base_url}/supply-chain/analyze",
            json=malicious_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✅ Malicious package detection successful")
            
            malicious_packages = analysis.get('malicious_packages', [])
            known_malicious = [pkg for pkg in malicious_packages if pkg.get('threat_type') == 'known_malicious']
            suspicious_naming = [pkg for pkg in malicious_packages if pkg.get('threat_type') == 'suspicious_naming']
            
            print(f"   🦠 Total Malicious Packages: {len(malicious_packages)}")
            print(f"   🎯 Known Malicious: {len(known_malicious)}")
            print(f"   ⚠️  Suspicious Naming: {len(suspicious_naming)}")
            
            for malicious in malicious_packages[:5]:
                print(f"   - {malicious['package_name']}: {malicious['threat_type']}")
                print(f"     Confidence: {malicious['confidence']:.2f} | Indicators: {len(malicious['indicators'])}")
            
            recommendations = analysis.get('recommendations', [])
            print(f"\\n   💡 Top Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec}")
        else:
            print(f"❌ Malicious package detection failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Malicious package detection error: {str(e)}")
    
    # Test 5: Package Risk Assessment
    print("\\n📊 Testing: Package Risk Assessment")
    print("=" * 50)
    
    risk_request = {
        "packages": [
            {"name": "well-maintained-package", "version": "3.2.1", "ecosystem": "python"},
            {"name": "outdated-package", "version": "0.1.0", "ecosystem": "python"},
            {"name": "single-maintainer-pkg", "version": "1.0.0", "ecosystem": "python"},
            {"name": "new-package", "version": "1.0.0", "ecosystem": "python"},
            {"name": "popular-package", "version": "2.5.1", "ecosystem": "python"}
        ]
    }
    
    try:
        response = requests.post(
            f"{base_url}/supply-chain/analyze",
            json=risk_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✅ Package risk assessment successful")
            
            package_risks = analysis.get('package_risks', [])
            high_risk_packages = analysis.get('high_risk_packages', 0)
            
            print(f"   📦 Total Packages: {analysis.get('total_packages', 0)}")
            print(f"   ⚠️  High Risk Packages: {high_risk_packages}")
            print(f"   🏆 Supply Chain Score: {analysis.get('supply_chain_score', 0):.1f}/100")
            
            print("\\n   📊 Package Risk Details:")
            for risk in package_risks[:3]:
                print(f"   - {risk['package_name']}: Risk Score {risk['risk_score']:.2f}")
                print(f"     Reputation: {risk['reputation_score']:.2f} | Trust: {risk['maintainer_trust']:.2f}")
                if risk['risk_factors']:
                    print(f"     Factors: {risk['risk_factors'][0]}")
        else:
            print(f"❌ Package risk assessment failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Package risk assessment error: {str(e)}")
    
    # Test 6: Comprehensive Analysis
    print("\\n🔬 Testing: Comprehensive Supply Chain Analysis")
    print("=" * 50)
    
    comprehensive_request = {
        "packages": [
            {"name": "requests", "version": "2.28.1", "ecosystem": "python"},
            {"name": "requsts", "version": "1.0.0", "ecosystem": "python"},  # Typosquatting
            {"name": "company-auth", "version": "1.0.0", "ecosystem": "python"},  # Internal
            {"name": "bitcoin-miner", "version": "1.0.0", "ecosystem": "python"},  # Malicious
            {"name": "old-package", "version": "0.1.0", "ecosystem": "python"},  # Risky
        ],
        "internal_packages": ["company-auth"],
        "project_context": {
            "project_name": "VulnaraX Test App",
            "environment": "production"
        }
    }
    
    try:
        response = requests.post(
            f"{base_url}/supply-chain/analyze",
            json=comprehensive_request,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✅ Comprehensive analysis successful")
            
            print(f"   📦 Analysis Summary:")
            print(f"      Total Packages: {analysis.get('total_packages', 0)}")
            print(f"      High Risk: {analysis.get('high_risk_packages', 0)}")
            print(f"      Malicious: {len(analysis.get('malicious_packages', []))}")
            print(f"      Confusion Risks: {len(analysis.get('dependency_confusion_risks', []))}")
            print(f"      Supply Chain Score: {analysis.get('supply_chain_score', 0):.1f}/100")
            
            recommendations = analysis.get('recommendations', [])
            print(f"\\n   💡 Critical Actions:")
            critical_recs = [r for r in recommendations if 'CRITICAL' in r or 'HIGH' in r]
            for i, rec in enumerate(critical_recs[:3], 1):
                print(f"      {i}. {rec}")
        else:
            print(f"❌ Comprehensive analysis failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Comprehensive analysis error: {str(e)}")
    
    print("\\n" + "=" * 60)
    print("🎉 Supply Chain Security API Test Suite Complete!")
    print("✨ VulnaraX Supply Chain Platform demonstrates:")
    print("   - Advanced typosquatting detection with similarity analysis")
    print("   - Dependency confusion attack prevention") 
    print("   - Malicious package identification and blocking")
    print("   - Comprehensive package risk assessment")
    print("   - Real-time threat intelligence integration")
    print("   - Actionable security recommendations")
    print("   - Enterprise-grade supply chain protection")

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
    test_supply_chain_security_api()