#!/usr/bin/env python3
"""
Test script for enhanced SBOM generation capabilities
Tests license detection, dependency relationships, and SBOM formats
"""

import json
import requests
import time
import subprocess

def test_sbom_generation():
    """Test enhanced SBOM generation functionality"""
    
    print("🔧 Starting VulnaraX Enhanced SBOM Testing...")
    
    # Start server
    print("Starting server...")
    server = subprocess.Popen(['python3', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)
    
    try:
        base_url = "http://localhost:8002"
        
        # Test 1: Generate SPDX SBOM for Java project
        print("\n📋 Test 1: Java Project SPDX SBOM Generation")
        response = requests.post(f"{base_url}/sbom/generate", json={
            "project_path": "./test-java-project",
            "project_name": "test-java-app",
            "ecosystem": "java",
            "format": "spdx"
        })
        
        if response.status_code == 200:
            java_sbom = response.json()
            print(f"✅ Java SPDX SBOM generated successfully")
            print(f"   📦 Packages: {java_sbom['package_count']}")
            print(f"   🔒 Vulnerabilities: {java_sbom['vulnerability_count']}")
            print(f"   📄 Format: {java_sbom['format']}")
            
            # Check SPDX structure
            sbom_doc = java_sbom['sbom']
            print(f"   🆔 SPDX Version: {sbom_doc.get('spdxVersion')}")
            print(f"   📚 Packages in SBOM: {len(sbom_doc.get('packages', []))}")
            print(f"   🔗 Relationships: {len(sbom_doc.get('relationships', []))}")
            
            # Show some package details
            packages = sbom_doc.get('packages', [])
            if len(packages) > 1:  # Skip root package
                sample_pkg = packages[1]
                print(f"   📋 Sample Package: {sample_pkg.get('name')} {sample_pkg.get('versionInfo')}")
                if 'externalRefs' in sample_pkg:
                    purl = next((ref['referenceLocator'] for ref in sample_pkg['externalRefs'] 
                               if ref['referenceType'] == 'purl'), None)
                    print(f"   🔗 PURL: {purl}")
        else:
            print(f"❌ Java SBOM generation failed: {response.status_code}")
            print(f"   Error: {response.text}")
        
        # Test 2: Generate CycloneDX SBOM for Go project
        print("\n📋 Test 2: Go Project CycloneDX SBOM Generation")
        response = requests.post(f"{base_url}/sbom/generate", json={
            "project_path": "./test-go-project",
            "project_name": "test-go-app",
            "ecosystem": "go",
            "format": "cyclonedx"
        })
        
        if response.status_code == 200:
            go_sbom = response.json()
            print(f"✅ Go CycloneDX SBOM generated successfully")
            print(f"   📦 Packages: {go_sbom['package_count']}")
            print(f"   🔒 Vulnerabilities: {go_sbom['vulnerability_count']}")
            print(f"   📄 Format: {go_sbom['format']}")
            
            # Check CycloneDX structure
            sbom_doc = go_sbom['sbom']
            print(f"   🆔 BOM Format: {sbom_doc.get('bomFormat')}")
            print(f"   📚 Components: {len(sbom_doc.get('components', []))}")
            
            # Show some component details
            components = sbom_doc.get('components', [])
            if components:
                sample_comp = components[0]
                print(f"   📋 Sample Component: {sample_comp.get('name')} {sample_comp.get('version')}")
                print(f"   🔗 PURL: {sample_comp.get('purl')}")
                if 'licenses' in sample_comp:
                    print(f"   📜 License: {sample_comp['licenses'][0]['license']['id']}")
        else:
            print(f"❌ Go SBOM generation failed: {response.status_code}")
            print(f"   Error: {response.text}")
        
        # Test 3: Generate SBOM from package list (simulated Python packages)
        print("\n📋 Test 3: SBOM from Package List (Python)")
        sample_packages = [
            {
                "name": "requests",
                "version": "2.28.1",
                "ecosystem": "python",
                "license": "Apache License 2.0",
                "author": "Kenneth Reitz",
                "vulnerabilities": []
            },
            {
                "name": "django",
                "version": "4.1.0", 
                "ecosystem": "python",
                "license": "BSD-3-Clause",
                "author": "Django Software Foundation",
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-12345",
                        "severity": "medium",
                        "description": "Example vulnerability"
                    }
                ]
            },
            {
                "name": "numpy",
                "version": "1.24.0",
                "ecosystem": "python",
                "license": "BSD",
                "vulnerabilities": []
            }
        ]
        
        response = requests.post(f"{base_url}/sbom/from-packages", json={
            "packages": sample_packages,
            "project_name": "test-python-app",
            "ecosystem": "python",
            "format": "spdx"
        })
        
        if response.status_code == 200:
            python_sbom = response.json()
            print(f"✅ Python SBOM from packages generated successfully")
            print(f"   📦 Packages: {python_sbom['package_count']}")
            print(f"   🔒 Vulnerabilities: {python_sbom['vulnerability_count']}")
            
            # Check license detection
            sbom_doc = python_sbom['sbom']
            packages = sbom_doc.get('packages', [])
            for pkg in packages[1:]:  # Skip root package
                pkg_name = pkg.get('name')
                license_concluded = pkg.get('licenseConcluded', 'NOASSERTION')
                print(f"   📜 {pkg_name}: {license_concluded}")
        else:
            print(f"❌ Python SBOM generation failed: {response.status_code}")
            print(f"   Error: {response.text}")
        
        # Test 4: Verify license detection
        print("\n🔍 Test 4: License Detection Verification")
        from vulnaraX.sbom_generator import LicenseDetector
        
        detector = LicenseDetector()
        
        # Test various license texts
        test_cases = [
            ("MIT License", "MIT"),
            ("Apache License, Version 2.0", "Apache-2.0"),
            ("GNU GENERAL PUBLIC LICENSE Version 3", "GPL-3.0"),
            ("BSD 3-Clause License", "BSD-3-Clause"),
            ("ISC License", "ISC")
        ]
        
        for text, expected_spdx in test_cases:
            license_info = detector.detect_license(text)
            if license_info.spdx_id == expected_spdx:
                print(f"   ✅ {text} → {license_info.spdx_id} (confidence: {license_info.confidence})")
            else:
                print(f"   ❌ {text} → {license_info.spdx_id} (expected: {expected_spdx})")
        
        # Test 5: PURL generation
        print("\n🔗 Test 5: PURL Generation Verification")
        from vulnaraX.sbom_generator import PURLGenerator
        
        generator = PURLGenerator()
        test_purls = [
            ("python", "requests", "2.28.1", None, "pkg:pypi/requests@2.28.1"),
            ("java", "spring-boot", "2.7.0", "org.springframework.boot", "pkg:maven/org.springframework.boot/spring-boot@2.7.0"),
            ("go", "github.com/gin-gonic/gin", "v1.8.1", None, "pkg:golang/github.com/gin-gonic/gin@v1.8.1"),
            ("npm", "express", "4.18.0", None, "pkg:npm/express@4.18.0")
        ]
        
        for ecosystem, name, version, namespace, expected in test_purls:
            if namespace:
                purl = generator.generate_purl(ecosystem, name, version, namespace)
            else:
                purl = generator.generate_purl(ecosystem, name, version)
            
            if purl == expected:
                print(f"   ✅ {ecosystem}: {purl}")
            else:
                print(f"   ❌ {ecosystem}: {purl} (expected: {expected})")
        
        print("\n🎉 Enhanced SBOM testing completed!")
        
    except Exception as e:
        print(f"❌ Testing failed with error: {str(e)}")
    
    finally:
        # Clean up server
        server.terminate()
        server.wait()

if __name__ == "__main__":
    test_sbom_generation()