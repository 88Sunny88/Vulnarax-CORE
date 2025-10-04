import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import re

@dataclass
class LicenseInfo:
    """License information for a package"""
    spdx_id: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    text: Optional[str] = None
    confidence: float = 0.0

@dataclass
class PackageInfo:
    """Enhanced package information for SBOM"""
    name: str
    version: str
    purl: str  # Package URL (PURL) - universal package identifier
    ecosystem: str
    supplier: Optional[str] = None
    download_location: Optional[str] = None
    files_analyzed: bool = False
    verification_code: Optional[str] = None
    license_info: Optional[LicenseInfo] = None
    copyright_text: Optional[str] = None
    dependencies: List[str] = None  # List of dependency PURLs
    vulnerabilities: List[Dict] = None
    checksum: Optional[str] = None
    source_info: Optional[str] = None

@dataclass
class SBOMMetadata:
    """SBOM metadata and document info"""
    spdx_version: str = "SPDX-2.3"
    data_license: str = "CC0-1.0"
    document_id: str = None
    name: str = "VulnaraX-SBOM"
    document_namespace: str = None
    created: str = None
    tool: str = "VulnaraX-Core"
    tool_version: str = "1.0.0"

class LicenseDetector:
    """Detect licenses from package metadata and files"""
    
    # Common license patterns
    LICENSE_PATTERNS = {
        'MIT': [
            r'MIT\s+License',
            r'Permission is hereby granted, free of charge',
            r'MIT/X11',
            r'MIT-style'
        ],
        'Apache-2.0': [
            r'Apache License,?\s*Version 2\.0',
            r'Licensed under the Apache License',
            r'Apache-2\.0'
        ],
        'GPL-3.0': [
            r'GNU GENERAL PUBLIC LICENSE\s*Version 3',
            r'GPL-?3\.0',
            r'GPLv3'
        ],
        'GPL-2.0': [
            r'GNU GENERAL PUBLIC LICENSE\s*Version 2',
            r'GPL-?2\.0',
            r'GPLv2'
        ],
        'BSD-3-Clause': [
            r'BSD 3-Clause',
            r'Redistribution and use in source and binary forms',
            r'BSD-3-Clause'
        ],
        'BSD-2-Clause': [
            r'BSD 2-Clause',
            r'BSD-2-Clause'
        ],
        'ISC': [
            r'ISC License',
            r'Permission to use, copy, modify, and/or distribute'
        ],
        'LGPL-2.1': [
            r'GNU Lesser General Public License.*version 2\.1',
            r'LGPL-?2\.1'
        ],
        'LGPL-3.0': [
            r'GNU Lesser General Public License.*version 3',
            r'LGPL-?3\.0'
        ]
    }
    
    def detect_license(self, text: str, package_name: str = None) -> LicenseInfo:
        """Detect license from text content"""
        if not text:
            return LicenseInfo()
        
        text_upper = text.upper()
        best_match = None
        highest_confidence = 0.0
        
        for spdx_id, patterns in self.LICENSE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    confidence = 0.8  # High confidence for pattern match
                    if confidence > highest_confidence:
                        highest_confidence = confidence
                        best_match = spdx_id
        
        # Check for common license files
        if package_name:
            license_keywords = ['license', 'licence', 'copying', 'copyright']
            for keyword in license_keywords:
                if keyword.lower() in text.lower():
                    if not best_match:
                        highest_confidence = 0.3  # Low confidence without pattern
        
        return LicenseInfo(
            spdx_id=best_match,
            name=best_match.replace('-', ' ') if best_match else None,
            confidence=highest_confidence
        )

class PURLGenerator:
    """Generate Package URLs (PURLs) for different ecosystems"""
    
    @staticmethod
    def generate_purl(ecosystem: str, name: str, version: str, 
                      namespace: Optional[str] = None, 
                      qualifiers: Optional[Dict[str, str]] = None) -> str:
        """Generate a PURL (Package URL) for a package"""
        # Normalize ecosystem
        ecosystem_map = {
            'python': 'pypi',
            'java': 'maven',
            'javascript': 'npm',
            'node': 'npm',
            'go': 'golang',
            'docker': 'docker'
        }
        
        normalized_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
        
        # Build PURL
        purl = f"pkg:{normalized_ecosystem}/"
        
        if namespace:
            purl += f"{namespace}/"
        
        purl += f"{name}@{version}"
        
        if qualifiers:
            qual_string = "&".join([f"{k}={v}" for k, v in qualifiers.items()])
            purl += f"?{qual_string}"
        
        return purl

class SBOMGenerator:
    """Generate comprehensive SPDX SBOM documents"""
    
    def __init__(self):
        self.license_detector = LicenseDetector()
        self.purl_generator = PURLGenerator()
    
    def _generate_checksum(self, content: str) -> str:
        """Generate SHA256 checksum"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _create_document_namespace(self, project_name: str) -> str:
        """Create unique document namespace"""
        timestamp = datetime.now(timezone.utc).isoformat()
        return f"https://vulnarax.io/sbom/{project_name}-{uuid.uuid4()}"
    
    def enhance_package_info(self, packages: List[Dict], ecosystem: str, 
                           project_path: Optional[str] = None) -> List[PackageInfo]:
        """Enhance basic package info with SBOM metadata"""
        enhanced_packages = []
        
        for pkg in packages:
            name = pkg.get('name', '')
            version = pkg.get('version', '')
            
            # Generate PURL
            purl = self.purl_generator.generate_purl(ecosystem, name, version)
            
            # Detect license (this would be enhanced with actual file scanning)
            license_info = self._detect_package_license(pkg, ecosystem)
            
            # Create enhanced package info
            package_info = PackageInfo(
                name=name,
                version=version,
                purl=purl,
                ecosystem=ecosystem,
                supplier=self._get_supplier_info(pkg, ecosystem),
                download_location=self._get_download_location(pkg, ecosystem),
                license_info=license_info,
                dependencies=self._extract_dependencies(pkg),
                vulnerabilities=pkg.get('vulnerabilities', []),
                checksum=pkg.get('checksum'),
                source_info=pkg.get('source_info')
            )
            
            enhanced_packages.append(package_info)
        
        return enhanced_packages
    
    def _detect_package_license(self, pkg: Dict, ecosystem: str) -> LicenseInfo:
        """Detect license for a package"""
        # Check if license info is already available
        if 'license' in pkg:
            license_text = str(pkg['license'])
            return self.license_detector.detect_license(license_text, pkg.get('name'))
        
        # Default license detection based on ecosystem patterns
        name = pkg.get('name', '').lower()
        
        # Common patterns for popular packages
        if ecosystem == 'python':
            if any(x in name for x in ['django', 'flask', 'requests']):
                return LicenseInfo(spdx_id='BSD-3-Clause', confidence=0.6)
            elif 'apache' in name:
                return LicenseInfo(spdx_id='Apache-2.0', confidence=0.6)
        
        return LicenseInfo()
    
    def _get_supplier_info(self, pkg: Dict, ecosystem: str) -> Optional[str]:
        """Get supplier/maintainer information"""
        if ecosystem == 'python' and 'author' in pkg:
            return pkg['author']
        elif ecosystem == 'java' and 'organization' in pkg:
            return pkg['organization']
        elif ecosystem == 'npm' and 'author' in pkg:
            return pkg['author']
        return None
    
    def _get_download_location(self, pkg: Dict, ecosystem: str) -> Optional[str]:
        """Get package download location"""
        name = pkg.get('name', '')
        version = pkg.get('version', '')
        
        if ecosystem == 'python':
            return f"https://pypi.org/project/{name}/{version}/"
        elif ecosystem == 'java':
            group_id = pkg.get('group_id', 'unknown')
            return f"https://mvnrepository.com/artifact/{group_id}/{name}/{version}"
        elif ecosystem == 'npm':
            return f"https://www.npmjs.com/package/{name}/v/{version}"
        elif ecosystem == 'go':
            return f"https://pkg.go.dev/{name}@{version}"
        
        return None
    
    def _extract_dependencies(self, pkg: Dict) -> List[str]:
        """Extract dependency PURLs"""
        dependencies = []
        
        if 'dependencies' in pkg:
            for dep in pkg['dependencies']:
                if isinstance(dep, dict):
                    dep_name = dep.get('name', '')
                    dep_version = dep.get('version', '')
                    ecosystem = dep.get('ecosystem', 'unknown')
                    
                    if dep_name and dep_version:
                        purl = self.purl_generator.generate_purl(ecosystem, dep_name, dep_version)
                        dependencies.append(purl)
        
        return dependencies
    
    def generate_spdx_sbom(self, packages: List[PackageInfo], project_name: str,
                          project_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate SPDX-format SBOM"""
        
        # Create metadata
        doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"
        metadata = SBOMMetadata(
            document_id=doc_id,
            name=f"{project_name}-SBOM",
            document_namespace=self._create_document_namespace(project_name),
            created=datetime.now(timezone.utc).isoformat()
        )
        
        # Build SPDX document
        sbom = {
            "spdxVersion": metadata.spdx_version,
            "dataLicense": metadata.data_license,
            "SPDXID": metadata.document_id,
            "name": metadata.name,
            "documentNamespace": metadata.document_namespace,
            "creationInfo": {
                "created": metadata.created,
                "creators": [f"Tool: {metadata.tool}-{metadata.tool_version}"],
                "licenseListVersion": "3.21"
            },
            "packages": [],
            "relationships": []
        }
        
        # Add root package
        root_package = {
            "SPDXID": "SPDXRef-Package-Root",
            "name": project_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION"
        }
        sbom["packages"].append(root_package)
        
        # Add packages
        for i, pkg in enumerate(packages):
            spdx_id = f"SPDXRef-Package-{i+1}"
            
            package_entry = {
                "SPDXID": spdx_id,
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": pkg.download_location or "NOASSERTION",
                "filesAnalyzed": pkg.files_analyzed,
                "copyrightText": pkg.copyright_text or "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE_MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": pkg.purl
                    }
                ]
            }
            
            # Add license info
            if pkg.license_info and pkg.license_info.spdx_id:
                package_entry["licenseConcluded"] = pkg.license_info.spdx_id
                package_entry["licenseDeclared"] = pkg.license_info.spdx_id
            else:
                package_entry["licenseConcluded"] = "NOASSERTION"
                package_entry["licenseDeclared"] = "NOASSERTION"
            
            # Add supplier
            if pkg.supplier:
                package_entry["supplier"] = f"Person: {pkg.supplier}"
            
            # Add checksum
            if pkg.checksum:
                package_entry["checksums"] = [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": pkg.checksum
                    }
                ]
            
            sbom["packages"].append(package_entry)
            
            # Add relationship to root
            sbom["relationships"].append({
                "spdxElementId": "SPDXRef-Package-Root",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id
            })
            
            # Add dependency relationships
            if pkg.dependencies:
                for dep_purl in pkg.dependencies:
                    # Find dependency in packages list
                    for j, dep_pkg in enumerate(packages):
                        if dep_pkg.purl == dep_purl:
                            dep_spdx_id = f"SPDXRef-Package-{j+1}"
                            sbom["relationships"].append({
                                "spdxElementId": spdx_id,
                                "relationshipType": "DEPENDS_ON",
                                "relatedSpdxElement": dep_spdx_id
                            })
                            break
        
        return sbom
    
    def generate_cyclone_dx_sbom(self, packages: List[PackageInfo], project_name: str) -> Dict[str, Any]:
        """Generate CycloneDX-format SBOM"""
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "VulnaraX",
                        "name": "VulnaraX-Core",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "1.0.0"
                }
            },
            "components": []
        }
        
        # Add components
        for pkg in packages:
            component = {
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": pkg.purl,
                "scope": "required"
            }
            
            # Add license
            if pkg.license_info and pkg.license_info.spdx_id:
                component["licenses"] = [
                    {
                        "license": {
                            "id": pkg.license_info.spdx_id
                        }
                    }
                ]
            
            # Add supplier
            if pkg.supplier:
                component["supplier"] = {
                    "name": pkg.supplier
                }
            
            # Add external references
            if pkg.download_location:
                component["externalReferences"] = [
                    {
                        "type": "distribution",
                        "url": pkg.download_location
                    }
                ]
            
            # Add vulnerabilities
            if pkg.vulnerabilities:
                component["vulnerabilities"] = []
                for vuln in pkg.vulnerabilities:
                    vuln_entry = {
                        "id": vuln.get('id', ''),
                        "source": {
                            "name": vuln.get('source', 'unknown')
                        }
                    }
                    
                    if 'severity' in vuln:
                        vuln_entry["severity"] = vuln['severity']
                    
                    if 'description' in vuln:
                        vuln_entry["description"] = vuln['description']
                    
                    component["vulnerabilities"].append(vuln_entry)
            
            sbom["components"].append(component)
        
        return sbom

# Export functions for easy use
def generate_enhanced_sbom(packages: List[Dict], ecosystem: str, project_name: str,
                          format: str = "spdx", project_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate enhanced SBOM with license detection and dependency relationships
    
    Args:
        packages: List of package dictionaries
        ecosystem: Package ecosystem (python, java, go, etc.)
        project_name: Name of the project
        format: SBOM format ('spdx' or 'cyclonedx')
        project_path: Optional path to project for file analysis
    
    Returns:
        SBOM document as dictionary
    """
    generator = SBOMGenerator()
    
    # Enhance package information
    enhanced_packages = generator.enhance_package_info(packages, ecosystem, project_path)
    
    # Generate SBOM in requested format
    if format.lower() == 'cyclonedx':
        return generator.generate_cyclone_dx_sbom(enhanced_packages, project_name)
    else:
        return generator.generate_spdx_sbom(enhanced_packages, project_name, project_path)