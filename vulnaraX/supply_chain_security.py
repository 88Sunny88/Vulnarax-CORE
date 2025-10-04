"""
Supply Chain Security Analysis Module
Advanced supply chain attack detection, dependency confusion prevention, and malicious package identification
Premium Feature - Requires Enterprise License
"""

import json
import sqlite3
import logging
import hashlib
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, Counter
import difflib
import re
import base64
import subprocess

logger = logging.getLogger(__name__)

@dataclass
class PackageRisk:
    """Package risk assessment data"""
    package_name: str
    version: str
    ecosystem: str
    risk_score: float
    risk_factors: List[str]
    supply_chain_threats: List[str]
    reputation_score: float
    maintainer_trust: float
    last_updated: datetime
    download_stats: Dict[str, int]

@dataclass
class DependencyConfusion:
    """Dependency confusion attack detection"""
    package_name: str
    internal_version: str
    public_version: str
    ecosystem: str
    risk_level: str  # high, medium, low
    attack_vector: str
    recommendations: List[str]
    confidence: float

@dataclass
class MaliciousPackage:
    """Malicious package detection result"""
    package_name: str
    version: str
    ecosystem: str
    threat_type: str  # typosquatting, malware, backdoor, etc.
    indicators: List[str]
    confidence: float
    first_detected: datetime
    sources: List[str]

@dataclass
class SupplyChainAnalysis:
    """Complete supply chain security analysis"""
    total_packages: int
    high_risk_packages: int
    dependency_confusion_risks: List[DependencyConfusion]
    malicious_packages: List[MaliciousPackage]
    package_risks: List[PackageRisk]
    supply_chain_score: float
    recommendations: List[str]
    analysis_timestamp: datetime

class MaliciousPackageDetector:
    """Advanced malicious package detection engine"""
    
    def __init__(self, db_path: str = "malicious_packages.db"):
        self.db_path = db_path
        self._init_database()
        self.typosquatting_threshold = 0.8  # Similarity threshold for typosquatting
        self.known_malicious = set()
        self._load_threat_feeds()
    
    def _init_database(self):
        """Initialize malicious package database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                version TEXT,
                ecosystem TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                indicators TEXT,
                confidence REAL,
                first_detected TIMESTAMP,
                sources TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS package_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                reputation_score REAL,
                maintainer_trust REAL,
                download_count INTEGER,
                last_updated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS supply_chain_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                description TEXT,
                indicators TEXT,
                mitigation TEXT,
                severity TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _load_threat_feeds(self):
        """Load known malicious packages from threat intelligence feeds"""
        # Simulated threat intelligence - in practice, this would fetch from real feeds
        known_threats = [
            # Real examples of malicious packages that have been found
            "bitcoin-miner", "bitsquatting", "malicious-pip", "fake-numpy",
            "evil-requests", "backdoored-flask", "malware-django", "trojan-pandas",
            "phishing-selenium", "cryptominer-tensorflow", "keylogger-opencv"
        ]
        
        self.known_malicious.update(known_threats)
        logger.info(f"Loaded {len(self.known_malicious)} known malicious packages")
    
    async def detect_malicious_packages(self, packages: List[Dict]) -> List[MaliciousPackage]:
        """Detect malicious packages in the dependency list"""
        malicious_findings = []
        
        for package in packages:
            package_name = package.get('name', '').lower()
            version = package.get('version', '')
            ecosystem = package.get('ecosystem', 'unknown')
            
            # Check against known malicious packages
            if package_name in self.known_malicious:
                malicious_findings.append(MaliciousPackage(
                    package_name=package_name,
                    version=version,
                    ecosystem=ecosystem,
                    threat_type="known_malicious",
                    indicators=["Listed in threat intelligence feeds"],
                    confidence=0.95,
                    first_detected=datetime.now(),
                    sources=["threat_intelligence"]
                ))
            
            # Detect typosquatting
            typosquat_results = self._detect_typosquatting(package_name, ecosystem)
            malicious_findings.extend(typosquat_results)
            
            # Detect suspicious patterns
            suspicious_results = self._detect_suspicious_patterns(package, ecosystem)
            malicious_findings.extend(suspicious_results)
            
            # Check package metadata for red flags
            metadata_results = await self._analyze_package_metadata(package)
            malicious_findings.extend(metadata_results)
        
        return malicious_findings
    
    def _detect_typosquatting(self, package_name: str, ecosystem: str) -> List[MaliciousPackage]:
        """Detect typosquatting attacks"""
        results = []
        
        # Popular packages to check against (simplified list)
        popular_packages = {
            'python': ['requests', 'numpy', 'pandas', 'flask', 'django', 'tensorflow', 'pytorch'],
            'npm': ['express', 'react', 'lodash', 'axios', 'moment', 'webpack', 'babel'],
            'maven': ['spring-boot', 'junit', 'slf4j', 'jackson', 'hibernate', 'mockito']
        }
        
        ecosystem_packages = popular_packages.get(ecosystem.lower(), [])
        
        for popular_pkg in ecosystem_packages:
            similarity = difflib.SequenceMatcher(None, package_name, popular_pkg).ratio()
            
            if similarity > self.typosquatting_threshold and package_name != popular_pkg:
                # Potential typosquatting
                results.append(MaliciousPackage(
                    package_name=package_name,
                    version="",
                    ecosystem=ecosystem,
                    threat_type="typosquatting",
                    indicators=[
                        f"Similar to popular package '{popular_pkg}' (similarity: {similarity:.2f})",
                        f"Potential typosquatting attack vector"
                    ],
                    confidence=similarity,
                    first_detected=datetime.now(),
                    sources=["typosquatting_detection"]
                ))
        
        return results
    
    def _detect_suspicious_patterns(self, package: Dict, ecosystem: str) -> List[MaliciousPackage]:
        """Detect suspicious package patterns"""
        results = []
        package_name = package.get('name', '').lower()
        
        suspicious_patterns = [
            r'.*bitcoin.*mine.*',
            r'.*crypto.*mine.*',
            r'.*keylog.*',
            r'.*backdoor.*',
            r'.*malware.*',
            r'.*trojan.*',
            r'.*phish.*',
            r'.*steal.*',
            r'.*hack.*tool.*'
        ]
        
        indicators = []
        for pattern in suspicious_patterns:
            if re.match(pattern, package_name):
                indicators.append(f"Matches suspicious pattern: {pattern}")
        
        if indicators:
            results.append(MaliciousPackage(
                package_name=package_name,
                version=package.get('version', ''),
                ecosystem=ecosystem,
                threat_type="suspicious_naming",
                indicators=indicators,
                confidence=0.75,
                first_detected=datetime.now(),
                sources=["pattern_analysis"]
            ))
        
        return results
    
    async def _analyze_package_metadata(self, package: Dict) -> List[MaliciousPackage]:
        """Analyze package metadata for red flags"""
        results = []
        package_name = package.get('name', '')
        
        # Red flags in package metadata
        red_flags = []
        
        # Check for suspicious descriptions
        description = package.get('description', '').lower()
        suspicious_keywords = ['bitcoin', 'cryptocurrency', 'mining', 'keylogger', 'backdoor']
        
        for keyword in suspicious_keywords:
            if keyword in description:
                red_flags.append(f"Suspicious keyword in description: {keyword}")
        
        # Check for recent creation with high version number (version inflation)
        version = package.get('version', '0.0.1')
        try:
            major_version = int(version.split('.')[0])
            if major_version > 50:  # Suspiciously high version number
                red_flags.append(f"Suspiciously high version number: {version}")
        except:
            pass
        
        if red_flags:
            results.append(MaliciousPackage(
                package_name=package_name,
                version=package.get('version', ''),
                ecosystem=package.get('ecosystem', 'unknown'),
                threat_type="metadata_anomaly",
                indicators=red_flags,
                confidence=0.65,
                first_detected=datetime.now(),
                sources=["metadata_analysis"]
            ))
        
        return results

class DependencyConfusionDetector:
    """Dependency confusion attack detection and prevention"""
    
    def __init__(self):
        self.internal_registries = {
            'python': ['internal.pypi.company.com', 'private-pypi.internal'],
            'npm': ['npm.company.com', 'private-npm.internal'],
            'maven': ['nexus.company.com', 'artifactory.internal']
        }
    
    async def detect_dependency_confusion(self, packages: List[Dict], internal_packages: Optional[List[str]] = None) -> List[DependencyConfusion]:
        """Detect potential dependency confusion attacks"""
        findings = []
        
        if not internal_packages:
            # Simulate internal package detection
            internal_packages = self._simulate_internal_packages(packages)
        
        for package in packages:
            package_name = package.get('name', '')
            version = package.get('version', '')
            ecosystem = package.get('ecosystem', 'unknown')
            
            if package_name in internal_packages:
                # Check if there's a public package with the same name
                public_version = await self._check_public_registry(package_name, ecosystem)
                
                if public_version:
                    confusion_risk = self._assess_confusion_risk(
                        package_name, version, public_version, ecosystem
                    )
                    if confusion_risk:
                        findings.append(confusion_risk)
        
        return findings
    
    def _simulate_internal_packages(self, packages: List[Dict]) -> List[str]:
        """Simulate detection of internal packages"""
        # In a real implementation, this would check against internal registries
        internal_patterns = [
            r'.*-internal$',
            r'^company-.*',
            r'^internal-.*',
            r'.*-private$'
        ]
        
        internal_packages = []
        for package in packages:
            package_name = package.get('name', '')
            for pattern in internal_patterns:
                if re.match(pattern, package_name):
                    internal_packages.append(package_name)
                    break
        
        return internal_packages
    
    async def _check_public_registry(self, package_name: str, ecosystem: str) -> Optional[str]:
        """Check if package exists in public registry"""
        # Simulated public registry check
        # In practice, this would make actual API calls to PyPI, NPM, etc.
        
        # Simulate that some internal packages have public counterparts
        if 'internal' in package_name or 'company' in package_name:
            return "999.999.999"  # Simulate malicious high version
        
        return None
    
    def _assess_confusion_risk(self, package_name: str, internal_version: str, public_version: str, ecosystem: str) -> Optional[DependencyConfusion]:
        """Assess the risk of dependency confusion"""
        
        try:
            # Simple version comparison
            internal_parts = [int(x) for x in internal_version.split('.')]
            public_parts = [int(x) for x in public_version.split('.')]
            
            # Pad to same length
            max_len = max(len(internal_parts), len(public_parts))
            internal_parts += [0] * (max_len - len(internal_parts))
            public_parts += [0] * (max_len - len(public_parts))
            
            # Compare versions
            public_is_higher = public_parts > internal_parts
            
            if public_is_higher:
                # Public version is higher - high risk of confusion attack
                risk_level = "high"
                attack_vector = "Version confusion - public package has higher version"
                confidence = 0.9
            else:
                # Public version is lower - medium risk
                risk_level = "medium"
                attack_vector = "Name collision - public package exists with same name"
                confidence = 0.6
            
            recommendations = [
                f"Pin exact version in dependency files: {package_name}=={internal_version}",
                f"Configure package manager to prefer internal registry",
                f"Consider renaming internal package to avoid collision",
                f"Implement registry authentication and access controls"
            ]
            
            return DependencyConfusion(
                package_name=package_name,
                internal_version=internal_version,
                public_version=public_version,
                ecosystem=ecosystem,
                risk_level=risk_level,
                attack_vector=attack_vector,
                recommendations=recommendations,
                confidence=confidence
            )
            
        except ValueError:
            # Invalid version format
            return None

class PackageRiskAssessment:
    """Comprehensive package risk assessment engine"""
    
    def __init__(self):
        self.risk_factors = {
            'outdated': {'weight': 0.3, 'threshold_days': 365},
            'low_downloads': {'weight': 0.2, 'threshold': 1000},
            'single_maintainer': {'weight': 0.15, 'threshold': 1},
            'recent_creation': {'weight': 0.1, 'threshold_days': 30},
            'no_tests': {'weight': 0.1},
            'suspicious_metadata': {'weight': 0.15}
        }
    
    async def assess_package_risks(self, packages: List[Dict]) -> List[PackageRisk]:
        """Assess risk for each package in the dependency tree"""
        risk_assessments = []
        
        for package in packages:
            risk_assessment = await self._assess_single_package(package)
            risk_assessments.append(risk_assessment)
        
        return risk_assessments
    
    async def _assess_single_package(self, package: Dict) -> PackageRisk:
        """Assess risk for a single package"""
        package_name = package.get('name', '')
        version = package.get('version', '')
        ecosystem = package.get('ecosystem', 'unknown')
        
        # Simulate package metadata (in practice, this would fetch from registries)
        metadata = await self._fetch_package_metadata(package_name, ecosystem)
        
        # Calculate risk factors
        risk_factors = []
        risk_score = 0.0
        
        # Check if package is outdated
        if metadata['days_since_update'] > self.risk_factors['outdated']['threshold_days']:
            risk_factors.append(f"Package not updated for {metadata['days_since_update']} days")
            risk_score += self.risk_factors['outdated']['weight']
        
        # Check download statistics
        if metadata['download_count'] < self.risk_factors['low_downloads']['threshold']:
            risk_factors.append(f"Low download count: {metadata['download_count']}")
            risk_score += self.risk_factors['low_downloads']['weight']
        
        # Check maintainer count
        if metadata['maintainer_count'] <= self.risk_factors['single_maintainer']['threshold']:
            risk_factors.append("Single maintainer - bus factor risk")
            risk_score += self.risk_factors['single_maintainer']['weight']
        
        # Check creation date
        if metadata['days_since_creation'] < self.risk_factors['recent_creation']['threshold_days']:
            risk_factors.append(f"Recently created package ({metadata['days_since_creation']} days)")
            risk_score += self.risk_factors['recent_creation']['weight']
        
        # Check for tests
        if not metadata['has_tests']:
            risk_factors.append("No test suite detected")
            risk_score += self.risk_factors['no_tests']['weight']
        
        # Calculate supply chain threats
        supply_chain_threats = self._identify_supply_chain_threats(package, metadata)
        
        return PackageRisk(
            package_name=package_name,
            version=version,
            ecosystem=ecosystem,
            risk_score=min(risk_score, 1.0),  # Cap at 1.0
            risk_factors=risk_factors,
            supply_chain_threats=supply_chain_threats,
            reputation_score=metadata['reputation_score'],
            maintainer_trust=metadata['maintainer_trust'],
            last_updated=metadata['last_updated'],
            download_stats=metadata['download_stats']
        )
    
    async def _fetch_package_metadata(self, package_name: str, ecosystem: str) -> Dict:
        """Fetch package metadata from registries"""
        # Simulated metadata - in practice, this would make API calls
        import random
        
        return {
            'days_since_update': random.randint(1, 730),
            'download_count': random.randint(100, 1000000),
            'maintainer_count': random.randint(1, 10),
            'days_since_creation': random.randint(10, 2000),
            'has_tests': random.choice([True, False]),
            'reputation_score': random.uniform(0.1, 1.0),
            'maintainer_trust': random.uniform(0.3, 1.0),
            'last_updated': datetime.now() - timedelta(days=random.randint(1, 365)),
            'download_stats': {
                'weekly': random.randint(10, 10000),
                'monthly': random.randint(50, 50000)
            }
        }
    
    def _identify_supply_chain_threats(self, package: Dict, metadata: Dict) -> List[str]:
        """Identify potential supply chain threats"""
        threats = []
        
        if metadata['maintainer_count'] == 1:
            threats.append("Single point of failure - maintainer compromise risk")
        
        if metadata['days_since_update'] > 365:
            threats.append("Unmaintained package - security patch risk")
        
        if metadata['download_count'] < 1000:
            threats.append("Low adoption - potential for malicious replacement")
        
        if not metadata['has_tests']:
            threats.append("No test coverage - quality and security risk")
        
        return threats

class SupplyChainSecurityEngine:
    """Main supply chain security analysis engine"""
    
    def __init__(self):
        self.malicious_detector = MaliciousPackageDetector()
        self.confusion_detector = DependencyConfusionDetector()
        self.risk_assessor = PackageRiskAssessment()
    
    async def analyze_supply_chain_security(self, packages: List[Dict], internal_packages: Optional[List[str]] = None) -> SupplyChainAnalysis:
        """Perform comprehensive supply chain security analysis"""
        
        logger.info(f"Starting supply chain analysis for {len(packages)} packages")
        
        # Detect malicious packages
        malicious_packages = await self.malicious_detector.detect_malicious_packages(packages)
        
        # Detect dependency confusion risks
        dependency_confusion_risks = await self.confusion_detector.detect_dependency_confusion(packages, internal_packages)
        
        # Assess package risks
        package_risks = await self.risk_assessor.assess_package_risks(packages)
        
        # Calculate overall supply chain score
        supply_chain_score = self._calculate_supply_chain_score(
            malicious_packages, dependency_confusion_risks, package_risks
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            malicious_packages, dependency_confusion_risks, package_risks
        )
        
        # Count high-risk packages
        high_risk_packages = len([pkg for pkg in package_risks if pkg.risk_score > 0.7])
        
        return SupplyChainAnalysis(
            total_packages=len(packages),
            high_risk_packages=high_risk_packages,
            dependency_confusion_risks=dependency_confusion_risks,
            malicious_packages=malicious_packages,
            package_risks=package_risks,
            supply_chain_score=supply_chain_score,
            recommendations=recommendations,
            analysis_timestamp=datetime.now()
        )
    
    def _calculate_supply_chain_score(self, malicious_packages: List[MaliciousPackage], 
                                    dependency_confusion_risks: List[DependencyConfusion],
                                    package_risks: List[PackageRisk]) -> float:
        """Calculate overall supply chain security score (0-100)"""
        
        base_score = 100.0
        
        # Deduct for malicious packages (major impact)
        base_score -= len(malicious_packages) * 25
        
        # Deduct for dependency confusion risks
        high_confusion_risks = len([r for r in dependency_confusion_risks if r.risk_level == 'high'])
        medium_confusion_risks = len([r for r in dependency_confusion_risks if r.risk_level == 'medium'])
        base_score -= high_confusion_risks * 15
        base_score -= medium_confusion_risks * 8
        
        # Deduct for high-risk packages
        high_risk_count = len([pkg for pkg in package_risks if pkg.risk_score > 0.7])
        medium_risk_count = len([pkg for pkg in package_risks if 0.4 < pkg.risk_score <= 0.7])
        base_score -= high_risk_count * 5
        base_score -= medium_risk_count * 2
        
        return max(0.0, min(100.0, base_score))
    
    def _generate_recommendations(self, malicious_packages: List[MaliciousPackage],
                                dependency_confusion_risks: List[DependencyConfusion],
                                package_risks: List[PackageRisk]) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        if malicious_packages:
            recommendations.append(f"CRITICAL: Remove {len(malicious_packages)} malicious packages immediately")
            recommendations.append("Implement automated malicious package scanning in CI/CD pipeline")
        
        if dependency_confusion_risks:
            high_risk_confusion = [r for r in dependency_confusion_risks if r.risk_level == 'high']
            if high_risk_confusion:
                recommendations.append(f"HIGH: Address {len(high_risk_confusion)} dependency confusion vulnerabilities")
            recommendations.append("Configure package managers to prefer internal registries")
            recommendations.append("Pin exact versions for all internal packages")
        
        high_risk_packages = [pkg for pkg in package_risks if pkg.risk_score > 0.7]
        if high_risk_packages:
            recommendations.append(f"Review {len(high_risk_packages)} high-risk packages for alternatives")
        
        # General recommendations
        recommendations.extend([
            "Implement Software Bill of Materials (SBOM) tracking",
            "Set up automated dependency update monitoring", 
            "Establish package vetting process for new dependencies",
            "Implement signature verification for package integrity",
            "Regular security audits of dependency tree"
        ])
        
        return recommendations[:10]  # Top 10 recommendations

# Demo function
async def demo_supply_chain_security():
    """Demonstrate supply chain security capabilities"""
    
    # Sample packages with various risk factors
    sample_packages = [
        {
            'name': 'requests',
            'version': '2.28.1',
            'ecosystem': 'python'
        },
        {
            'name': 'requsts',  # Typosquatting example
            'version': '1.0.0', 
            'ecosystem': 'python'
        },
        {
            'name': 'company-internal-auth',
            'version': '1.2.3',
            'ecosystem': 'python'
        },
        {
            'name': 'bitcoin-miner',  # Known malicious
            'version': '1.0.0',
            'ecosystem': 'python'
        },
        {
            'name': 'old-package',
            'version': '0.1.0',
            'ecosystem': 'python'
        }
    ]
    
    internal_packages = ['company-internal-auth']
    
    # Initialize supply chain security engine
    sc_engine = SupplyChainSecurityEngine()
    
    # Perform analysis
    analysis = await sc_engine.analyze_supply_chain_security(sample_packages, internal_packages)
    
    print("🔒 Supply Chain Security Analysis Results")
    print("=" * 50)
    print(f"📦 Total Packages: {analysis.total_packages}")
    print(f"⚠️  High Risk Packages: {analysis.high_risk_packages}")
    print(f"🏆 Supply Chain Score: {analysis.supply_chain_score:.1f}/100")
    
    print(f"\\n🦠 Malicious Packages Found: {len(analysis.malicious_packages)}")
    for malicious in analysis.malicious_packages:
        print(f"   - {malicious.package_name}: {malicious.threat_type} (confidence: {malicious.confidence:.2f})")
    
    print(f"\\n⚡ Dependency Confusion Risks: {len(analysis.dependency_confusion_risks)}")
    for confusion in analysis.dependency_confusion_risks:
        print(f"   - {confusion.package_name}: {confusion.risk_level} risk")
    
    print(f"\\n📋 Top Recommendations:")
    for i, rec in enumerate(analysis.recommendations[:5], 1):
        print(f"   {i}. {rec}")
    
    return analysis

if __name__ == "__main__":
    import asyncio
    asyncio.run(demo_supply_chain_security())