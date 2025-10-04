"""
Enterprise Reporting & Analytics Module
Advanced security reporting, compliance automation, and executive dashboards
Premium Feature - Requires Enterprise License
"""

import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, Counter
import base64
import io

# Optional imports with fallbacks
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    
try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ComplianceFramework:
    """Compliance framework definition"""
    name: str
    version: str
    controls: Dict[str, Any]
    requirements: List[str]
    mapping: Dict[str, List[str]]  # vulnerability_type -> control_ids

@dataclass
class ExecutiveSummary:
    """Executive summary data structure"""
    organization: str
    report_period: str
    total_assets: int
    critical_vulnerabilities: int
    high_risk_assets: int
    compliance_score: float
    security_trend: str  # improving, declining, stable
    key_risks: List[str]
    recommendations: List[str]

@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    source: str
    indicator_type: str  # CVE, IOC, signature
    value: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    description: str
    tags: List[str]

@dataclass
class RiskTrend:
    """Risk trending data"""
    date: datetime
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_assets: int
    average_risk_score: float

class ComplianceEngine:
    """Compliance framework engine for automated reporting"""
    
    def __init__(self, frameworks_dir: str = "compliance_frameworks"):
        self.frameworks_dir = Path(frameworks_dir)
        self.frameworks = {}
        self._load_frameworks()
    
    def _load_frameworks(self):
        """Load compliance frameworks from configuration"""
        # SOC2 Type II Framework
        soc2_framework = ComplianceFramework(
            name="SOC2 Type II",
            version="2017",
            controls={
                "CC6.1": "Logical and physical access controls",
                "CC6.2": "Access credentials management", 
                "CC6.3": "Network segmentation and firewalls",
                "CC7.1": "System vulnerability management",
                "CC7.2": "Security monitoring and logging",
                "CC8.1": "Change management procedures"
            },
            requirements=[
                "Vulnerability management program",
                "Access control implementation",
                "Security monitoring capabilities",
                "Change management processes"
            ],
            mapping={
                "sql_injection": ["CC6.1", "CC7.1"],
                "command_injection": ["CC6.1", "CC7.1"], 
                "hardcoded_secrets": ["CC6.2", "CC7.1"],
                "insecure_configuration": ["CC6.3", "CC7.1"],
                "privilege_escalation": ["CC6.1", "CC6.3"],
                "network_exposure": ["CC6.3", "CC7.2"]
            }
        )
        
        # PCI-DSS Framework
        pci_framework = ComplianceFramework(
            name="PCI-DSS",
            version="4.0",
            controls={
                "1.1": "Network security controls and firewall configuration",
                "2.1": "Vendor-supplied defaults and security parameters", 
                "6.1": "Secure coding practices and vulnerability management",
                "6.2": "Software security patches and updates",
                "11.1": "Vulnerability scanning and penetration testing",
                "12.1": "Information security policy"
            },
            requirements=[
                "Regular vulnerability scanning",
                "Secure coding practices",
                "Network segmentation",
                "Access control measures"
            ],
            mapping={
                "sql_injection": ["6.1", "11.1"],
                "weak_cryptography": ["2.1", "6.1"],
                "hardcoded_secrets": ["2.1", "6.1"],
                "network_exposure": ["1.1", "11.1"],
                "insecure_configuration": ["2.1", "6.2"]
            }
        )
        
        # ISO 27001 Framework  
        iso27001_framework = ComplianceFramework(
            name="ISO 27001",
            version="2022",
            controls={
                "A.8.1": "Inventory of assets",
                "A.8.2": "Information classification", 
                "A.12.1": "Operational procedures and responsibilities",
                "A.12.6": "Management of technical vulnerabilities",
                "A.13.1": "Network security management",
                "A.14.2": "Security in development and support processes"
            },
            requirements=[
                "Asset inventory and classification",
                "Vulnerability management procedures", 
                "Secure development lifecycle",
                "Network security controls"
            ],
            mapping={
                "sql_injection": ["A.12.6", "A.14.2"],
                "command_injection": ["A.12.6", "A.14.2"],
                "insecure_configuration": ["A.12.1", "A.13.1"],
                "privilege_escalation": ["A.13.1", "A.12.6"],
                "hardcoded_secrets": ["A.14.2", "A.8.2"]
            }
        )
        
        self.frameworks = {
            "SOC2": soc2_framework,
            "PCI-DSS": pci_framework, 
            "ISO27001": iso27001_framework
        }
    
    def assess_compliance(self, vulnerabilities: List[Dict], framework: str) -> Dict[str, Any]:
        """Assess compliance against a specific framework"""
        if framework not in self.frameworks:
            raise ValueError(f"Framework {framework} not supported")
        
        fw = self.frameworks[framework]
        control_violations = defaultdict(list)
        total_controls = len(fw.controls)
        violated_controls = set()
        
        # Map vulnerabilities to controls
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            if vuln_type in fw.mapping:
                for control_id in fw.mapping[vuln_type]:
                    control_violations[control_id].append(vuln)
                    violated_controls.add(control_id)
        
        # Calculate compliance score
        compliant_controls = total_controls - len(violated_controls)
        compliance_score = (compliant_controls / total_controls) * 100
        
        return {
            "framework": framework,
            "version": fw.version,
            "compliance_score": compliance_score,
            "total_controls": total_controls,
            "compliant_controls": compliant_controls,
            "violated_controls": len(violated_controls),
            "control_violations": dict(control_violations),
            "requirements_status": self._assess_requirements(fw, violated_controls),
            "remediation_priority": self._get_remediation_priority(control_violations, fw)
        }
    
    def _assess_requirements(self, framework: ComplianceFramework, violated_controls: set) -> Dict[str, str]:
        """Assess requirement compliance status"""
        # This is a simplified mapping - in practice, requirements map to multiple controls
        requirement_status = {}
        for req in framework.requirements:
            # Determine if requirement is met based on related control violations
            status = "compliant" if not any(ctrl in violated_controls for ctrl in framework.controls.keys()) else "non-compliant"
            requirement_status[req] = status
        return requirement_status
    
    def _get_remediation_priority(self, control_violations: Dict, framework: ComplianceFramework) -> List[Dict]:
        """Get remediation priority list"""
        priority_list = []
        for control_id, violations in control_violations.items():
            priority_list.append({
                "control_id": control_id,
                "control_name": framework.controls.get(control_id, "Unknown"),
                "violation_count": len(violations),
                "severity_score": sum(self._get_severity_score(v.get('severity', 'low')) for v in violations),
                "priority": "high" if len(violations) > 5 else "medium" if len(violations) > 2 else "low"
            })
        
        # Sort by severity score descending
        priority_list.sort(key=lambda x: x['severity_score'], reverse=True)
        return priority_list
    
    def _get_severity_score(self, severity: str) -> int:
        """Convert severity to numeric score"""
        scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        return scores.get(severity.lower(), 1)

class ThreatIntelligenceEngine:
    """Advanced threat intelligence integration"""
    
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = db_path
        self._init_database()
        self.sources = {
            "mitre_cve": "https://cve.mitre.org/data/downloads/allitems.xml",
            "nist_nvd": "https://services.nvd.nist.gov/rest/json/cves/1.0",
            "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "abuse_ch": "https://threatfox.abuse.ch/api/",
            "alienvault_otx": "https://otx.alienvault.com/api/v1/indicators/"
        }
    
    def _init_database(self):
        """Initialize threat intelligence database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                severity TEXT,
                confidence REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                description TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intel_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id TEXT NOT NULL,
                intel_id TEXT NOT NULL,
                correlation_type TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def correlate_with_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Correlate vulnerabilities with threat intelligence"""
        correlations = []
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            enhanced_vuln = vuln.copy()
            vuln_correlations = self._find_correlations(vuln)
            
            if vuln_correlations:
                enhanced_vuln['threat_intel'] = {
                    'correlations': vuln_correlations,
                    'threat_level': self._calculate_threat_level(vuln_correlations),
                    'intelligence_sources': list(set(c['source'] for c in vuln_correlations))
                }
                correlations.extend(vuln_correlations)
            
            enhanced_vulns.append(enhanced_vuln)
        
        return {
            "enhanced_vulnerabilities": enhanced_vulns,
            "total_correlations": len(correlations),
            "threat_intelligence_summary": self._generate_intel_summary(correlations),
            "actionable_intelligence": self._get_actionable_intelligence(correlations)
        }
    
    def _find_correlations(self, vulnerability: Dict) -> List[Dict]:
        """Find threat intelligence correlations for a vulnerability"""
        correlations = []
        
        # Example correlation logic - in practice, this would be more sophisticated
        vuln_type = vulnerability.get('vulnerability_type', '')
        description = vulnerability.get('description', '').lower()
        
        # Simulated threat intelligence correlations
        if 'sql' in vuln_type or 'injection' in description:
            correlations.append({
                'source': 'mitre_cve',
                'type': 'technique',
                'value': 'T1190',
                'description': 'Exploit Public-Facing Application',
                'confidence': 0.85
            })
        
        if 'command' in vuln_type or 'rce' in description:
            correlations.append({
                'source': 'cisa_kev',
                'type': 'exploitation',
                'value': 'actively_exploited',
                'description': 'Command injection vulnerabilities actively exploited',
                'confidence': 0.90
            })
        
        return correlations
    
    def _calculate_threat_level(self, correlations: List[Dict]) -> str:
        """Calculate overall threat level based on correlations"""
        if not correlations:
            return "low"
        
        max_confidence = max(c.get('confidence', 0) for c in correlations)
        active_exploit = any('actively_exploited' in c.get('value', '') for c in correlations)
        
        if active_exploit or max_confidence > 0.8:
            return "critical"
        elif max_confidence > 0.6:
            return "high"
        elif max_confidence > 0.4:
            return "medium"
        else:
            return "low"
    
    def _generate_intel_summary(self, correlations: List[Dict]) -> Dict[str, Any]:
        """Generate threat intelligence summary"""
        sources = Counter(c.get('source', 'unknown') for c in correlations)
        types = Counter(c.get('type', 'unknown') for c in correlations)
        
        return {
            "total_indicators": len(correlations),
            "sources": dict(sources),
            "indicator_types": dict(types),
            "average_confidence": sum(c.get('confidence', 0) for c in correlations) / len(correlations) if correlations else 0
        }
    
    def _get_actionable_intelligence(self, correlations: List[Dict]) -> List[Dict]:
        """Get actionable intelligence recommendations"""
        actions = []
        
        for correlation in correlations:
            if correlation.get('confidence', 0) > 0.7:
                actions.append({
                    "priority": "high",
                    "action": f"Investigate {correlation.get('type', 'indicator')} from {correlation.get('source', 'unknown')}",
                    "description": correlation.get('description', ''),
                    "confidence": correlation.get('confidence', 0)
                })
        
        return sorted(actions, key=lambda x: x['confidence'], reverse=True)

class EnterpriseReportingEngine:
    """Enterprise-grade reporting and analytics engine"""
    
    def __init__(self, db_path: str = "enterprise_analytics.db"):
        self.db_path = db_path
        self.compliance_engine = ComplianceEngine()
        self.threat_intel = ThreatIntelligenceEngine()
        self._init_database()
    
    def _init_database(self):
        """Initialize enterprise analytics database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                total_assets INTEGER,
                average_risk_score REAL,
                organization TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS executive_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                organization TEXT,
                report_type TEXT,
                report_period TEXT,
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def generate_executive_dashboard(self, scan_results: List[Dict], organization: str = "VulnaraX Enterprise") -> Dict[str, Any]:
        """Generate executive dashboard data"""
        
        # Aggregate vulnerability data
        total_vulns = sum(len(result.get('vulnerabilities', [])) for result in scan_results)
        severity_counts = self._count_by_severity(scan_results)
        
        # Risk trending
        risk_trends = self._calculate_risk_trends(scan_results)
        
        # Compliance assessment
        all_vulns = []
        for result in scan_results:
            all_vulns.extend(result.get('vulnerabilities', []))
        
        compliance_assessments = {}
        for framework in ["SOC2", "PCI-DSS", "ISO27001"]:
            compliance_assessments[framework] = self.compliance_engine.assess_compliance(all_vulns, framework)
        
        # Threat intelligence correlation
        threat_analysis = self.threat_intel.correlate_with_vulnerabilities(all_vulns)
        
        # Executive summary
        executive_summary = ExecutiveSummary(
            organization=organization,
            report_period=f"{datetime.now().strftime('%Y-%m')}",
            total_assets=len(scan_results),
            critical_vulnerabilities=severity_counts.get('critical', 0),
            high_risk_assets=len([r for r in scan_results if self._calculate_asset_risk(r) > 7.0]),
            compliance_score=self._calculate_overall_compliance_score(compliance_assessments),
            security_trend=self._determine_security_trend(risk_trends),
            key_risks=self._identify_key_risks(all_vulns, threat_analysis),
            recommendations=self._generate_executive_recommendations(compliance_assessments, threat_analysis)
        )
        
        return {
            "executive_summary": asdict(executive_summary),
            "vulnerability_overview": {
                "total_vulnerabilities": total_vulns,
                "severity_distribution": severity_counts,
                "assets_scanned": len(scan_results),
                "risk_score_average": self._calculate_average_risk_score(all_vulns)
            },
            "compliance_status": compliance_assessments,
            "threat_intelligence": threat_analysis['threat_intelligence_summary'],
            "risk_trends": risk_trends,
            "actionable_insights": self._generate_actionable_insights(compliance_assessments, threat_analysis),
            "generated_at": datetime.now().isoformat()
        }
    
    def generate_compliance_report(self, vulnerabilities: List[Dict], framework: str, organization: str) -> Dict[str, Any]:
        """Generate detailed compliance report"""
        
        assessment = self.compliance_engine.assess_compliance(vulnerabilities, framework)
        
        # Detailed control analysis
        control_details = []
        fw = self.compliance_engine.frameworks[framework]
        
        for control_id, control_name in fw.controls.items():
            violations = assessment['control_violations'].get(control_id, [])
            control_details.append({
                "control_id": control_id,
                "control_name": control_name,
                "status": "compliant" if not violations else "non-compliant",
                "violation_count": len(violations),
                "risk_score": sum(self._get_vulnerability_risk_score(v) for v in violations),
                "violations": violations[:5]  # Top 5 violations
            })
        
        return {
            "organization": organization,
            "framework": framework,
            "assessment_date": datetime.now().isoformat(),
            "overall_score": assessment['compliance_score'],
            "summary": {
                "total_controls": assessment['total_controls'],
                "compliant_controls": assessment['compliant_controls'],
                "violations": assessment['violated_controls']
            },
            "control_details": control_details,
            "remediation_roadmap": self._create_remediation_roadmap(assessment['remediation_priority']),
            "executive_summary": self._create_compliance_executive_summary(assessment, framework)
        }
    
    def _count_by_severity(self, scan_results: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = defaultdict(int)
        for result in scan_results:
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'unknown').lower()
                counts[severity] += 1
        return dict(counts)
    
    def _calculate_risk_trends(self, scan_results: List[Dict]) -> List[Dict]:
        """Calculate risk trends over time"""
        # For demo purposes, generate trend data
        trends = []
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(5):  # Last 5 data points
            date = base_date + timedelta(days=i*7)
            severity_counts = self._count_by_severity(scan_results)
            
            trends.append({
                "date": date.strftime('%Y-%m-%d'),
                "critical": severity_counts.get('critical', 0),
                "high": severity_counts.get('high', 0),
                "medium": severity_counts.get('medium', 0),
                "low": severity_counts.get('low', 0),
                "total_assets": len(scan_results)
            })
        
        return trends
    
    def _calculate_asset_risk(self, scan_result: Dict) -> float:
        """Calculate risk score for an asset"""
        vulnerabilities = scan_result.get('vulnerabilities', [])
        if not vulnerabilities:
            return 0.0
        
        total_risk = sum(self._get_vulnerability_risk_score(v) for v in vulnerabilities)
        return total_risk / len(vulnerabilities)
    
    def _get_vulnerability_risk_score(self, vulnerability: Dict) -> float:
        """Get numeric risk score for vulnerability"""
        severity = vulnerability.get('severity', 'low').lower()
        confidence = vulnerability.get('confidence', 0.5)
        
        base_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        return base_scores.get(severity, 1) * confidence
    
    def _calculate_overall_compliance_score(self, assessments: Dict) -> float:
        """Calculate overall compliance score across frameworks"""
        if not assessments:
            return 0.0
        
        scores = [a['compliance_score'] for a in assessments.values()]
        return sum(scores) / len(scores)
    
    def _determine_security_trend(self, trends: List[Dict]) -> str:
        """Determine security trend direction"""
        if len(trends) < 2:
            return "stable"
        
        recent_critical = trends[-1]['critical']
        previous_critical = trends[-2]['critical']
        
        if recent_critical < previous_critical:
            return "improving"
        elif recent_critical > previous_critical:
            return "declining"
        else:
            return "stable"
    
    def _identify_key_risks(self, vulnerabilities: List[Dict], threat_analysis: Dict) -> List[str]:
        """Identify key organizational risks"""
        risks = []
        
        # High-severity vulnerability count
        critical_vulns = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])
        if critical_vulns > 5:
            risks.append(f"{critical_vulns} critical vulnerabilities requiring immediate attention")
        
        # Threat intelligence correlations
        correlations = threat_analysis.get('total_correlations', 0)
        if correlations > 10:
            risks.append(f"{correlations} vulnerabilities correlated with active threat intelligence")
        
        # Vulnerability types
        vuln_types = Counter(v.get('vulnerability_type', '') for v in vulnerabilities)
        top_type, top_count = vuln_types.most_common(1)[0] if vuln_types else ('', 0)
        if top_count > 10:
            risks.append(f"High concentration of {top_type} vulnerabilities ({top_count} instances)")
        
        return risks[:5]  # Top 5 risks
    
    def _generate_executive_recommendations(self, compliance_assessments: Dict, threat_analysis: Dict) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        # Compliance-based recommendations
        for framework, assessment in compliance_assessments.items():
            if assessment['compliance_score'] < 80:
                recommendations.append(f"Prioritize {framework} compliance improvement (current: {assessment['compliance_score']:.1f}%)")
        
        # Threat intelligence recommendations
        actionable_intel = threat_analysis.get('actionable_intelligence', [])
        if actionable_intel:
            recommendations.append(f"Address {len(actionable_intel)} high-confidence threat intelligence indicators")
        
        # General recommendations
        recommendations.extend([
            "Implement automated vulnerability scanning in CI/CD pipeline",
            "Establish vulnerability remediation SLAs based on risk scoring",
            "Enhance security monitoring and incident response capabilities"
        ])
        
        return recommendations[:5]  # Top 5 recommendations
    
    def _calculate_average_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate average risk score"""
        if not vulnerabilities:
            return 0.0
        
        total_score = sum(self._get_vulnerability_risk_score(v) for v in vulnerabilities)
        return total_score / len(vulnerabilities)
    
    def _generate_actionable_insights(self, compliance_assessments: Dict, threat_analysis: Dict) -> List[Dict]:
        """Generate actionable insights"""
        insights = []
        
        # Top compliance gaps
        for framework, assessment in compliance_assessments.items():
            if assessment['compliance_score'] < 90:
                insights.append({
                    "type": "compliance_gap",
                    "priority": "high",
                    "framework": framework,
                    "description": f"{framework} compliance at {assessment['compliance_score']:.1f}%",
                    "action": "Review control violations and implement remediation plan"
                })
        
        # Threat intelligence insights
        for intel in threat_analysis.get('actionable_intelligence', [])[:3]:
            insights.append({
                "type": "threat_intelligence",
                "priority": intel['priority'],
                "description": intel['description'],
                "action": intel['action']
            })
        
        return insights
    
    def _create_remediation_roadmap(self, remediation_priority: List[Dict]) -> List[Dict]:
        """Create remediation roadmap"""
        roadmap = []
        
        for i, item in enumerate(remediation_priority[:10]):  # Top 10 items
            roadmap.append({
                "phase": f"Phase {(i//3) + 1}",
                "timeline": f"{((i//3) + 1) * 30} days",
                "control": item['control_id'],
                "control_name": item['control_name'],
                "priority": item['priority'],
                "effort": "high" if item['violation_count'] > 10 else "medium" if item['violation_count'] > 5 else "low"
            })
        
        return roadmap
    
    def _create_compliance_executive_summary(self, assessment: Dict, framework: str) -> str:
        """Create executive summary for compliance report"""
        score = assessment['compliance_score']
        violations = assessment['violated_controls']
        
        if score >= 90:
            status = "excellent"
        elif score >= 80:
            status = "good"
        elif score >= 70:
            status = "fair"
        else:
            status = "poor"
        
        return f"""
        {framework} Compliance Assessment Summary:
        
        Overall compliance score: {score:.1f}% ({status})
        Controls with violations: {violations}
        Priority actions required: {len(assessment['remediation_priority'])}
        
        The organization demonstrates {status} compliance with {framework} requirements.
        Immediate attention is required for {violations} control areas to achieve full compliance.
        """

# Demo function to test enterprise reporting
def demo_enterprise_reporting():
    """Demonstrate enterprise reporting capabilities"""
    
    # Sample scan results
    sample_vulnerabilities = [
        {
            "id": "VULN-001",
            "vulnerability_type": "sql_injection",
            "severity": "critical",
            "confidence": 0.95,
            "description": "SQL injection in user authentication"
        },
        {
            "id": "VULN-002", 
            "vulnerability_type": "command_injection",
            "severity": "high",
            "confidence": 0.88,
            "description": "Command injection in file upload"
        },
        {
            "id": "VULN-003",
            "vulnerability_type": "hardcoded_secrets",
            "severity": "medium",
            "confidence": 0.92,
            "description": "API key hardcoded in source"
        }
    ]
    
    sample_scan_results = [
        {
            "project_path": "/app1",
            "vulnerabilities": sample_vulnerabilities[:2]
        },
        {
            "project_path": "/app2", 
            "vulnerabilities": sample_vulnerabilities[2:]
        }
    ]
    
    # Initialize reporting engine
    reporting_engine = EnterpriseReportingEngine()
    
    # Generate executive dashboard
    dashboard = reporting_engine.generate_executive_dashboard(sample_scan_results, "Demo Organization")
    
    print("🎯 Executive Dashboard Generated")
    print(f"├── Total Vulnerabilities: {dashboard['vulnerability_overview']['total_vulnerabilities']}")
    print(f"├── Compliance Score: {dashboard['executive_summary']['compliance_score']:.1f}%")
    print(f"├── Security Trend: {dashboard['executive_summary']['security_trend']}")
    print(f"└── Key Risks: {len(dashboard['executive_summary']['key_risks'])}")
    
    # Generate compliance report
    compliance_report = reporting_engine.generate_compliance_report(sample_vulnerabilities, "SOC2", "Demo Organization")
    
    print(f"\n📋 SOC2 Compliance Report Generated")
    print(f"├── Overall Score: {compliance_report['overall_score']:.1f}%")
    print(f"├── Compliant Controls: {compliance_report['summary']['compliant_controls']}")
    print(f"└── Violations: {compliance_report['summary']['violations']}")
    
    return dashboard, compliance_report

if __name__ == "__main__":
    demo_enterprise_reporting()