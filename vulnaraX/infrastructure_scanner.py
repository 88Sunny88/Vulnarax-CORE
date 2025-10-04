"""
Container and Infrastructure Security Scanner
Provides comprehensive security analysis for containers, Kubernetes, and Infrastructure as Code
"""

import os
import json
import yaml
import re
import logging
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import tarfile
import gzip

# Import Docker client
try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    logging.warning("Docker client not available. Container scanning limited.")


class InfraVulnerabilityType(Enum):
    """Types of infrastructure vulnerabilities"""
    EXPOSED_SECRETS = "exposed_secrets"
    INSECURE_CONFIG = "insecure_configuration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_EXPOSURE = "network_exposure"
    WEAK_ENCRYPTION = "weak_encryption"
    INSECURE_DEFAULTS = "insecure_defaults"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    CONTAINER_ESCAPE = "container_escape"
    KUBERNETES_MISCONFIG = "kubernetes_misconfiguration"
    DOCKERFILE_BEST_PRACTICES = "dockerfile_best_practices"


class InfraSeverity(Enum):
    """Infrastructure vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class InfraVulnerability:
    """Infrastructure vulnerability finding"""
    id: str
    vulnerability_type: InfraVulnerabilityType
    severity: InfraSeverity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    resource_name: Optional[str] = None
    fix_recommendation: Optional[str] = None
    compliance_impact: Optional[str] = None
    cis_control: Optional[str] = None
    confidence: float = 1.0


class DockerfileAnalyzer:
    """Analyzer for Dockerfile security issues"""
    
    def __init__(self):
        self.security_rules = [
            {
                'pattern': r'FROM\s+.*:latest',
                'type': InfraVulnerabilityType.INSECURE_DEFAULTS,
                'severity': InfraSeverity.MEDIUM,
                'title': 'Use of latest tag',
                'description': 'Using :latest tag makes builds non-reproducible',
                'fix': 'Use specific version tags instead of :latest'
            },
            {
                'pattern': r'USER\s+root|USER\s+0',
                'type': InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                'severity': InfraSeverity.HIGH,
                'title': 'Running as root user',
                'description': 'Container runs with root privileges',
                'fix': 'Create and use a non-root user'
            },
            {
                'pattern': r'ADD\s+http',
                'type': InfraVulnerabilityType.INSECURE_CONFIG,
                'severity': InfraSeverity.MEDIUM,
                'title': 'Insecure ADD from URL',
                'description': 'ADD instruction fetches files over HTTP',
                'fix': 'Use HTTPS or download files separately with verification'
            },
            {
                'pattern': r'COPY\s+.*\*.*/',
                'type': InfraVulnerabilityType.INSECURE_DEFAULTS,
                'severity': InfraSeverity.LOW,
                'title': 'Overly broad COPY instruction',
                'description': 'COPY instruction may include unintended files',
                'fix': 'Use specific file paths or .dockerignore'
            },
            {
                'pattern': r'RUN\s+.*sudo',
                'type': InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                'severity': InfraSeverity.MEDIUM,
                'title': 'Use of sudo in RUN',
                'description': 'sudo usage indicates privilege escalation',
                'fix': 'Avoid sudo in containers, use proper user permissions'
            },
            {
                'pattern': r'ENV\s+.*(?:password|secret|key|token)\s*=\s*["\']?[^"\s]+',
                'type': InfraVulnerabilityType.EXPOSED_SECRETS,
                'severity': InfraSeverity.CRITICAL,
                'title': 'Hardcoded secret in ENV',
                'description': 'Secret credentials found in environment variable',
                'fix': 'Use Docker secrets or external secret management'
            }
        ]

    def analyze_dockerfile(self, dockerfile_path: str) -> List[InfraVulnerability]:
        """Analyze Dockerfile for security issues"""
        vulnerabilities = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                for rule in self.security_rules:
                    if re.search(rule['pattern'], line, re.IGNORECASE):
                        vulnerabilities.append(InfraVulnerability(
                            id=f"DOCKER-{rule['type'].value.upper()}-{i}",
                            vulnerability_type=rule['type'],
                            severity=rule['severity'],
                            title=rule['title'],
                            description=rule['description'],
                            file_path=dockerfile_path,
                            line_number=i,
                            fix_recommendation=rule['fix'],
                            compliance_impact="CIS Docker Benchmark"
                        ))
            
            # Additional analysis
            vulnerabilities.extend(self._analyze_dockerfile_structure(content, dockerfile_path))
            
        except Exception as e:
            logging.error(f"Error analyzing Dockerfile {dockerfile_path}: {e}")
            
        return vulnerabilities

    def _analyze_dockerfile_structure(self, content: str, file_path: str) -> List[InfraVulnerability]:
        """Analyze Dockerfile structure and best practices"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Check for missing USER instruction
        has_user_instruction = any('USER' in line for line in lines if not line.strip().startswith('#'))
        if not has_user_instruction:
            vulnerabilities.append(InfraVulnerability(
                id="DOCKER-USER-MISSING",
                vulnerability_type=InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                severity=InfraSeverity.HIGH,
                title="Missing USER instruction",
                description="Container will run as root by default",
                file_path=file_path,
                fix_recommendation="Add USER instruction to run as non-root user",
                compliance_impact="CIS Docker Benchmark 4.1"
            ))
        
        # Check for HEALTHCHECK
        has_healthcheck = any('HEALTHCHECK' in line for line in lines if not line.strip().startswith('#'))
        if not has_healthcheck:
            vulnerabilities.append(InfraVulnerability(
                id="DOCKER-HEALTHCHECK-MISSING",
                vulnerability_type=InfraVulnerabilityType.INSECURE_DEFAULTS,
                severity=InfraSeverity.LOW,
                title="Missing HEALTHCHECK instruction",
                description="Container lacks health monitoring",
                file_path=file_path,
                fix_recommendation="Add HEALTHCHECK instruction for container monitoring"
            ))
        
        return vulnerabilities


class KubernetesAnalyzer:
    """Analyzer for Kubernetes security configurations"""
    
    def __init__(self):
        self.security_checks = [
            {
                'path': ['spec', 'containers', '*', 'securityContext', 'runAsUser'],
                'check': lambda x: x == 0,
                'type': InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                'severity': InfraSeverity.HIGH,
                'title': 'Container runs as root',
                'description': 'Container configured to run as root user (UID 0)',
                'fix': 'Set runAsUser to non-zero value'
            },
            {
                'path': ['spec', 'containers', '*', 'securityContext', 'privileged'],
                'check': lambda x: x is True,
                'type': InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                'severity': InfraSeverity.CRITICAL,
                'title': 'Privileged container',
                'description': 'Container runs in privileged mode',
                'fix': 'Remove privileged: true or set to false'
            },
            {
                'path': ['spec', 'containers', '*', 'securityContext', 'allowPrivilegeEscalation'],
                'check': lambda x: x is True,
                'type': InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                'severity': InfraSeverity.HIGH,
                'title': 'Privilege escalation allowed',
                'description': 'Container allows privilege escalation',
                'fix': 'Set allowPrivilegeEscalation to false'
            },
            {
                'path': ['spec', 'hostNetwork'],
                'check': lambda x: x is True,
                'type': InfraVulnerabilityType.NETWORK_EXPOSURE,
                'severity': InfraSeverity.HIGH,
                'title': 'Host network enabled',
                'description': 'Pod uses host network namespace',
                'fix': 'Remove hostNetwork or set to false'
            },
            {
                'path': ['spec', 'hostPID'],
                'check': lambda x: x is True,
                'type': InfraVulnerabilityType.CONTAINER_ESCAPE,
                'severity': InfraSeverity.HIGH,
                'title': 'Host PID namespace enabled',
                'description': 'Pod uses host PID namespace',
                'fix': 'Remove hostPID or set to false'
            }
        ]

    def analyze_kubernetes_manifest(self, manifest_path: str) -> List[InfraVulnerability]:
        """Analyze Kubernetes manifest for security issues"""
        vulnerabilities = []
        
        try:
            with open(manifest_path, 'r') as f:
                content = f.read()
            
            # Parse YAML documents (may contain multiple)
            documents = list(yaml.safe_load_all(content))
            
            for doc_idx, doc in enumerate(documents):
                if not doc or not isinstance(doc, dict):
                    continue
                
                # Analyze each document
                vulnerabilities.extend(self._analyze_k8s_document(doc, manifest_path, doc_idx))
                
        except Exception as e:
            logging.error(f"Error analyzing Kubernetes manifest {manifest_path}: {e}")
            
        return vulnerabilities

    def _analyze_k8s_document(self, doc: Dict, file_path: str, doc_idx: int) -> List[InfraVulnerability]:
        """Analyze single Kubernetes document"""
        vulnerabilities = []
        kind = doc.get('kind', 'Unknown')
        name = doc.get('metadata', {}).get('name', 'unnamed')
        
        # Apply security checks
        for check in self.security_checks:
            findings = self._check_path(doc, check['path'], check['check'])
            
            for finding in findings:
                vulnerabilities.append(InfraVulnerability(
                    id=f"K8S-{check['type'].value.upper()}-{doc_idx}-{hash(str(finding))}",
                    vulnerability_type=check['type'],
                    severity=check['severity'],
                    title=check['title'],
                    description=f"{check['description']} in {kind}/{name}",
                    file_path=file_path,
                    resource_name=f"{kind}/{name}",
                    fix_recommendation=check['fix'],
                    compliance_impact="CIS Kubernetes Benchmark"
                ))
        
        # Additional checks specific to resource types
        if kind in ['Deployment', 'Pod', 'DaemonSet', 'StatefulSet']:
            vulnerabilities.extend(self._analyze_pod_security(doc, file_path, kind, name))
        
        return vulnerabilities

    def _check_path(self, obj: Dict, path: List[str], check_func) -> List[str]:
        """Check a specific path in Kubernetes object"""
        findings = []
        
        def traverse(current_obj, remaining_path, current_path=""):
            if not remaining_path:
                if check_func(current_obj):
                    findings.append(current_path)
                return
            
            key = remaining_path[0]
            rest = remaining_path[1:]
            
            if key == '*':
                # Wildcard - check all items in array
                if isinstance(current_obj, list):
                    for i, item in enumerate(current_obj):
                        traverse(item, rest, f"{current_path}[{i}]")
                elif isinstance(current_obj, dict):
                    for k, v in current_obj.items():
                        traverse(v, rest, f"{current_path}.{k}")
            else:
                # Regular key
                if isinstance(current_obj, dict) and key in current_obj:
                    new_path = f"{current_path}.{key}" if current_path else key
                    traverse(current_obj[key], rest, new_path)
        
        traverse(obj, path)
        return findings

    def _analyze_pod_security(self, doc: Dict, file_path: str, kind: str, name: str) -> List[InfraVulnerability]:
        """Analyze pod security context"""
        vulnerabilities = []
        
        # Get pod spec (handle different resource types)
        if kind == 'Pod':
            pod_spec = doc.get('spec', {})
        else:
            pod_spec = doc.get('spec', {}).get('template', {}).get('spec', {})
        
        if not pod_spec:
            return vulnerabilities
        
        # Check for missing security context
        containers = pod_spec.get('containers', [])
        for i, container in enumerate(containers):
            container_name = container.get('name', f'container-{i}')
            
            if 'securityContext' not in container:
                vulnerabilities.append(InfraVulnerability(
                    id=f"K8S-SECURITY-CONTEXT-MISSING-{i}",
                    vulnerability_type=InfraVulnerabilityType.INSECURE_DEFAULTS,
                    severity=InfraSeverity.MEDIUM,
                    title="Missing security context",
                    description=f"Container {container_name} lacks security context configuration",
                    file_path=file_path,
                    resource_name=f"{kind}/{name}",
                    fix_recommendation="Add securityContext with appropriate security settings"
                ))
        
        return vulnerabilities


class TerraformAnalyzer:
    """Analyzer for Terraform security configurations"""
    
    def __init__(self):
        self.aws_security_rules = [
            {
                'resource_type': 'aws_security_group',
                'attribute': 'ingress.cidr_blocks',
                'pattern': r'0\.0\.0\.0/0',
                'type': InfraVulnerabilityType.NETWORK_EXPOSURE,
                'severity': InfraSeverity.HIGH,
                'title': 'Security group allows access from anywhere',
                'description': 'Security group rule allows inbound traffic from 0.0.0.0/0',
                'fix': 'Restrict source CIDR blocks to specific IP ranges'
            },
            {
                'resource_type': 'aws_s3_bucket',
                'attribute': 'acl',
                'pattern': r'public-read|public-read-write',
                'type': InfraVulnerabilityType.NETWORK_EXPOSURE,
                'severity': InfraSeverity.CRITICAL,
                'title': 'S3 bucket publicly accessible',
                'description': 'S3 bucket configured with public access',
                'fix': 'Use private ACL and configure bucket policies appropriately'
            },
            {
                'resource_type': 'aws_instance',
                'attribute': 'associate_public_ip_address',
                'pattern': r'true',
                'type': InfraVulnerabilityType.NETWORK_EXPOSURE,
                'severity': InfraSeverity.MEDIUM,
                'title': 'EC2 instance has public IP',
                'description': 'EC2 instance automatically gets public IP address',
                'fix': 'Set associate_public_ip_address to false for private instances'
            }
        ]

    def analyze_terraform_file(self, tf_file_path: str) -> List[InfraVulnerability]:
        """Analyze Terraform file for security issues"""
        vulnerabilities = []
        
        try:
            with open(tf_file_path, 'r') as f:
                content = f.read()
            
            # Simple HCL parsing (basic pattern matching)
            vulnerabilities.extend(self._analyze_terraform_patterns(content, tf_file_path))
            
        except Exception as e:
            logging.error(f"Error analyzing Terraform file {tf_file_path}: {e}")
            
        return vulnerabilities

    def _analyze_terraform_patterns(self, content: str, file_path: str) -> List[InfraVulnerability]:
        """Pattern-based analysis of Terraform content"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Track current resource context
        current_resource = None
        current_resource_line = 0
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Detect resource blocks
            resource_match = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"', line)
            if resource_match:
                current_resource = resource_match.group(1)
                current_resource_line = i
                continue
            
            # Check for security patterns
            for rule in self.aws_security_rules:
                if current_resource == rule['resource_type']:
                    if re.search(rule['pattern'], line, re.IGNORECASE):
                        vulnerabilities.append(InfraVulnerability(
                            id=f"TF-{rule['type'].value.upper()}-{i}",
                            vulnerability_type=rule['type'],
                            severity=rule['severity'],
                            title=rule['title'],
                            description=rule['description'],
                            file_path=file_path,
                            line_number=i,
                            resource_name=f"{current_resource} (line {current_resource_line})",
                            fix_recommendation=rule['fix'],
                            compliance_impact="AWS Security Best Practices"
                        ))
        
        return vulnerabilities


class InfrastructureSecurityScanner:
    """Main infrastructure security scanner"""
    
    def __init__(self):
        self.dockerfile_analyzer = DockerfileAnalyzer()
        self.k8s_analyzer = KubernetesAnalyzer()
        self.terraform_analyzer = TerraformAnalyzer()
        
        # File extension mapping
        self.analyzers = {
            'Dockerfile': self.dockerfile_analyzer.analyze_dockerfile,
            '.dockerfile': self.dockerfile_analyzer.analyze_dockerfile,
            '.yaml': self._analyze_yaml_file,
            '.yml': self._analyze_yaml_file,
            '.tf': self.terraform_analyzer.analyze_terraform_file,
            '.hcl': self.terraform_analyzer.analyze_terraform_file,
        }

    def scan_directory(self, directory_path: str, exclude_patterns: Optional[List[str]] = None) -> List[InfraVulnerability]:
        """Scan directory for infrastructure security issues"""
        vulnerabilities = []
        exclude_patterns = exclude_patterns or ['*/node_modules/*', '*/.git/*', '*/.terraform/*']
        
        for root, dirs, files in os.walk(directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(
                self._matches_pattern(os.path.join(root, d), pattern) 
                for pattern in exclude_patterns
            )]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip excluded files
                if any(self._matches_pattern(file_path, pattern) for pattern in exclude_patterns):
                    continue
                
                # Check file type and analyze
                analyzer = self._get_analyzer_for_file(file)
                if analyzer:
                    file_vulns = analyzer(file_path)
                    vulnerabilities.extend(file_vulns)
        
        return vulnerabilities

    def _get_analyzer_for_file(self, filename: str):
        """Get appropriate analyzer for file"""
        # Check exact filename matches first
        if filename in self.analyzers:
            return self.analyzers[filename]
        
        # Check for Dockerfile patterns (Dockerfile, Dockerfile.*, *.dockerfile)
        if (filename == 'Dockerfile' or 
            filename.startswith('Dockerfile.') or 
            filename.lower().endswith('.dockerfile')):
            return self.dockerfile_analyzer.analyze_dockerfile
        
        # Check extension matches
        for ext in ['.yaml', '.yml', '.tf', '.hcl']:
            if filename.lower().endswith(ext):
                return self.analyzers[ext]
        
        return None

    def _analyze_yaml_file(self, file_path: str) -> List[InfraVulnerability]:
        """Analyze YAML file (could be Kubernetes, Docker Compose, etc.)"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Try to detect file type from content
            if self._is_kubernetes_manifest(content):
                return self.k8s_analyzer.analyze_kubernetes_manifest(file_path)
            elif self._is_docker_compose(content):
                return self._analyze_docker_compose(file_path, content)
            
        except Exception as e:
            logging.error(f"Error analyzing YAML file {file_path}: {e}")
        
        return []

    def _is_kubernetes_manifest(self, content: str) -> bool:
        """Check if YAML content is a Kubernetes manifest"""
        k8s_keywords = ['apiVersion', 'kind', 'metadata', 'spec']
        return any(keyword in content for keyword in k8s_keywords)

    def _is_docker_compose(self, content: str) -> bool:
        """Check if YAML content is a Docker Compose file"""
        compose_keywords = ['version:', 'services:', 'volumes:', 'networks:']
        return any(keyword in content for keyword in compose_keywords)

    def _analyze_docker_compose(self, file_path: str, content: str) -> List[InfraVulnerability]:
        """Analyze Docker Compose file for security issues"""
        vulnerabilities = []
        
        try:
            compose_data = yaml.safe_load(content)
            services = compose_data.get('services', {})
            
            for service_name, service_config in services.items():
                # Check for privileged containers
                if service_config.get('privileged'):
                    vulnerabilities.append(InfraVulnerability(
                        id=f"COMPOSE-PRIVILEGED-{service_name}",
                        vulnerability_type=InfraVulnerabilityType.PRIVILEGE_ESCALATION,
                        severity=InfraSeverity.HIGH,
                        title="Privileged container in Docker Compose",
                        description=f"Service {service_name} runs in privileged mode",
                        file_path=file_path,
                        resource_name=f"service/{service_name}",
                        fix_recommendation="Remove privileged: true or use specific capabilities"
                    ))
                
                # Check for host network mode
                if service_config.get('network_mode') == 'host':
                    vulnerabilities.append(InfraVulnerability(
                        id=f"COMPOSE-HOST-NETWORK-{service_name}",
                        vulnerability_type=InfraVulnerabilityType.NETWORK_EXPOSURE,
                        severity=InfraSeverity.MEDIUM,
                        title="Host network mode in Docker Compose",
                        description=f"Service {service_name} uses host network mode",
                        file_path=file_path,
                        resource_name=f"service/{service_name}",
                        fix_recommendation="Use bridge network mode or custom networks"
                    ))
        
        except Exception as e:
            logging.error(f"Error parsing Docker Compose file {file_path}: {e}")
        
        return vulnerabilities

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches exclusion pattern"""
        import fnmatch
        return fnmatch.fnmatch(path, pattern)

    def scan_project(self, project_path: str, config: Optional[Dict] = None) -> Dict[str, Any]:
        """Comprehensive infrastructure security scan"""
        import time
        from datetime import datetime
        
        config = config or {}
        exclude_patterns = config.get('exclude_patterns', [])
        
        start_time = time.time()
        vulnerabilities = self.scan_directory(project_path, exclude_patterns)
        scan_time = time.time() - start_time
        
        # Convert vulnerabilities to dictionaries
        serialized_vulns = []
        for v in vulnerabilities:
            vuln_dict = asdict(v)
            vuln_dict['vulnerability_type'] = v.vulnerability_type.value
            vuln_dict['severity'] = v.severity.value
            serialized_vulns.append(vuln_dict)
        
        # Generate summary
        summary = self._generate_summary(vulnerabilities)
        
        results = {
            'scan_info': {
                'project_path': project_path,
                'scan_time': scan_time,
                'total_vulnerabilities': len(vulnerabilities),
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'infrastructure_security'
            },
            'summary': summary,
            'vulnerabilities': serialized_vulns,
            'files_scanned': self._get_files_scanned(project_path, exclude_patterns),
            'metrics': self._generate_metrics(vulnerabilities)
        }
        
        return results

    def _generate_summary(self, vulnerabilities: List[InfraVulnerability]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        severity_counts = {}
        type_counts = {}
        compliance_impacts = {}
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.vulnerability_type.value
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # Count compliance impacts
            if vuln.compliance_impact:
                compliance_impacts[vuln.compliance_impact] = compliance_impacts.get(vuln.compliance_impact, 0) + 1
        
        return {
            'severity_distribution': severity_counts,
            'vulnerability_types': type_counts,
            'compliance_frameworks': compliance_impacts,
            'total_files_with_issues': len(set(v.file_path for v in vulnerabilities))
        }

    def _get_files_scanned(self, project_path: str, exclude_patterns: List[str]) -> List[str]:
        """Get list of files that were scanned"""
        files_scanned = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                if (self._get_analyzer_for_file(file) and 
                    not any(self._matches_pattern(file_path, pattern) for pattern in exclude_patterns)):
                    files_scanned.append(file_path)
        
        return files_scanned

    def _generate_metrics(self, vulnerabilities: List[InfraVulnerability]) -> Dict[str, Any]:
        """Generate scan metrics"""
        if not vulnerabilities:
            return {'risk_score': 0, 'confidence_avg': 0}
        
        # Calculate risk score based on severity
        severity_weights = {
            InfraSeverity.CRITICAL: 10,
            InfraSeverity.HIGH: 7,
            InfraSeverity.MEDIUM: 4,
            InfraSeverity.LOW: 2,
            InfraSeverity.INFO: 1
        }
        
        total_risk = sum(severity_weights.get(v.severity, 1) for v in vulnerabilities)
        avg_confidence = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)
        
        return {
            'risk_score': total_risk,
            'confidence_avg': round(avg_confidence, 2),
            'high_confidence_count': len([v for v in vulnerabilities if v.confidence >= 0.8]),
            'compliance_violations': len(set(v.compliance_impact for v in vulnerabilities if v.compliance_impact))
        }


# Global instance
infra_scanner = InfrastructureSecurityScanner()

def scan_infrastructure_security(project_path: str, config: Optional[Dict] = None) -> Dict[str, Any]:
    """Main entry point for infrastructure security scanning"""
    return infra_scanner.scan_project(project_path, config)