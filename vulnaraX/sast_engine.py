"""
Advanced Static Application Security Testing (SAST) Engine
Provides AST-based code analysis for multiple programming languages
"""

import ast
import os
import re
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

# Try to import tree-sitter for advanced parsing
try:
    import tree_sitter
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
    logging.warning("tree-sitter not available. Using basic AST analysis only.")


class VulnerabilityType(Enum):
    """Types of vulnerabilities detected by SAST"""
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    HARDCODED_SECRETS = "hardcoded_secrets"
    WEAK_CRYPTO = "weak_cryptography"
    UNSAFE_REFLECTION = "unsafe_reflection"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    INSECURE_RANDOM = "insecure_random"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    INSECURE_REDIRECT = "insecure_redirect"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeLocation:
    """Represents a location in source code"""
    file_path: str
    line_number: int
    column_number: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None


@dataclass
class VulnerabilityMatch:
    """Represents a vulnerability found in code"""
    id: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    location: CodeLocation
    code_snippet: str
    fix_suggestion: Optional[str] = None
    confidence: float = 1.0
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class LanguageAnalyzer(ABC):
    """Abstract base class for language-specific analyzers"""
    
    @abstractmethod
    def analyze_file(self, file_path: str) -> List[VulnerabilityMatch]:
        """Analyze a single file and return vulnerabilities"""
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """Return list of supported file extensions"""
        pass


class PythonAnalyzer(LanguageAnalyzer):
    """Python static analysis using AST"""
    
    def __init__(self):
        self.dangerous_functions = {
            'eval': VulnerabilityType.UNSAFE_REFLECTION,
            'exec': VulnerabilityType.UNSAFE_REFLECTION,
            'compile': VulnerabilityType.UNSAFE_REFLECTION,
            'subprocess.call': VulnerabilityType.COMMAND_INJECTION,
            'subprocess.run': VulnerabilityType.COMMAND_INJECTION,
            'subprocess.Popen': VulnerabilityType.COMMAND_INJECTION,
            'os.system': VulnerabilityType.COMMAND_INJECTION,
            'os.popen': VulnerabilityType.COMMAND_INJECTION,
            'pickle.loads': VulnerabilityType.INSECURE_DESERIALIZATION,
            'pickle.load': VulnerabilityType.INSECURE_DESERIALIZATION,
            'yaml.load': VulnerabilityType.INSECURE_DESERIALIZATION,
        }
        
        self.sql_patterns = [
            r'SELECT.*FROM.*WHERE.*\+.*',
            r'INSERT.*INTO.*VALUES.*\+.*',
            r'UPDATE.*SET.*WHERE.*\+.*',
            r'DELETE.*FROM.*WHERE.*\+.*',
        ]
        
        self.secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*=\s*["\'][^"\']{16,}["\']', 'Hardcoded API key'),
            (r'secret[_-]?key\s*=\s*["\'][^"\']{16,}["\']', 'Hardcoded secret key'),
            (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\'][^"\']+["\']', 'AWS Access Key'),
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
            (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
        ]
        
        self.weak_crypto_functions = {
            'md5', 'sha1', 'des', 'rc4', 'md4'
        }

    def analyze_file(self, file_path: str) -> List[VulnerabilityMatch]:
        """Analyze Python file using AST"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content, filename=file_path)
            
            # Analyze AST nodes
            vulnerabilities.extend(self._analyze_ast(tree, file_path, content))
            
            # Pattern-based analysis
            vulnerabilities.extend(self._analyze_patterns(content, file_path))
            
        except Exception as e:
            logging.error(f"Error analyzing Python file {file_path}: {e}")
            
        return vulnerabilities

    def _analyze_ast(self, tree: ast.AST, file_path: str, content: str) -> List[VulnerabilityMatch]:
        """Analyze AST for vulnerabilities"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            # Check function calls
            if isinstance(node, ast.Call):
                vuln = self._check_dangerous_call(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Check string operations for SQL injection
            elif isinstance(node, ast.BinOp):
                if isinstance(node.op, ast.Add):
                    vuln = self._check_string_concat(node, file_path, lines)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            # Check assignments for hardcoded secrets
            elif isinstance(node, ast.Assign):
                vuln = self._check_assignment(node, file_path, lines)
                if vuln:
                    vulnerabilities.append(vuln)
                    
        return vulnerabilities

    def _check_dangerous_call(self, node: ast.Call, file_path: str, lines: List[str]) -> Optional[VulnerabilityMatch]:
        """Check for dangerous function calls"""
        func_name = self._get_function_name(node.func)
        
        if func_name in self.dangerous_functions:
            vuln_type = self.dangerous_functions[func_name]
            
            # Get code snippet
            line_num = node.lineno
            code_snippet = lines[line_num - 1] if line_num <= len(lines) else ""
            
            severity = Severity.HIGH
            if vuln_type in [VulnerabilityType.UNSAFE_REFLECTION, VulnerabilityType.COMMAND_INJECTION]:
                severity = Severity.CRITICAL
                
            return VulnerabilityMatch(
                id=f"SAST-{vuln_type.value.upper()}-{line_num}",
                vulnerability_type=vuln_type,
                severity=severity,
                title=f"Dangerous function call: {func_name}",
                description=f"Use of potentially dangerous function '{func_name}' detected",
                location=CodeLocation(
                    file_path=file_path,
                    line_number=line_num,
                    column_number=node.col_offset + 1
                ),
                code_snippet=code_snippet.strip(),
                fix_suggestion=self._get_fix_suggestion(vuln_type, func_name),
                cwe_id=self._get_cwe_id(vuln_type)
            )
            
        return None

    def _check_string_concat(self, node: ast.BinOp, file_path: str, lines: List[str]) -> Optional[VulnerabilityMatch]:
        """Check string concatenation for SQL injection patterns"""
        line_num = node.lineno
        code_snippet = lines[line_num - 1] if line_num <= len(lines) else ""
        
        # Look for SQL-like patterns in string concatenation
        for pattern in self.sql_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return VulnerabilityMatch(
                    id=f"SAST-SQL-{line_num}",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="Potential SQL Injection",
                    description="SQL query construction using string concatenation detected",
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_num,
                        column_number=node.col_offset + 1
                    ),
                    code_snippet=code_snippet.strip(),
                    fix_suggestion="Use parameterized queries or ORM methods instead of string concatenation",
                    cwe_id="CWE-89",
                    confidence=0.8
                )
                
        return None

    def _check_assignment(self, node: ast.Assign, file_path: str, lines: List[str]) -> Optional[VulnerabilityMatch]:
        """Check assignments for hardcoded secrets"""
        line_num = node.lineno
        code_snippet = lines[line_num - 1] if line_num <= len(lines) else ""
        
        for pattern, description in self.secret_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return VulnerabilityMatch(
                    id=f"SAST-SECRET-{line_num}",
                    vulnerability_type=VulnerabilityType.HARDCODED_SECRETS,
                    severity=Severity.MEDIUM,
                    title="Hardcoded Secret Detected",
                    description=f"{description} found in source code",
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_num,
                        column_number=1
                    ),
                    code_snippet=code_snippet.strip(),
                    fix_suggestion="Use environment variables or secure configuration management",
                    cwe_id="CWE-798"
                )
                
        return None

    def _analyze_patterns(self, content: str, file_path: str) -> List[VulnerabilityMatch]:
        """Pattern-based analysis for additional vulnerabilities"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Check for weak cryptography
        for i, line in enumerate(lines, 1):
            for weak_func in self.weak_crypto_functions:
                if weak_func in line.lower():
                    vulnerabilities.append(VulnerabilityMatch(
                        id=f"SAST-CRYPTO-{i}",
                        vulnerability_type=VulnerabilityType.WEAK_CRYPTO,
                        severity=Severity.MEDIUM,
                        title=f"Weak cryptographic algorithm: {weak_func}",
                        description=f"Use of weak cryptographic algorithm '{weak_func}' detected",
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=i,
                            column_number=1
                        ),
                        code_snippet=line.strip(),
                        fix_suggestion="Use strong cryptographic algorithms like SHA-256, AES, etc.",
                        cwe_id="CWE-327"
                    ))
                    
        return vulnerabilities

    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Handle module.function calls
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            else:
                return node.attr
        return ""

    def _get_fix_suggestion(self, vuln_type: VulnerabilityType, func_name: str) -> str:
        """Get fix suggestion for vulnerability type"""
        suggestions = {
            VulnerabilityType.UNSAFE_REFLECTION: "Avoid using eval/exec. Use safer alternatives like ast.literal_eval for data parsing",
            VulnerabilityType.COMMAND_INJECTION: "Use subprocess with shell=False and pass arguments as a list",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Use safe serialization formats like JSON or validate input before deserializing",
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or ORM methods",
            VulnerabilityType.HARDCODED_SECRETS: "Use environment variables or secure configuration management"
        }
        return suggestions.get(vuln_type, "Review and remediate this security issue")

    def _get_cwe_id(self, vuln_type: VulnerabilityType) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_mapping = {
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
            VulnerabilityType.INSECURE_DESERIALIZATION: "CWE-502",
            VulnerabilityType.HARDCODED_SECRETS: "CWE-798",
            VulnerabilityType.WEAK_CRYPTO: "CWE-327",
            VulnerabilityType.UNSAFE_REFLECTION: "CWE-95"
        }
        return cwe_mapping.get(vuln_type, "CWE-0")

    def get_supported_extensions(self) -> List[str]:
        """Return supported Python file extensions"""
        return ['.py', '.pyx', '.pyi']


class JavaScriptAnalyzer(LanguageAnalyzer):
    """JavaScript/TypeScript static analysis"""
    
    def __init__(self):
        self.dangerous_patterns = [
            (r'eval\s*\(', VulnerabilityType.UNSAFE_REFLECTION, "Use of eval() function"),
            (r'innerHTML\s*=.*\+', VulnerabilityType.XSS, "Potential XSS via innerHTML"),
            (r'document\.write\s*\(.*\+', VulnerabilityType.XSS, "Potential XSS via document.write"),
            (r'exec\s*\(', VulnerabilityType.COMMAND_INJECTION, "Command execution function"),
            (r'child_process\.exec', VulnerabilityType.COMMAND_INJECTION, "Node.js command execution"),
        ]
        
    def analyze_file(self, file_path: str) -> List[VulnerabilityMatch]:
        """Analyze JavaScript file"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                for pattern, vuln_type, description in self.dangerous_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append(VulnerabilityMatch(
                            id=f"SAST-JS-{vuln_type.value.upper()}-{i}",
                            vulnerability_type=vuln_type,
                            severity=Severity.HIGH,
                            title=description,
                            description=f"{description} detected in JavaScript code",
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=i,
                                column_number=1
                            ),
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_js_fix_suggestion(vuln_type),
                            cwe_id=self._get_cwe_id(vuln_type)
                        ))
                        
        except Exception as e:
            logging.error(f"Error analyzing JavaScript file {file_path}: {e}")
            
        return vulnerabilities
    
    def _get_js_fix_suggestion(self, vuln_type: VulnerabilityType) -> str:
        """Get JavaScript-specific fix suggestions"""
        suggestions = {
            VulnerabilityType.UNSAFE_REFLECTION: "Avoid eval(). Use JSON.parse() for data or safer alternatives",
            VulnerabilityType.XSS: "Use textContent instead of innerHTML, or sanitize user input",
            VulnerabilityType.COMMAND_INJECTION: "Validate and sanitize all input before executing commands"
        }
        return suggestions.get(vuln_type, "Review and remediate this security issue")
    
    def _get_cwe_id(self, vuln_type: VulnerabilityType) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_mapping = {
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.UNSAFE_REFLECTION: "CWE-95"
        }
        return cwe_mapping.get(vuln_type, "CWE-0")
    
    def get_supported_extensions(self) -> List[str]:
        """Return supported JavaScript file extensions"""
        return ['.js', '.jsx', '.ts', '.tsx', '.vue']


class SASTEngine:
    """Main Static Application Security Testing engine"""
    
    def __init__(self):
        self.analyzers = {
            'python': PythonAnalyzer(),
            'javascript': JavaScriptAnalyzer(),
        }
        
        # Map file extensions to analyzers
        self.extension_map = {}
        for lang, analyzer in self.analyzers.items():
            for ext in analyzer.get_supported_extensions():
                self.extension_map[ext] = analyzer
                
        self.logger = logging.getLogger(__name__)

    def scan_file(self, file_path: str) -> List[VulnerabilityMatch]:
        """Scan a single file for vulnerabilities"""
        file_ext = Path(file_path).suffix.lower()
        analyzer = self.extension_map.get(file_ext)
        
        if not analyzer:
            return []
            
        return analyzer.analyze_file(file_path)

    def scan_directory(self, directory_path: str, exclude_patterns: Optional[List[str]] = None) -> List[VulnerabilityMatch]:
        """Scan directory recursively for vulnerabilities"""
        vulnerabilities = []
        exclude_patterns = exclude_patterns or [
            '*/node_modules/*', '*/.git/*', '*/__pycache__/*', 
            '*/venv/*', '*/env/*', '*/build/*', '*/dist/*'
        ]
        
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
                    
                file_ext = Path(file_path).suffix.lower()
                if file_ext in self.extension_map:
                    file_vulns = self.scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
                    
        return vulnerabilities

    def scan_project(self, project_path: str, config: Optional[Dict] = None) -> Dict[str, Any]:
        """Comprehensive project scan with detailed results"""
        config = config or {}
        exclude_patterns = config.get('exclude_patterns', [])
        
        start_time = time.time()
        vulnerabilities = self.scan_directory(project_path, exclude_patterns)
        scan_time = time.time() - start_time
        
        # Convert vulnerabilities to dictionaries with proper serialization
        serialized_vulns = []
        for v in vulnerabilities:
            vuln_dict = asdict(v)
            # Convert enums to strings
            vuln_dict['vulnerability_type'] = v.vulnerability_type.value
            vuln_dict['severity'] = v.severity.value
            serialized_vulns.append(vuln_dict)
        
        # Aggregate results
        results = {
            'scan_info': {
                'project_path': project_path,
                'scan_time': scan_time,
                'total_vulnerabilities': len(vulnerabilities),
                'timestamp': datetime.now().isoformat()
            },
            'summary': self._generate_summary(vulnerabilities),
            'vulnerabilities': serialized_vulns,
            'files_scanned': self._get_files_scanned(project_path, exclude_patterns),
            'metrics': self._generate_metrics(vulnerabilities)
        }
        
        return results

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches exclusion pattern"""
        import fnmatch
        return fnmatch.fnmatch(path, pattern)

    def _generate_summary(self, vulnerabilities: List[VulnerabilityMatch]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        severity_counts = {}
        type_counts = {}
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.vulnerability_type.value
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
        return {
            'severity_distribution': severity_counts,
            'vulnerability_types': type_counts,
            'total_files_with_issues': len(set(v.location.file_path for v in vulnerabilities))
        }

    def _get_files_scanned(self, project_path: str, exclude_patterns: List[str]) -> List[str]:
        """Get list of files that were scanned"""
        files_scanned = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = Path(file_path).suffix.lower()
                
                if (file_ext in self.extension_map and 
                    not any(self._matches_pattern(file_path, pattern) for pattern in exclude_patterns)):
                    files_scanned.append(file_path)
                    
        return files_scanned

    def _generate_metrics(self, vulnerabilities: List[VulnerabilityMatch]) -> Dict[str, Any]:
        """Generate scan metrics"""
        if not vulnerabilities:
            return {'risk_score': 0, 'confidence_avg': 0}
            
        # Calculate risk score based on severity
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        
        total_risk = sum(severity_weights.get(v.severity, 1) for v in vulnerabilities)
        avg_confidence = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)
        
        return {
            'risk_score': total_risk,
            'confidence_avg': round(avg_confidence, 2),
            'high_confidence_count': len([v for v in vulnerabilities if v.confidence >= 0.8])
        }


# Global instance
sast_engine = SASTEngine()

def scan_code_security(project_path: str, config: Optional[Dict] = None) -> Dict[str, Any]:
    """Main entry point for static code analysis"""
    return sast_engine.scan_project(project_path, config)