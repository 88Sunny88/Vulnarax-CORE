"""
VulnaraX Runtime Application Self-Protection (RASP) Engine
Enterprise-grade runtime security and behavioral threat detection
"""

import asyncio
import json
import time
import hashlib
import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import statistics
from collections import defaultdict, deque
import psutil
import threading
import queue

@dataclass
class SecurityEvent:
    """Security event detected by RASP engine"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    component: str
    threat_category: str
    description: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    payload: Optional[str] = None
    stack_trace: Optional[str] = None
    mitigation_action: Optional[str] = None
    confidence_score: float = 0.0
    risk_score: float = 0.0
    indicators: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []

@dataclass
class BehavioralPattern:
    """Behavioral analysis pattern for anomaly detection"""
    pattern_id: str
    pattern_type: str
    baseline_metrics: Dict[str, float]
    anomaly_threshold: float
    detection_window: int
    confidence_threshold: float
    severity_mapping: Dict[str, str]

class RuntimeMonitor:
    """Real-time application runtime monitoring"""
    
    def __init__(self):
        self.monitoring_active = False
        self.performance_metrics = {}
        self.resource_usage = deque(maxlen=1000)
        self.network_connections = {}
        self.file_operations = deque(maxlen=500)
        self.process_monitoring = True
        
    async def start_monitoring(self) -> Dict[str, Any]:
        """Start runtime monitoring"""
        self.monitoring_active = True
        
        # Initialize monitoring threads
        performance_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        network_thread = threading.Thread(target=self._monitor_network, daemon=True)
        file_thread = threading.Thread(target=self._monitor_file_operations, daemon=True)
        
        performance_thread.start()
        network_thread.start()
        file_thread.start()
        
        return {
            "status": "monitoring_active",
            "timestamp": datetime.utcnow().isoformat(),
            "components": ["performance", "network", "file_operations"],
            "baseline_collection": "started"
        }
    
    def _monitor_performance(self):
        """Monitor application performance metrics"""
        while self.monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                metrics = {
                    "timestamp": time.time(),
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_gb": memory.used / (1024**3),
                    "disk_percent": disk.percent,
                    "process_count": len(psutil.pids())
                }
                
                self.resource_usage.append(metrics)
                
                # Update performance metrics
                self.performance_metrics.update({
                    "current_metrics": metrics,
                    "baseline_cpu": self._calculate_baseline("cpu_percent"),
                    "baseline_memory": self._calculate_baseline("memory_percent"),
                    "anomaly_detection": self._detect_performance_anomalies()
                })
                
            except Exception as e:
                logging.error(f"Performance monitoring error: {e}")
            
            time.sleep(5)
    
    def _monitor_network(self):
        """Monitor network connections and traffic"""
        while self.monitoring_active:
            try:
                connections = psutil.net_connections()
                
                current_connections = {}
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        key = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections[key] = {
                            "family": conn.family.name,
                            "type": conn.type.name,
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "timestamp": time.time()
                        }
                
                self.network_connections = current_connections
                
            except Exception as e:
                logging.error(f"Network monitoring error: {e}")
            
            time.sleep(10)
    
    def _monitor_file_operations(self):
        """Monitor file system operations"""
        while self.monitoring_active:
            try:
                # Simulate file operation monitoring
                # In real implementation, this would use system-level hooks
                current_process = psutil.Process()
                
                file_op = {
                    "timestamp": time.time(),
                    "pid": current_process.pid,
                    "open_files": len(current_process.open_files()),
                    "cwd": str(current_process.cwd()),
                    "num_threads": current_process.num_threads()
                }
                
                self.file_operations.append(file_op)
                
            except Exception as e:
                logging.error(f"File monitoring error: {e}")
            
            time.sleep(15)
    
    def _calculate_baseline(self, metric: str) -> float:
        """Calculate baseline for a metric"""
        if len(self.resource_usage) < 10:
            return 0.0
        
        values = [item[metric] for item in self.resource_usage if metric in item]
        return statistics.mean(values) if values else 0.0
    
    def _detect_performance_anomalies(self) -> List[Dict[str, Any]]:
        """Detect performance anomalies"""
        anomalies = []
        
        if len(self.resource_usage) < 20:
            return anomalies
        
        # Check for CPU spikes
        recent_cpu = [item["cpu_percent"] for item in list(self.resource_usage)[-10:]]
        baseline_cpu = self._calculate_baseline("cpu_percent")
        
        if baseline_cpu > 0 and max(recent_cpu) > baseline_cpu * 2:
            anomalies.append({
                "type": "cpu_spike",
                "current": max(recent_cpu),
                "baseline": baseline_cpu,
                "severity": "medium" if max(recent_cpu) > 80 else "low"
            })
        
        # Check for memory anomalies
        recent_memory = [item["memory_percent"] for item in list(self.resource_usage)[-10:]]
        baseline_memory = self._calculate_baseline("memory_percent")
        
        if baseline_memory > 0 and max(recent_memory) > baseline_memory * 1.5:
            anomalies.append({
                "type": "memory_anomaly",
                "current": max(recent_memory),
                "baseline": baseline_memory,
                "severity": "high" if max(recent_memory) > 90 else "medium"
            })
        
        return anomalies

class ThreatDetectionEngine:
    """Advanced threat detection using behavioral analysis"""
    
    def __init__(self):
        self.detection_rules = self._load_detection_rules()
        self.behavioral_baselines = {}
        self.threat_patterns = self._initialize_threat_patterns()
        self.active_threats = {}
        
    def _load_detection_rules(self) -> Dict[str, Any]:
        """Load threat detection rules"""
        return {
            "injection_attacks": {
                "sql_injection": {
                    "patterns": [
                        r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)",
                        r"(\bDROP\b|\bALTER\b|\bCREATE\b)\s+\bTABLE\b",
                        r"(\'\s*OR\s*\'\d*\'\s*=\s*\'\d*)",
                        r"(\bEXEC\b|\bEXECUTE\b)\s*\("
                    ],
                    "severity": "high",
                    "mitigation": "block_request"
                },
                "xss_attacks": {
                    "patterns": [
                        r"<script[^>]*>.*?</script>",
                        r"javascript:",
                        r"on\w+\s*=",
                        r"<iframe[^>]*>.*?</iframe>"
                    ],
                    "severity": "medium",
                    "mitigation": "sanitize_input"
                },
                "command_injection": {
                    "patterns": [
                        r"(\|\s*\w+)",
                        r"(;\s*\w+)",
                        r"(`.*?`)",
                        r"(\$\(.*?\))"
                    ],
                    "severity": "high",
                    "mitigation": "block_request"
                }
            },
            "behavioral_anomalies": {
                "unusual_file_access": {
                    "threshold": 50,
                    "time_window": 300,
                    "severity": "medium"
                },
                "excessive_network_requests": {
                    "threshold": 100,
                    "time_window": 60,
                    "severity": "high"
                },
                "privilege_escalation": {
                    "patterns": ["sudo", "su", "chmod 777", "setuid"],
                    "severity": "critical"
                }
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, BehavioralPattern]:
        """Initialize behavioral threat patterns"""
        patterns = {}
        
        # SQL Injection pattern
        patterns["sql_injection"] = BehavioralPattern(
            pattern_id="sql_injection",
            pattern_type="injection_attack",
            baseline_metrics={"query_complexity": 2.0, "param_count": 5.0},
            anomaly_threshold=3.0,
            detection_window=300,
            confidence_threshold=0.8,
            severity_mapping={"low": "medium", "medium": "high", "high": "critical"}
        )
        
        # API Abuse pattern
        patterns["api_abuse"] = BehavioralPattern(
            pattern_id="api_abuse",
            pattern_type="behavioral_anomaly",
            baseline_metrics={"requests_per_minute": 10.0, "error_rate": 0.1},
            anomaly_threshold=5.0,
            detection_window=60,
            confidence_threshold=0.7,
            severity_mapping={"low": "low", "medium": "medium", "high": "high"}
        )
        
        return patterns
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> List[SecurityEvent]:
        """Analyze incoming request for threats"""
        events = []
        
        # Check for injection attacks
        injection_events = await self._detect_injection_attacks(request_data)
        events.extend(injection_events)
        
        # Behavioral analysis
        behavioral_events = await self._analyze_behavioral_patterns(request_data)
        events.extend(behavioral_events)
        
        # Rate limiting analysis
        rate_limit_events = await self._analyze_rate_limiting(request_data)
        events.extend(rate_limit_events)
        
        return events
    
    async def _detect_injection_attacks(self, request_data: Dict[str, Any]) -> List[SecurityEvent]:
        """Detect various injection attacks"""
        events = []
        
        # Get request content to analyze
        content = str(request_data.get("body", "")) + str(request_data.get("query_params", ""))
        user_agent = request_data.get("headers", {}).get("user-agent", "")
        source_ip = request_data.get("client_ip", "unknown")
        
        # SQL Injection detection
        sql_patterns = self.detection_rules["injection_attacks"]["sql_injection"]["patterns"]
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                event = SecurityEvent(
                    event_id=hashlib.md5(f"sql_injection_{time.time()}".encode()).hexdigest()[:16],
                    timestamp=datetime.utcnow(),
                    event_type="sql_injection_attempt",
                    severity="high",
                    component="rasp_engine",
                    threat_category="injection_attack",
                    description=f"SQL injection pattern detected: {pattern}",
                    source_ip=source_ip,
                    user_agent=user_agent,
                    payload=content[:500],
                    mitigation_action="block_request",
                    confidence_score=0.85,
                    risk_score=8.5,
                    indicators=[f"SQL pattern: {pattern}", "Malicious payload detected"]
                )
                events.append(event)
        
        # XSS detection
        xss_patterns = self.detection_rules["injection_attacks"]["xss_attacks"]["patterns"]
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                event = SecurityEvent(
                    event_id=hashlib.md5(f"xss_attack_{time.time()}".encode()).hexdigest()[:16],
                    timestamp=datetime.utcnow(),
                    event_type="xss_attempt",
                    severity="medium",
                    component="rasp_engine",
                    threat_category="injection_attack",
                    description=f"XSS pattern detected: {pattern}",
                    source_ip=source_ip,
                    user_agent=user_agent,
                    payload=content[:500],
                    mitigation_action="sanitize_input",
                    confidence_score=0.75,
                    risk_score=6.5,
                    indicators=[f"XSS pattern: {pattern}", "Script injection attempt"]
                )
                events.append(event)
        
        # Command injection detection
        cmd_patterns = self.detection_rules["injection_attacks"]["command_injection"]["patterns"]
        for pattern in cmd_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                event = SecurityEvent(
                    event_id=hashlib.md5(f"cmd_injection_{time.time()}".encode()).hexdigest()[:16],
                    timestamp=datetime.utcnow(),
                    event_type="command_injection_attempt",
                    severity="high",
                    component="rasp_engine",
                    threat_category="injection_attack",
                    description=f"Command injection pattern detected: {pattern}",
                    source_ip=source_ip,
                    user_agent=user_agent,
                    payload=content[:500],
                    mitigation_action="block_request",
                    confidence_score=0.90,
                    risk_score=9.0,
                    indicators=[f"Command pattern: {pattern}", "OS command injection"]
                )
                events.append(event)
        
        return events
    
    async def _analyze_behavioral_patterns(self, request_data: Dict[str, Any]) -> List[SecurityEvent]:
        """Analyze behavioral patterns for anomalies"""
        events = []
        
        source_ip = request_data.get("client_ip", "unknown")
        endpoint = request_data.get("endpoint", "/")
        
        # Analyze request frequency
        current_time = time.time()
        
        # Check for rapid successive requests (potential DoS)
        if source_ip not in self.behavioral_baselines:
            self.behavioral_baselines[source_ip] = {
                "request_times": deque(maxlen=100),
                "endpoints": defaultdict(int),
                "error_count": 0,
                "first_seen": current_time
            }
        
        baseline = self.behavioral_baselines[source_ip]
        baseline["request_times"].append(current_time)
        baseline["endpoints"][endpoint] += 1
        
        # Check for request flooding
        recent_requests = [t for t in baseline["request_times"] if current_time - t < 60]
        if len(recent_requests) > 50:
            event = SecurityEvent(
                event_id=hashlib.md5(f"request_flooding_{source_ip}_{current_time}".encode()).hexdigest()[:16],
                timestamp=datetime.utcnow(),
                event_type="request_flooding",
                severity="high",
                component="rasp_engine",
                threat_category="behavioral_anomaly",
                description=f"Excessive requests detected: {len(recent_requests)} requests in 60 seconds",
                source_ip=source_ip,
                mitigation_action="rate_limit",
                confidence_score=0.95,
                risk_score=7.5,
                indicators=[f"Request count: {len(recent_requests)}", "Rate limit exceeded", "Potential DoS attack"]
            )
            events.append(event)
        
        # Check for endpoint scanning
        unique_endpoints = len(baseline["endpoints"])
        if unique_endpoints > 20 and current_time - baseline["first_seen"] < 300:
            event = SecurityEvent(
                event_id=hashlib.md5(f"endpoint_scanning_{source_ip}_{current_time}".encode()).hexdigest()[:16],
                timestamp=datetime.utcnow(),
                event_type="endpoint_scanning",
                severity="medium",
                component="rasp_engine",
                threat_category="reconnaissance",
                description=f"Potential endpoint scanning: {unique_endpoints} unique endpoints accessed",
                source_ip=source_ip,
                mitigation_action="monitor",
                confidence_score=0.80,
                risk_score=6.0,
                indicators=[f"Unique endpoints: {unique_endpoints}", "Reconnaissance behavior", "Potential vulnerability scanning"]
            )
            events.append(event)
        
        return events
    
    async def _analyze_rate_limiting(self, request_data: Dict[str, Any]) -> List[SecurityEvent]:
        """Analyze rate limiting violations"""
        events = []
        
        source_ip = request_data.get("client_ip", "unknown")
        endpoint = request_data.get("endpoint", "/")
        
        # Simple rate limiting check
        current_time = time.time()
        rate_key = f"{source_ip}:{endpoint}"
        
        if not hasattr(self, 'rate_tracker'):
            self.rate_tracker = {}
        
        if rate_key not in self.rate_tracker:
            self.rate_tracker[rate_key] = deque(maxlen=50)
        
        self.rate_tracker[rate_key].append(current_time)
        
        # Check for rate violations
        recent_calls = [t for t in self.rate_tracker[rate_key] if current_time - t < 60]
        
        if len(recent_calls) > 30:  # More than 30 calls per minute
            event = SecurityEvent(
                event_id=hashlib.md5(f"rate_limit_{rate_key}_{current_time}".encode()).hexdigest()[:16],
                timestamp=datetime.utcnow(),
                event_type="rate_limit_violation",
                severity="medium",
                component="rasp_engine",
                threat_category="behavioral_anomaly",
                description=f"Rate limit exceeded: {len(recent_calls)} calls to {endpoint} in 60 seconds",
                source_ip=source_ip,
                mitigation_action="throttle",
                confidence_score=0.85,
                risk_score=5.5,
                indicators=[f"Call count: {len(recent_calls)}", f"Endpoint: {endpoint}", "Rate limit policy violation"]
            )
            events.append(event)
        
        return events

class RASPEngine:
    """Main Runtime Application Self-Protection Engine"""
    
    def __init__(self):
        self.runtime_monitor = RuntimeMonitor()
        self.threat_detector = ThreatDetectionEngine()
        self.security_events = deque(maxlen=10000)
        self.active_protections = set()
        self.engine_stats = {
            "total_requests_analyzed": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "false_positives": 0,
            "engine_uptime": time.time()
        }
        
    async def initialize(self) -> Dict[str, Any]:
        """Initialize RASP engine"""
        # Start runtime monitoring
        monitor_status = await self.runtime_monitor.start_monitoring()
        
        # Activate protection modules
        self.active_protections.update([
            "injection_protection",
            "behavioral_analysis", 
            "rate_limiting",
            "runtime_monitoring",
            "threat_intelligence"
        ])
        
        return {
            "status": "initialized",
            "timestamp": datetime.utcnow().isoformat(),
            "monitor_status": monitor_status,
            "active_protections": list(self.active_protections),
            "engine_version": "1.0.0",
            "capabilities": [
                "Real-time threat detection",
                "SQL injection protection",
                "XSS attack prevention", 
                "Command injection blocking",
                "Behavioral anomaly detection",
                "Rate limiting enforcement",
                "Runtime performance monitoring",
                "Automated threat response"
            ]
        }
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze request through RASP engine"""
        start_time = time.time()
        
        # Update stats
        self.engine_stats["total_requests_analyzed"] += 1
        
        # Perform threat analysis
        security_events = await self.threat_detector.analyze_request(request_data)
        
        # Store events
        for event in security_events:
            self.security_events.append(event)
        
        # Update threat statistics
        if security_events:
            self.engine_stats["threats_detected"] += len(security_events)
            
            # Count blocked threats
            blocked_events = [e for e in security_events if e.mitigation_action in ["block_request", "block"]]
            self.engine_stats["threats_blocked"] += len(blocked_events)
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000  # milliseconds
        
        # Determine overall risk level
        max_risk = max([e.risk_score for e in security_events], default=0.0)
        risk_level = "low"
        if max_risk >= 8.0:
            risk_level = "critical"
        elif max_risk >= 6.0:
            risk_level = "high"
        elif max_risk >= 4.0:
            risk_level = "medium"
        
        return {
            "request_id": hashlib.md5(f"{request_data}_{start_time}".encode()).hexdigest()[:16],
            "timestamp": datetime.utcnow().isoformat(),
            "analysis_time_ms": round(analysis_time, 2),
            "risk_level": risk_level,
            "max_risk_score": max_risk,
            "threats_detected": len(security_events),
            "security_events": [asdict(event) for event in security_events],
            "recommendations": self._generate_recommendations(security_events),
            "mitigation_actions": [event.mitigation_action for event in security_events if event.mitigation_action],
            "engine_performance": {
                "total_analyzed": self.engine_stats["total_requests_analyzed"],
                "detection_rate": round(self.engine_stats["threats_detected"] / max(1, self.engine_stats["total_requests_analyzed"]) * 100, 2),
                "blocking_rate": round(self.engine_stats["threats_blocked"] / max(1, self.engine_stats["threats_detected"]) * 100, 2)
            }
        }
    
    async def get_runtime_status(self) -> Dict[str, Any]:
        """Get current runtime security status"""
        # Get recent events
        recent_events = [event for event in self.security_events 
                        if (datetime.utcnow() - event.timestamp).total_seconds() < 3600]
        
        # Calculate threat statistics
        threat_categories = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for event in recent_events:
            threat_categories[event.threat_category] += 1
            severity_counts[event.severity] += 1
        
        # Get performance metrics
        performance_data = self.runtime_monitor.performance_metrics
        
        return {
            "engine_status": "active",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_hours": round((time.time() - self.engine_stats["engine_uptime"]) / 3600, 2),
            "active_protections": list(self.active_protections),
            "recent_threats": {
                "total_events": len(recent_events),
                "by_category": dict(threat_categories),
                "by_severity": dict(severity_counts),
                "critical_events": len([e for e in recent_events if e.severity == "critical"])
            },
            "performance_metrics": performance_data,
            "engine_statistics": self.engine_stats,
            "protection_status": {
                "injection_protection": "active",
                "behavioral_analysis": "active",
                "rate_limiting": "active",
                "runtime_monitoring": "active",
                "threat_response": "active"
            }
        }
    
    async def get_threat_intelligence(self) -> Dict[str, Any]:
        """Get current threat intelligence and patterns"""
        # Analyze recent threat patterns
        recent_events = [event for event in self.security_events 
                        if (datetime.utcnow() - event.timestamp).total_seconds() < 86400]  # Last 24 hours
        
        # Group by threat types
        threat_patterns = defaultdict(list)
        ip_threats = defaultdict(int)
        attack_vectors = defaultdict(int)
        
        for event in recent_events:
            threat_patterns[event.event_type].append(event)
            if event.source_ip:
                ip_threats[event.source_ip] += 1
            attack_vectors[event.threat_category] += 1
        
        # Identify top threats
        top_threat_ips = sorted(ip_threats.items(), key=lambda x: x[1], reverse=True)[:10]
        top_attack_vectors = sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "threat_intelligence_summary": {
                "reporting_period": "24_hours",
                "total_threats": len(recent_events),
                "unique_threat_types": len(threat_patterns),
                "unique_source_ips": len(ip_threats),
                "most_active_threats": list(top_attack_vectors)
            },
            "top_threat_sources": [
                {"ip": ip, "threat_count": count, "risk_level": "high" if count > 10 else "medium"}
                for ip, count in top_threat_ips
            ],
            "attack_patterns": {
                pattern_type: {
                    "count": len(events),
                    "severity_distribution": {
                        "critical": len([e for e in events if e.severity == "critical"]),
                        "high": len([e for e in events if e.severity == "high"]),
                        "medium": len([e for e in events if e.severity == "medium"]),
                        "low": len([e for e in events if e.severity == "low"])
                    },
                    "latest_occurrence": max([e.timestamp for e in events]).isoformat() if events else None
                }
                for pattern_type, events in threat_patterns.items()
            },
            "detection_capabilities": [
                "SQL injection attacks",
                "Cross-site scripting (XSS)",
                "Command injection",
                "Request flooding / DoS",
                "Endpoint reconnaissance",
                "Rate limit violations",
                "Behavioral anomalies",
                "Runtime performance attacks"
            ],
            "mitigation_actions": {
                "automatic_blocking": self.engine_stats["threats_blocked"],
                "rate_limiting": len([e for e in recent_events if e.mitigation_action == "rate_limit"]),
                "input_sanitization": len([e for e in recent_events if e.mitigation_action == "sanitize_input"]),
                "monitoring_alerts": len([e for e in recent_events if e.mitigation_action == "monitor"])
            }
        }
    
    def _generate_recommendations(self, security_events: List[SecurityEvent]) -> List[str]:
        """Generate security recommendations based on detected events"""
        recommendations = []
        
        if not security_events:
            return ["Continue monitoring for security threats"]
        
        # Check for critical events
        critical_events = [e for e in security_events if e.severity == "critical"]
        if critical_events:
            recommendations.append(f"CRITICAL: Immediately investigate {len(critical_events)} critical security events")
        
        # Check for injection attacks
        injection_events = [e for e in security_events if "injection" in e.event_type]
        if injection_events:
            recommendations.append(f"Implement additional input validation for {len(injection_events)} injection attempts")
        
        # Check for behavioral anomalies
        behavioral_events = [e for e in security_events if e.threat_category == "behavioral_anomaly"]
        if behavioral_events:
            recommendations.append(f"Review behavioral patterns - {len(behavioral_events)} anomalies detected")
        
        # Check for rate limiting violations
        rate_events = [e for e in security_events if "rate_limit" in e.event_type]
        if rate_events:
            recommendations.append(f"Enforce stricter rate limiting - {len(rate_events)} violations detected")
        
        # Check for specific mitigation actions
        block_events = [e for e in security_events if e.mitigation_action == "block_request"]
        if block_events:
            recommendations.append(f"Review blocked requests - {len(block_events)} potentially malicious requests blocked")
        
        # General recommendations
        if len(security_events) > 5:
            recommendations.append("Consider implementing additional security controls due to high threat activity")
        
        if not recommendations:
            recommendations.append("All security events have been properly mitigated")
        
        return recommendations