"""
Prometheus metrics for VulnaraX vulnerability scanner
"""

import time
import threading
from typing import Dict, Optional
from datetime import datetime
from collections import defaultdict, Counter


class PrometheusMetrics:
    """Prometheus-style metrics collector for VulnaraX"""
    
    def __init__(self):
        self._lock = threading.Lock()
        
        # Counters
        self.scan_requests_total = Counter()
        self.vulnerabilities_found_total = Counter()
        self.api_calls_total = Counter()
        self.cache_operations_total = Counter()
        self.errors_total = Counter()
        
        # Histograms (simplified as buckets)
        self.scan_duration_buckets = defaultdict(int)
        self.api_response_time_buckets = defaultdict(int)
        
        # Gauges
        self.active_scans = 0
        self.cache_size = 0
        self.cache_hit_ratio = 0.0
        
        # Timing data for histograms
        self._scan_times = []
        self._api_times = []
        
        # Cache metrics
        self._cache_hits = 0
        self._cache_misses = 0
        
    def increment_scan_requests(self, scan_type: str = "unknown", status: str = "success"):
        """Increment scan request counter"""
        with self._lock:
            key = f"{scan_type}_{status}"
            self.scan_requests_total[key] += 1
    
    def increment_vulnerabilities_found(self, ecosystem: str, severity: str, count: int = 1):
        """Increment vulnerabilities found counter"""
        with self._lock:
            key = f"{ecosystem}_{severity}"
            self.vulnerabilities_found_total[key] += count
    
    def increment_api_calls(self, source: str, status_code: int = 200):
        """Increment API calls counter"""
        with self._lock:
            key = f"{source}_{status_code}"
            self.api_calls_total[key] += 1
    
    def increment_cache_operations(self, operation: str, result: str):
        """Increment cache operations counter"""
        with self._lock:
            key = f"{operation}_{result}"
            self.cache_operations_total[key] += 1
            
            # Update cache hit/miss tracking
            if operation == "get":
                if result == "hit":
                    self._cache_hits += 1
                elif result == "miss":
                    self._cache_misses += 1
                
                # Recalculate hit ratio
                total_operations = self._cache_hits + self._cache_misses
                if total_operations > 0:
                    self.cache_hit_ratio = self._cache_hits / total_operations
    
    def increment_errors(self, error_type: str, component: str):
        """Increment error counter"""
        with self._lock:
            key = f"{error_type}_{component}"
            self.errors_total[key] += 1
    
    def record_scan_duration(self, duration_seconds: float, scan_type: str = "unknown"):
        """Record scan duration in histogram"""
        with self._lock:
            self._scan_times.append(duration_seconds)
            
            # Update histogram buckets
            bucket = self._get_histogram_bucket(duration_seconds, "scan")
            self.scan_duration_buckets[f"{scan_type}_{bucket}"] += 1
    
    def record_api_response_time(self, duration_seconds: float, source: str):
        """Record API response time in histogram"""
        with self._lock:
            self._api_times.append(duration_seconds)
            
            # Update histogram buckets
            bucket = self._get_histogram_bucket(duration_seconds, "api")
            self.api_response_time_buckets[f"{source}_{bucket}"] += 1
    
    def set_active_scans(self, count: int):
        """Set number of active scans"""
        with self._lock:
            self.active_scans = count
    
    def set_cache_size(self, size: int):
        """Set cache size"""
        with self._lock:
            self.cache_size = size
    
    def get_metrics_text(self) -> str:
        """Generate Prometheus text format metrics"""
        with self._lock:
            lines = []
            timestamp = int(time.time() * 1000)
            
            # HELP and TYPE declarations
            lines.extend([
                "# HELP vulnarax_scan_requests_total Total number of scan requests",
                "# TYPE vulnarax_scan_requests_total counter"
            ])
            
            # Scan requests
            for key, value in self.scan_requests_total.items():
                scan_type, status = key.rsplit('_', 1)
                lines.append(f'vulnarax_scan_requests_total{{scan_type="{scan_type}",status="{status}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_vulnerabilities_found_total Total vulnerabilities found",
                "# TYPE vulnarax_vulnerabilities_found_total counter"
            ])
            
            # Vulnerabilities found
            for key, value in self.vulnerabilities_found_total.items():
                ecosystem, severity = key.rsplit('_', 1)
                lines.append(f'vulnarax_vulnerabilities_found_total{{ecosystem="{ecosystem}",severity="{severity}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_api_calls_total Total API calls made",
                "# TYPE vulnarax_api_calls_total counter"
            ])
            
            # API calls
            for key, value in self.api_calls_total.items():
                source, status_code = key.rsplit('_', 1)
                lines.append(f'vulnarax_api_calls_total{{source="{source}",status_code="{status_code}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_cache_operations_total Total cache operations",
                "# TYPE vulnarax_cache_operations_total counter"
            ])
            
            # Cache operations
            for key, value in self.cache_operations_total.items():
                operation, result = key.rsplit('_', 1)
                lines.append(f'vulnarax_cache_operations_total{{operation="{operation}",result="{result}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_errors_total Total errors encountered",
                "# TYPE vulnarax_errors_total counter"
            ])
            
            # Errors
            for key, value in self.errors_total.items():
                error_type, component = key.rsplit('_', 1)
                lines.append(f'vulnarax_errors_total{{error_type="{error_type}",component="{component}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_scan_duration_seconds Scan duration histogram",
                "# TYPE vulnarax_scan_duration_seconds histogram"
            ])
            
            # Scan duration histogram
            for key, value in self.scan_duration_buckets.items():
                scan_type, bucket = key.rsplit('_', 1)
                lines.append(f'vulnarax_scan_duration_seconds_bucket{{scan_type="{scan_type}",le="{bucket}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_api_response_time_seconds API response time histogram",
                "# TYPE vulnarax_api_response_time_seconds histogram"
            ])
            
            # API response time histogram
            for key, value in self.api_response_time_buckets.items():
                source, bucket = key.rsplit('_', 1)
                lines.append(f'vulnarax_api_response_time_seconds_bucket{{source="{source}",le="{bucket}"}} {value} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_active_scans Current number of active scans",
                "# TYPE vulnarax_active_scans gauge"
            ])
            lines.append(f'vulnarax_active_scans {self.active_scans} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_cache_size_entries Current cache size in entries",
                "# TYPE vulnarax_cache_size_entries gauge"
            ])
            lines.append(f'vulnarax_cache_size_entries {self.cache_size} {timestamp}')
            
            lines.extend([
                "# HELP vulnarax_cache_hit_ratio Cache hit ratio (0.0 to 1.0)",
                "# TYPE vulnarax_cache_hit_ratio gauge"
            ])
            lines.append(f'vulnarax_cache_hit_ratio {self.cache_hit_ratio:.4f} {timestamp}')
            
            return '\n'.join(lines) + '\n'
    
    def get_summary_stats(self) -> Dict:
        """Get summary statistics for debugging"""
        with self._lock:
            total_scans = sum(self.scan_requests_total.values())
            total_vulns = sum(self.vulnerabilities_found_total.values())
            total_api_calls = sum(self.api_calls_total.values())
            total_errors = sum(self.errors_total.values())
            
            avg_scan_time = 0.0
            if self._scan_times:
                avg_scan_time = sum(self._scan_times) / len(self._scan_times)
            
            avg_api_time = 0.0
            if self._api_times:
                avg_api_time = sum(self._api_times) / len(self._api_times)
            
            return {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulns,
                "total_api_calls": total_api_calls,
                "total_errors": total_errors,
                "active_scans": self.active_scans,
                "cache_size": self.cache_size,
                "cache_hit_ratio": self.cache_hit_ratio,
                "avg_scan_time_seconds": avg_scan_time,
                "avg_api_time_seconds": avg_api_time,
                "timestamp": datetime.now().isoformat()
            }
    
    def _get_histogram_bucket(self, value: float, metric_type: str) -> str:
        """Get histogram bucket for a value"""
        if metric_type == "scan":
            # Scan duration buckets: 1s, 5s, 10s, 30s, 60s, 300s, +Inf
            buckets = [1.0, 5.0, 10.0, 30.0, 60.0, 300.0, float('inf')]
        elif metric_type == "api":
            # API response time buckets: 0.1s, 0.5s, 1s, 2s, 5s, 10s, +Inf
            buckets = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, float('inf')]
        else:
            buckets = [1.0, 5.0, 10.0, float('inf')]
        
        for bucket in buckets:
            if value <= bucket:
                return str(bucket) if bucket != float('inf') else "+Inf"
        
        return "+Inf"
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing)"""
        with self._lock:
            self.scan_requests_total.clear()
            self.vulnerabilities_found_total.clear()
            self.api_calls_total.clear()
            self.cache_operations_total.clear()
            self.errors_total.clear()
            self.scan_duration_buckets.clear()
            self.api_response_time_buckets.clear()
            self.active_scans = 0
            self.cache_size = 0
            self.cache_hit_ratio = 0.0
            self._scan_times.clear()
            self._api_times.clear()
            self._cache_hits = 0
            self._cache_misses = 0


# Global metrics instance
metrics = PrometheusMetrics()

def get_metrics() -> PrometheusMetrics:
    """Get the global metrics instance"""
    return metrics