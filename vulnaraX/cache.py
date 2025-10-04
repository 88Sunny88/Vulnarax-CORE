import sqlite3
import json
import time
import hashlib
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import threading

# Import metrics for tracking
try:
    from .metrics import get_metrics
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

class VulnerabilityCache:
    """SQLite-based persistent cache for vulnerability data"""
    
    def __init__(self, db_path: str = "vulnerabilities.db", ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self.lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    source TEXT NOT NULL,
                    vulnerabilities TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            ''')
            
            # Create indexes separately
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cache_key ON vulnerability_cache(cache_key)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_package_name ON vulnerability_cache(package_name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_expires_at ON vulnerability_cache(expires_at)')
            
            conn.commit()
    
    def _generate_cache_key(self, package_name: str, version: str, source: str) -> str:
        """Generate a unique cache key for the package/version/source combination"""
        key_data = f"{package_name}:{version}:{source}".encode('utf-8')
        return hashlib.sha256(key_data).hexdigest()
    
    def get(self, package_name: str, version: str, source: str) -> Optional[List[Dict]]:
        """Get cached vulnerability data"""
        cache_key = self._generate_cache_key(package_name, version, source)
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Clean up expired entries first
                cursor.execute('DELETE FROM vulnerability_cache WHERE expires_at < ?', 
                             (datetime.now(),))
                
                # Get cached data
                cursor.execute(
                    'SELECT vulnerabilities FROM vulnerability_cache WHERE cache_key = ? AND expires_at > ?',
                    (cache_key, datetime.now())
                )
                
                row = cursor.fetchone()
                if row:
                    try:
                        # Record cache hit
                        if METRICS_AVAILABLE:
                            metrics = get_metrics()
                            metrics.increment_cache_operations("get", "hit")
                        
                        return json.loads(row['vulnerabilities'])
                    except json.JSONDecodeError:
                        # Remove corrupted entry
                        cursor.execute('DELETE FROM vulnerability_cache WHERE cache_key = ?', 
                                     (cache_key,))
                        
                        # Record cache miss due to corruption
                        if METRICS_AVAILABLE:
                            metrics = get_metrics()
                            metrics.increment_cache_operations("get", "miss")
                            metrics.increment_errors("cache_corruption", "cache")
                        
                        conn.commit()
                        return None
                
                # Record cache miss
                if METRICS_AVAILABLE:
                    metrics = get_metrics()
                    metrics.increment_cache_operations("get", "miss")
                
                return None
    
    def set(self, package_name: str, version: str, source: str, vulnerabilities: List[Dict]):
        """Store vulnerability data in cache with TTL"""
        cache_key = self._generate_cache_key(package_name, version, source)
        expires_at = datetime.now() + timedelta(hours=self.ttl_hours)
        vulnerabilities_json = json.dumps(vulnerabilities)
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Use INSERT OR REPLACE to handle duplicates
                cursor.execute('''
                    INSERT OR REPLACE INTO vulnerability_cache 
                    (cache_key, package_name, package_version, source, vulnerabilities, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (cache_key, package_name, version, source, vulnerabilities_json, expires_at))
                
                # Record cache set operation
                if METRICS_AVAILABLE:
                    metrics = get_metrics()
                    metrics.increment_cache_operations("set", "success")
                
                conn.commit()
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM vulnerability_cache WHERE expires_at < ?', 
                             (datetime.now(),))
                deleted_count = cursor.rowcount
                
                # Record cleanup operation
                if METRICS_AVAILABLE:
                    metrics = get_metrics()
                    metrics.increment_cache_operations("cleanup", "success")
                
                conn.commit()
                return deleted_count
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total entries
            cursor.execute('SELECT COUNT(*) as total FROM vulnerability_cache')
            total = cursor.fetchone()[0]
            
            # Expired entries
            cursor.execute('SELECT COUNT(*) as expired FROM vulnerability_cache WHERE expires_at < ?', 
                          (datetime.now(),))
            expired = cursor.fetchone()[0]
            
            # Entries by source
            cursor.execute('''
                SELECT source, COUNT(*) as count 
                FROM vulnerability_cache 
                WHERE expires_at > ? 
                GROUP BY source
            ''', (datetime.now(),))
            
            by_source = {row[0]: row[1] for row in cursor.fetchall()}
            
            return {
                "total_entries": total,
                "expired_entries": expired,
                "valid_entries": total - expired,
                "by_source": by_source
            }
    
    def clear_all(self):
        """Clear all cache entries"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM vulnerability_cache')
                deleted_count = cursor.rowcount
                
                # Record clear operation
                if METRICS_AVAILABLE:
                    metrics = get_metrics()
                    metrics.increment_cache_operations("clear", "success")
                
                conn.commit()
                return deleted_count

# Global cache instance
_cache_instance = None

def get_cache() -> VulnerabilityCache:
    """Get the global cache instance"""
    global _cache_instance
    if _cache_instance is None:
        cache_path = os.getenv('VULNARAX_CACHE_PATH', 'vulnerabilities.db')
        _cache_instance = VulnerabilityCache(cache_path)
    return _cache_instance