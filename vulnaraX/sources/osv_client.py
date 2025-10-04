import asyncio
import aiohttp
import time
import requests
from typing import Dict, List, Optional
from ..cache import get_cache

OSV_API_URL = "https://api.osv.dev/v1/query"

class RateLimitedOSVClient:
    def __init__(self):
        self.rate_limit_delay = 0.1  # OSV is more lenient
        self.last_request_time = 0
        self.session = None
        self.cache = {}
        self._lock = asyncio.Lock()
        
    async def get_session(self):
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self.session
    
    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
    
    async def _rate_limit(self):
        """Basic rate limiting for OSV"""
        async with self._lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - time_since_last)
            
            self.last_request_time = time.time()
    
    async def query_osv_async(self, package_name: str, version: str) -> List[Dict]:
        """Async OSV query with persistent caching"""
        cache = get_cache()
        
        # Check persistent cache first
        cached_result = cache.get(package_name, version, "osv")
        if cached_result is not None:
            return cached_result
        
        await self._rate_limit()
        
        session = await self.get_session()
        
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "Debian"  # Adjust based on detected distro
            },
            "version": version
        }
        
        try:
            async with session.post(OSV_API_URL, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    vulns = self._parse_osv_response_new(data, package_name, version)
                    
                    # Store in persistent cache
                    cache.set(package_name, version, "osv", vulns)
                    return vulns
                else:
                    return []
                    
        except Exception as e:
            print(f"[!] OSV query failed for {package_name} {version}: {e}")
            return []
    
    def _parse_osv_response_new(self, data: Dict, package_name: str, version: str) -> List[Dict]:
        """Parse OSV response for new format"""
        vulns = []
        
        for v in data.get("vulns", []):
            vuln_id = v.get("id", "UNKNOWN")
            summary = v.get("summary", "")
            
            # Map OSV severity to standard levels
            severity_info = v.get("severity", [])
            severity = "UNKNOWN"
            if severity_info:
                for sev in severity_info:
                    if sev.get("type") == "CVSS_V3":
                        score = sev.get("score", "")
                        if "CVSS:3" in score:
                            # Extract base score from CVSS string
                            try:
                                base_score = float(score.split("/")[1].split(":")[1])
                                if base_score >= 9.0:
                                    severity = "CRITICAL"
                                elif base_score >= 7.0:
                                    severity = "HIGH"
                                elif base_score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                            except:
                                severity = "UNKNOWN"
                        break
            
            # Extract fixed version if available
            fixed_version = None
            affected = v.get("affected", [])
            for affect in affected:
                ranges = affect.get("ranges", [])
                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break
                    if fixed_version:
                        break
                if fixed_version:
                    break
            
            vulns.append({
                "id": vuln_id,
                "package": package_name,
                "version": version,
                "severity": severity,
                "description": summary[:200] + "..." if len(summary) > 200 else summary,
                "fixed_version": fixed_version,
                "instructions": f"apt-get install --only-upgrade {package_name}"
            })
        
        return vulns

# Global instance for async operations
osv_client = RateLimitedOSVClient()

# Existing sync function (keep for backward compatibility)
def query_osv(package_name: str, version: str):
    """
    Query OSV API for a package+version with persistent caching.
    """
    cache = get_cache()
    
    # Check persistent cache first
    cached_result = cache.get(package_name, version, "osv")
    if cached_result is not None:
        return cached_result
    
    payload = {
        "package": {"name": package_name},
        "version": version
    }
    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []

    vulns = []
    for v in data.get("vulns", []):
        fixed_version = None
        affected = v.get("affected", [])
        if affected:
            events = affected[0].get("ranges", [])
            for ev in events:
                for event in ev.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]

        vulns.append({
            "id": v.get("id"),
            "package": package_name,
            "version": version,
            "severity": v.get("severity", "UNKNOWN"),
            "description": v.get("summary", ""),
            "fixed_version": fixed_version,
            "instructions": f"apt-get install --only-upgrade {package_name}"
        })
    
    # Store in persistent cache
    cache.set(package_name, version, "osv", vulns)
    return vulns

# New async function for production use
async def query_osv_async(package_name: str, version: str):
    """Direct async OSV query"""
    return await osv_client.query_osv_async(package_name, version)