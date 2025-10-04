import asyncio
import aiohttp
import time
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, List, Optional
from functools import lru_cache
from ..cache import get_cache

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

class RateLimitedNVDClient:
    def __init__(self):
        self.api_key = NVD_API_KEY
        # With API key: 50 req/30sec, without: 5 req/30sec
        self.rate_limit_delay = 0.6 if self.api_key else 6.0
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
        """Ensure we don't exceed rate limits with async lock"""
        async with self._lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - time_since_last
                await asyncio.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def _get_cached_result(self, cache_key: str) -> Optional[List]:
        """Get cached vulnerability data"""
        return self.cache.get(cache_key)
    
    def _set_cache(self, cache_key: str, data: List):
        """Cache vulnerability data with size limit"""
        if len(self.cache) >= 1000:
            # Remove oldest 100 entries
            keys_to_remove = list(self.cache.keys())[:100]
            for key in keys_to_remove:
                del self.cache[key]
        
        self.cache[cache_key] = data
    
    async def query_nvd_async(self, package_name: str, version: str) -> List[Dict]:
        """Async NVD query with persistent caching and rate limiting"""
        cache = get_cache()
        
        # Check persistent cache first
        cached_result = cache.get(package_name, version, "nvd")
        if cached_result is not None:
            return cached_result
        
        # Rate limit the request
        await self._rate_limit()
        
        session = await self.get_session()
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        params = {
            'keywordSearch': f"{package_name} {version}",
            'resultsPerPage': 10
        }
        
        try:
            async with session.get(NVD_API_URL, params=params, headers=headers) as response:
                if response.status == 429:
                    print(f"[!] NVD rate limited for {package_name} {version}")
                    await asyncio.sleep(min(30, self.rate_limit_delay * 3))
                    return []
                
                if response.status == 200:
                    data = await response.json()
                    vulns = self._parse_nvd_response(data, package_name, version)
                    
                    # Store in persistent cache
                    cache.set(package_name, version, "nvd", vulns)
                    return vulns
                else:
                    print(f"[!] NVD query failed for {package_name} {version}: HTTP {response.status}")
                    return []
                    
        except asyncio.TimeoutError:
            print(f"[!] NVD query timeout for {package_name} {version}")
            return []
        except Exception as e:
            print(f"[!] NVD query failed for {package_name} {version}: {e}")
            return []
    
    def _parse_nvd_response(self, data: Dict, package_name: str, version: str) -> List[Dict]:
        """Parse NVD API response into vulnerability list"""
        vulns = []
        
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue
                
            # Extract description
            descs = cve_data.get("descriptions", [])
            description = ""
            for desc in descs:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract severity
            severity = "UNKNOWN"
            fixed_version = None
            metrics = cve_data.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV3" in metrics:
                cvss = metrics["cvssMetricV3"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                base_score = cvss.get("baseScore", 0)
                if base_score >= 7.0:
                    severity = "HIGH"
                elif base_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            vulns.append({
                "id": cve_id,
                "package": package_name,
                "version": version,
                "severity": severity.upper(),
                "description": description[:200] + "..." if len(description) > 200 else description,
                "fixed_version": fixed_version,
                "instructions": f"apt-get install --only-upgrade {package_name}"
            })
        
        return vulns

# Global instance
nvd_client = RateLimitedNVDClient()

# Keep the original sync function for backward compatibility
def query_nvd(package_name: str, version: str):
    """
    Synchronous wrapper for the async NVD query with persistent caching.
    For backward compatibility.
    """
    cache = get_cache()
    
    # Check persistent cache first
    cached_result = cache.get(package_name, version, "nvd")
    if cached_result is not None:
        return cached_result
    
    # If not cached, run async query
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(nvd_client.query_nvd_async(package_name, version))
    finally:
        loop.close()