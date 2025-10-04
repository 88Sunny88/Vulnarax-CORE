import requests
import json
import sqlite3
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class VulnerabilitySeverity(Enum):
    """Standardized vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

@dataclass
class CVSSScore:
    """CVSS scoring information"""
    version: str  # "2.0", "3.0", "3.1"
    base_score: float
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    vector_string: Optional[str] = None
    severity: Optional[str] = None
    
    def get_severity(self) -> VulnerabilitySeverity:
        """Get severity based on CVSS score"""
        if self.base_score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif self.base_score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif self.base_score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        elif self.base_score > 0.0:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.INFORMATIONAL

@dataclass
class EPSSScore:
    """EPSS (Exploit Prediction Scoring System) information"""
    score: float  # 0.0 to 1.0 (probability of exploitation)
    percentile: float  # 0.0 to 100.0 (percentile among all CVEs)
    date: str  # Date of EPSS calculation

@dataclass
class KEVInfo:
    """Known Exploited Vulnerability information"""
    is_kev: bool
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    action_required: Optional[str] = None
    notes: Optional[str] = None

@dataclass
class VulnerabilityRisk:
    """Comprehensive vulnerability risk assessment"""
    cve_id: str
    cvss_score: Optional[CVSSScore] = None
    epss_score: Optional[EPSSScore] = None
    kev_info: Optional[KEVInfo] = None
    risk_score: float = 0.0  # Calculated overall risk score
    priority: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        base_risk = 0.0
        
        # CVSS contributes 40% of risk score
        if self.cvss_score:
            base_risk += (self.cvss_score.base_score / 10.0) * 40
        
        # EPSS contributes 30% of risk score
        if self.epss_score:
            base_risk += self.epss_score.score * 30
        
        # KEV status contributes 30% of risk score
        if self.kev_info and self.kev_info.is_kev:
            base_risk += 30
        
        self.risk_score = min(base_risk, 100.0)
        
        # Determine priority
        if self.risk_score >= 80 or (self.kev_info and self.kev_info.is_kev):
            self.priority = "CRITICAL"
        elif self.risk_score >= 60:
            self.priority = "HIGH"
        elif self.risk_score >= 30:
            self.priority = "MEDIUM"
        else:
            self.priority = "LOW"
        
        return self.risk_score

class CVSSClient:
    """Client for fetching CVSS scores from various sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnaraX-Core/1.0.0'
        })
    
    async def get_cvss_score(self, cve_id: str) -> Optional[CVSSScore]:
        """Get CVSS score for a CVE"""
        try:
            # Try NVD first
            nvd_score = await self._get_cvss_from_nvd(cve_id)
            if nvd_score:
                return nvd_score
            
            # Fallback to other sources if needed
            return None
            
        except Exception as e:
            logger.error(f"Error fetching CVSS for {cve_id}: {str(e)}")
            return None
    
    async def _get_cvss_from_nvd(self, cve_id: str) -> Optional[CVSSScore]:
        """Get CVSS score from NVD API"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'cveId': cve_id
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        
                        if vulnerabilities:
                            vuln = vulnerabilities[0]
                            cve_data = vuln.get('cve', {})
                            metrics = cve_data.get('metrics', {})
                            
                            # Try CVSS v3.1 first, then v3.0, then v2.0
                            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                                if version in metrics:
                                    metric_data = metrics[version][0]
                                    cvss_data = metric_data.get('cvssData', {})
                                    
                                    return CVSSScore(
                                        version=cvss_data.get('version', '3.1'),
                                        base_score=cvss_data.get('baseScore', 0.0),
                                        vector_string=cvss_data.get('vectorString'),
                                        severity=cvss_data.get('baseSeverity')
                                    )
            
            return None
            
        except Exception as e:
            logger.error(f"NVD CVSS fetch error for {cve_id}: {str(e)}")
            return None

class EPSSClient:
    """Client for fetching EPSS scores"""
    
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
        self.session = requests.Session()
    
    async def get_epss_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a CVE"""
        try:
            url = f"{self.base_url}"
            params = {'cve': cve_id}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'OK' and data.get('data'):
                            epss_data = data['data'][0]
                            
                            return EPSSScore(
                                score=float(epss_data.get('epss', 0.0)),
                                percentile=float(epss_data.get('percentile', 0.0)),
                                date=epss_data.get('date', '')
                            )
            
            return None
            
        except Exception as e:
            logger.error(f"EPSS fetch error for {cve_id}: {str(e)}")
            return None

class KEVClient:
    """Client for fetching Known Exploited Vulnerabilities data from CISA"""
    
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.cache_file = "kev_cache.json"
        self.cache_ttl = 24 * 3600  # 24 hours
        self._kev_data = {}
        self._last_update = 0
        self._lock = threading.Lock()
    
    async def get_kev_info(self, cve_id: str) -> KEVInfo:
        """Get KEV information for a CVE"""
        await self._update_kev_cache()
        
        with self._lock:
            kev_entry = self._kev_data.get(cve_id)
            
            if kev_entry:
                return KEVInfo(
                    is_kev=True,
                    date_added=kev_entry.get('dateAdded'),
                    due_date=kev_entry.get('dueDate'),
                    action_required=kev_entry.get('requiredAction'),
                    notes=kev_entry.get('notes')
                )
            else:
                return KEVInfo(is_kev=False)
    
    async def _update_kev_cache(self):
        """Update KEV cache if needed"""
        current_time = time.time()
        
        if current_time - self._last_update < self.cache_ttl:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.kev_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        with self._lock:
                            self._kev_data = {}
                            
                            for vuln in data.get('vulnerabilities', []):
                                cve_id = vuln.get('cveID')
                                if cve_id:
                                    self._kev_data[cve_id] = vuln
                            
                            self._last_update = current_time
                            
                            # Save to cache file
                            cache_data = {
                                'data': self._kev_data,
                                'last_update': self._last_update
                            }
                            
                            with open(self.cache_file, 'w') as f:
                                json.dump(cache_data, f)
                            
                            logger.info(f"Updated KEV cache with {len(self._kev_data)} vulnerabilities")
                            
        except Exception as e:
            logger.error(f"Error updating KEV cache: {str(e)}")
            # Try to load from cache file
            await self._load_from_cache()
    
    async def _load_from_cache(self):
        """Load KEV data from cache file"""
        try:
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
                
                with self._lock:
                    self._kev_data = cache_data.get('data', {})
                    self._last_update = cache_data.get('last_update', 0)
                
        except Exception as e:
            logger.error(f"Error loading KEV cache: {str(e)}")

class VulnerabilityRiskAssessment:
    """Main class for vulnerability risk assessment and prioritization"""
    
    def __init__(self):
        self.cvss_client = CVSSClient()
        self.epss_client = EPSSClient()
        self.kev_client = KEVClient()
        self.cache_db = "vulnerability_risk_cache.db"
        self._init_cache_db()
    
    def _init_cache_db(self):
        """Initialize risk assessment cache database"""
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_risk_cache (
                    cve_id TEXT PRIMARY KEY,
                    cvss_data TEXT,
                    epss_data TEXT,
                    kev_data TEXT,
                    risk_score REAL,
                    priority TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_priority ON vulnerability_risk_cache(priority)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_risk_score ON vulnerability_risk_cache(risk_score)')
            conn.commit()
    
    async def assess_vulnerability_risk(self, cve_id: str, force_refresh: bool = False) -> VulnerabilityRisk:
        """Assess comprehensive risk for a vulnerability"""
        
        # Check cache first
        if not force_refresh:
            cached_risk = self._get_cached_risk(cve_id)
            if cached_risk:
                return cached_risk
        
        # Fetch all risk data
        cvss_task = self.cvss_client.get_cvss_score(cve_id)
        epss_task = self.epss_client.get_epss_score(cve_id)
        kev_task = self.kev_client.get_kev_info(cve_id)
        
        cvss_score, epss_score, kev_info = await asyncio.gather(
            cvss_task, epss_task, kev_task, return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(cvss_score, Exception):
            cvss_score = None
        if isinstance(epss_score, Exception):
            epss_score = None
        if isinstance(kev_info, Exception):
            kev_info = KEVInfo(is_kev=False)
        
        # Create risk assessment
        risk = VulnerabilityRisk(
            cve_id=cve_id,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_info=kev_info
        )
        
        # Calculate overall risk score
        risk.calculate_risk_score()
        
        # Cache the result
        self._cache_risk(risk)
        
        return risk
    
    async def assess_vulnerabilities_batch(self, cve_ids: List[str]) -> List[VulnerabilityRisk]:
        """Assess risk for multiple vulnerabilities"""
        tasks = [self.assess_vulnerability_risk(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, VulnerabilityRisk):
                valid_results.append(result)
            else:
                logger.error(f"Risk assessment failed: {str(result)}")
        
        return valid_results
    
    def _get_cached_risk(self, cve_id: str) -> Optional[VulnerabilityRisk]:
        """Get cached risk assessment"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Check if cache is fresh (24 hours)
                cursor.execute('''
                    SELECT * FROM vulnerability_risk_cache 
                    WHERE cve_id = ? AND updated_at > datetime('now', '-24 hours')
                ''', (cve_id,))
                
                row = cursor.fetchone()
                if row:
                    # Deserialize data
                    cvss_data = json.loads(row['cvss_data']) if row['cvss_data'] else None
                    epss_data = json.loads(row['epss_data']) if row['epss_data'] else None
                    kev_data = json.loads(row['kev_data']) if row['kev_data'] else None
                    
                    cvss_score = CVSSScore(**cvss_data) if cvss_data else None
                    epss_score = EPSSScore(**epss_data) if epss_data else None
                    kev_info = KEVInfo(**kev_data) if kev_data else None
                    
                    return VulnerabilityRisk(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        epss_score=epss_score,
                        kev_info=kev_info,
                        risk_score=row['risk_score'],
                        priority=row['priority']
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached risk for {cve_id}: {str(e)}")
            return None
    
    def _cache_risk(self, risk: VulnerabilityRisk):
        """Cache risk assessment"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cvss_data = json.dumps(asdict(risk.cvss_score)) if risk.cvss_score else None
                epss_data = json.dumps(asdict(risk.epss_score)) if risk.epss_score else None
                kev_data = json.dumps(asdict(risk.kev_info)) if risk.kev_info else None
                
                conn.execute('''
                    INSERT OR REPLACE INTO vulnerability_risk_cache
                    (cve_id, cvss_data, epss_data, kev_data, risk_score, priority)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    risk.cve_id,
                    cvss_data,
                    epss_data,
                    kev_data,
                    risk.risk_score,
                    risk.priority
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error caching risk for {risk.cve_id}: {str(e)}")
    
    def get_risk_statistics(self) -> Dict:
        """Get risk assessment statistics"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.cursor()
                
                # Count by priority
                cursor.execute('''
                    SELECT priority, COUNT(*) as count
                    FROM vulnerability_risk_cache
                    GROUP BY priority
                ''')
                
                priority_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Get top risks
                cursor.execute('''
                    SELECT cve_id, risk_score, priority
                    FROM vulnerability_risk_cache
                    ORDER BY risk_score DESC
                    LIMIT 10
                ''')
                
                top_risks = [
                    {'cve_id': row[0], 'risk_score': row[1], 'priority': row[2]}
                    for row in cursor.fetchall()
                ]
                
                return {
                    'priority_distribution': priority_counts,
                    'top_risks': top_risks,
                    'total_assessed': sum(priority_counts.values())
                }
                
        except Exception as e:
            logger.error(f"Error getting risk statistics: {str(e)}")
            return {}

# Global instance
_risk_assessment_instance = None

def get_risk_assessment() -> VulnerabilityRiskAssessment:
    """Get global risk assessment instance"""
    global _risk_assessment_instance
    if _risk_assessment_instance is None:
        _risk_assessment_instance = VulnerabilityRiskAssessment()
    return _risk_assessment_instance