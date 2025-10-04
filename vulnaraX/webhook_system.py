import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
import time
import aiohttp
import hashlib
from urllib.parse import urlparse
import hmac

# Import metrics for tracking
try:
    from .metrics import get_metrics
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)

class WebhookEvent(Enum):
    """Types of webhook events"""
    NEW_VULNERABILITY = "new_vulnerability"
    VULNERABILITY_UPDATE = "vulnerability_update"
    HIGH_RISK_DETECTED = "high_risk_detected"
    KEV_ADDED = "kev_added"
    SCAN_COMPLETED = "scan_completed"
    CRITICAL_ALERT = "critical_alert"

class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration"""
    id: str
    url: str
    secret: Optional[str] = None
    events: List[WebhookEvent] = None
    active: bool = True
    retry_count: int = 3
    timeout: int = 30
    headers: Dict[str, str] = None
    created_at: str = None
    last_triggered: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0

@dataclass
class VulnerabilityAlert:
    """Vulnerability alert data"""
    id: str
    event_type: WebhookEvent
    priority: NotificationPriority
    vulnerability: Dict[str, Any]
    package_info: Optional[Dict[str, Any]] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    affected_projects: List[str] = None
    timestamp: str = None
    metadata: Dict[str, Any] = None

@dataclass
class FeedConfiguration:
    """Vulnerability feed configuration"""
    id: str
    name: str
    url: str
    poll_interval: int = 3600  # seconds
    last_check: Optional[str] = None
    active: bool = True
    filter_criteria: Dict[str, Any] = None
    transform_rules: List[Dict[str, Any]] = None

class WebhookManager:
    """Manages webhook endpoints and notifications"""
    
    def __init__(self, db_path: str = "webhooks.db"):
        self.db_path = db_path
        self.endpoints: Dict[str, WebhookEndpoint] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self._init_db()
        self._load_endpoints()
    
    def _init_db(self):
        """Initialize webhook database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS webhook_endpoints (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    secret TEXT,
                    events TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    retry_count INTEGER DEFAULT 3,
                    timeout INTEGER DEFAULT 30,
                    headers TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_triggered TEXT,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id TEXT PRIMARY KEY,
                    webhook_id TEXT,
                    event_type TEXT,
                    payload TEXT,
                    status_code INTEGER,
                    response_body TEXT,
                    delivered_at TEXT,
                    error_message TEXT,
                    FOREIGN KEY (webhook_id) REFERENCES webhook_endpoints (id)
                )
            ''')
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivered_at ON webhook_deliveries(delivered_at)')
            
            conn.commit()
    
    def _load_endpoints(self):
        """Load webhook endpoints from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM webhook_endpoints WHERE active = 1')
            
            for row in cursor.fetchall():
                events = json.loads(row['events']) if row['events'] else []
                headers = json.loads(row['headers']) if row['headers'] else {}
                
                endpoint = WebhookEndpoint(
                    id=row['id'],
                    url=row['url'],
                    secret=row['secret'],
                    events=[WebhookEvent(e) for e in events],
                    active=bool(row['active']),
                    retry_count=row['retry_count'],
                    timeout=row['timeout'],
                    headers=headers,
                    created_at=row['created_at'],
                    last_triggered=row['last_triggered'],
                    success_count=row['success_count'],
                    failure_count=row['failure_count']
                )
                
                self.endpoints[endpoint.id] = endpoint
    
    def add_webhook(self, url: str, events: List[WebhookEvent], 
                   secret: Optional[str] = None,
                   headers: Optional[Dict[str, str]] = None) -> str:
        """Add a new webhook endpoint"""
        webhook_id = str(uuid.uuid4())
        
        endpoint = WebhookEndpoint(
            id=webhook_id,
            url=url,
            secret=secret,
            events=events,
            headers=headers or {},
            created_at=datetime.now().isoformat()
        )
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO webhook_endpoints
                (id, url, secret, events, headers, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                webhook_id,
                url,
                secret,
                json.dumps([e.value for e in events]),
                json.dumps(headers or {}),
                endpoint.created_at
            ))
            conn.commit()
        
        self.endpoints[webhook_id] = endpoint
        logger.info(f"Added webhook endpoint: {webhook_id} -> {url}")
        
        return webhook_id
    
    def remove_webhook(self, webhook_id: str) -> bool:
        """Remove a webhook endpoint"""
        if webhook_id in self.endpoints:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('UPDATE webhook_endpoints SET active = 0 WHERE id = ?', (webhook_id,))
                conn.commit()
            
            del self.endpoints[webhook_id]
            logger.info(f"Removed webhook endpoint: {webhook_id}")
            return True
        
        return False
    
    def _generate_signature(self, payload: str, secret: str) -> str:
        """Generate HMAC signature for webhook payload"""
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
    
    async def _deliver_webhook(self, endpoint: WebhookEndpoint, alert: VulnerabilityAlert) -> bool:
        """Deliver webhook notification"""
        payload = {
            "event": alert.event_type.value,
            "priority": alert.priority.value,
            "timestamp": alert.timestamp,
            "alert_id": alert.id,
            "vulnerability": alert.vulnerability,
            "package_info": alert.package_info,
            "risk_assessment": alert.risk_assessment,
            "affected_projects": alert.affected_projects,
            "metadata": alert.metadata
        }
        
        payload_json = json.dumps(payload, sort_keys=True)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnaraX-Webhook/1.0",
            "X-VulnaraX-Event": alert.event_type.value,
            "X-VulnaraX-Priority": alert.priority.value,
            **endpoint.headers
        }
        
        # Add signature if secret is provided
        if endpoint.secret:
            signature = self._generate_signature(payload_json, endpoint.secret)
            headers["X-VulnaraX-Signature"] = f"sha256={signature}"
        
        delivery_id = str(uuid.uuid4())
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.post(
                endpoint.url,
                data=payload_json,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=endpoint.timeout)
            ) as response:
                
                response_body = await response.text()
                success = 200 <= response.status < 300
                
                # Log delivery
                self._log_delivery(
                    delivery_id=delivery_id,
                    webhook_id=endpoint.id,
                    event_type=alert.event_type.value,
                    payload=payload_json,
                    status_code=response.status,
                    response_body=response_body,
                    success=success
                )
                
                if success:
                    endpoint.success_count += 1
                    endpoint.last_triggered = datetime.now().isoformat()
                    self._update_endpoint_stats(endpoint)
                    
                    if METRICS_AVAILABLE:
                        metrics = get_metrics()
                        metrics.increment_webhook_deliveries("success")
                    
                    logger.info(f"Webhook delivered successfully: {endpoint.url}")
                    return True
                else:
                    endpoint.failure_count += 1
                    self._update_endpoint_stats(endpoint)
                    
                    if METRICS_AVAILABLE:
                        metrics = get_metrics()
                        metrics.increment_webhook_deliveries("failure")
                    
                    logger.warning(f"Webhook delivery failed: {endpoint.url} - {response.status}")
                    return False
        
        except Exception as e:
            endpoint.failure_count += 1
            self._update_endpoint_stats(endpoint)
            
            self._log_delivery(
                delivery_id=delivery_id,
                webhook_id=endpoint.id,
                event_type=alert.event_type.value,
                payload=payload_json,
                status_code=0,
                response_body="",
                success=False,
                error_message=str(e)
            )
            
            if METRICS_AVAILABLE:
                metrics = get_metrics()
                metrics.increment_webhook_deliveries("error")
                metrics.increment_errors("webhook_delivery", "webhook")
            
            logger.error(f"Webhook delivery error: {endpoint.url} - {str(e)}")
            return False
    
    def _log_delivery(self, delivery_id: str, webhook_id: str, event_type: str,
                     payload: str, status_code: int, response_body: str,
                     success: bool, error_message: str = None):
        """Log webhook delivery attempt"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO webhook_deliveries
                    (id, webhook_id, event_type, payload, status_code, response_body, 
                     delivered_at, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    delivery_id,
                    webhook_id,
                    event_type,
                    payload,
                    status_code,
                    response_body,
                    datetime.now().isoformat(),
                    error_message
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log webhook delivery: {str(e)}")
    
    def _update_endpoint_stats(self, endpoint: WebhookEndpoint):
        """Update endpoint statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE webhook_endpoints
                    SET success_count = ?, failure_count = ?, last_triggered = ?
                    WHERE id = ?
                ''', (
                    endpoint.success_count,
                    endpoint.failure_count,
                    endpoint.last_triggered,
                    endpoint.id
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update endpoint stats: {str(e)}")
    
    async def send_alert(self, alert: VulnerabilityAlert):
        """Send alert to all matching webhooks"""
        matching_endpoints = [
            endpoint for endpoint in self.endpoints.values()
            if endpoint.active and alert.event_type in endpoint.events
        ]
        
        if not matching_endpoints:
            logger.debug(f"No matching webhooks for event: {alert.event_type.value}")
            return
        
        logger.info(f"Sending alert to {len(matching_endpoints)} webhooks")
        
        # Send to all matching endpoints
        tasks = []
        for endpoint in matching_endpoints:
            task = self._deliver_webhook_with_retry(endpoint, alert)
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _deliver_webhook_with_retry(self, endpoint: WebhookEndpoint, alert: VulnerabilityAlert):
        """Deliver webhook with retry logic"""
        for attempt in range(endpoint.retry_count):
            try:
                success = await self._deliver_webhook(endpoint, alert)
                if success:
                    return
                
                # Wait before retry
                if attempt < endpoint.retry_count - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except Exception as e:
                logger.error(f"Webhook delivery attempt {attempt + 1} failed: {str(e)}")
                if attempt < endpoint.retry_count - 1:
                    await asyncio.sleep(2 ** attempt)
    
    def get_webhook_stats(self) -> Dict[str, Any]:
        """Get webhook statistics"""
        total_endpoints = len(self.endpoints)
        active_endpoints = len([e for e in self.endpoints.values() if e.active])
        
        total_success = sum(e.success_count for e in self.endpoints.values())
        total_failures = sum(e.failure_count for e in self.endpoints.values())
        
        return {
            "total_endpoints": total_endpoints,
            "active_endpoints": active_endpoints,
            "total_deliveries": total_success + total_failures,
            "success_rate": total_success / (total_success + total_failures) if (total_success + total_failures) > 0 else 0,
            "endpoints": [
                {
                    "id": e.id,
                    "url": e.url,
                    "events": [event.value for event in e.events],
                    "success_count": e.success_count,
                    "failure_count": e.failure_count,
                    "last_triggered": e.last_triggered
                }
                for e in self.endpoints.values()
            ]
        }
    
    async def close(self):
        """Close webhook manager"""
        if self.session:
            await self.session.close()

class VulnerabilityFeedMonitor:
    """Monitors external vulnerability feeds for new threats"""
    
    def __init__(self, webhook_manager: WebhookManager):
        self.webhook_manager = webhook_manager
        self.feeds: Dict[str, FeedConfiguration] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self.db_path = "vulnerability_feeds.db"
        self._init_db()
        self._load_feeds()
    
    def _init_db(self):
        """Initialize feed monitoring database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_feeds (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    poll_interval INTEGER DEFAULT 3600,
                    last_check TEXT,
                    active INTEGER DEFAULT 1,
                    filter_criteria TEXT,
                    transform_rules TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS feed_vulnerabilities (
                    id TEXT PRIMARY KEY,
                    feed_id TEXT,
                    vulnerability_id TEXT,
                    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                    data TEXT,
                    FOREIGN KEY (feed_id) REFERENCES vulnerability_feeds (id)
                )
            ''')
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_feed_vulnerabilities_feed_id ON feed_vulnerabilities(feed_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_feed_vulnerabilities_vuln_id ON feed_vulnerabilities(vulnerability_id)')
            
            conn.commit()
    
    def _load_feeds(self):
        """Load feed configurations from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM vulnerability_feeds WHERE active = 1')
            
            for row in cursor.fetchall():
                filter_criteria = json.loads(row['filter_criteria']) if row['filter_criteria'] else {}
                transform_rules = json.loads(row['transform_rules']) if row['transform_rules'] else []
                
                feed = FeedConfiguration(
                    id=row['id'],
                    name=row['name'],
                    url=row['url'],
                    poll_interval=row['poll_interval'],
                    last_check=row['last_check'],
                    active=bool(row['active']),
                    filter_criteria=filter_criteria,
                    transform_rules=transform_rules
                )
                
                self.feeds[feed.id] = feed
    
    def add_feed(self, name: str, url: str, poll_interval: int = 3600,
                filter_criteria: Optional[Dict[str, Any]] = None) -> str:
        """Add a new vulnerability feed"""
        feed_id = str(uuid.uuid4())
        
        feed = FeedConfiguration(
            id=feed_id,
            name=name,
            url=url,
            poll_interval=poll_interval,
            filter_criteria=filter_criteria or {}
        )
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO vulnerability_feeds
                (id, name, url, poll_interval, filter_criteria)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                feed_id,
                name,
                url,
                poll_interval,
                json.dumps(filter_criteria or {})
            ))
            conn.commit()
        
        self.feeds[feed_id] = feed
        
        # Start monitoring if we're running
        if self._running:
            self._start_feed_monitoring(feed)
        
        logger.info(f"Added vulnerability feed: {name} -> {url}")
        return feed_id
    
    async def start_monitoring(self):
        """Start monitoring all feeds"""
        self._running = True
        
        for feed in self.feeds.values():
            if feed.active:
                self._start_feed_monitoring(feed)
        
        logger.info(f"Started monitoring {len(self.feeds)} vulnerability feeds")
    
    def _start_feed_monitoring(self, feed: FeedConfiguration):
        """Start monitoring a specific feed"""
        async def monitor_feed():
            while self._running and feed.active:
                try:
                    await self._check_feed(feed)
                    await asyncio.sleep(feed.poll_interval)
                except Exception as e:
                    logger.error(f"Error monitoring feed {feed.name}: {str(e)}")
                    await asyncio.sleep(300)  # Wait 5 minutes on error
        
        task = asyncio.create_task(monitor_feed())
        self.monitoring_tasks[feed.id] = task
    
    async def _check_feed(self, feed: FeedConfiguration):
        """Check a vulnerability feed for new entries"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed.url, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self._process_feed_data(feed, data)
                        
                        # Update last check time
                        feed.last_check = datetime.now().isoformat()
                        self._update_feed_check_time(feed)
                    else:
                        logger.warning(f"Feed {feed.name} returned status {response.status}")
        
        except Exception as e:
            logger.error(f"Error checking feed {feed.name}: {str(e)}")
    
    async def _process_feed_data(self, feed: FeedConfiguration, data: Dict[str, Any]):
        """Process feed data and generate alerts for new vulnerabilities"""
        # This is a simplified implementation - real feeds would have different formats
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln_data in vulnerabilities:
            vuln_id = vuln_data.get('id')
            if not vuln_id:
                continue
            
            # Check if we've seen this vulnerability before
            if not self._is_new_vulnerability(feed.id, vuln_id):
                continue
            
            # Apply filters
            if not self._passes_filters(vuln_data, feed.filter_criteria):
                continue
            
            # Record new vulnerability
            self._record_vulnerability(feed.id, vuln_id, vuln_data)
            
            # Generate alert
            await self._generate_vulnerability_alert(vuln_data, feed)
    
    def _is_new_vulnerability(self, feed_id: str, vuln_id: str) -> bool:
        """Check if vulnerability is new to this feed"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT 1 FROM feed_vulnerabilities WHERE feed_id = ? AND vulnerability_id = ?',
                (feed_id, vuln_id)
            )
            return cursor.fetchone() is None
    
    def _passes_filters(self, vuln_data: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if vulnerability passes filter criteria"""
        if not filters:
            return True
        
        # Example filters
        if 'min_cvss' in filters:
            cvss_score = vuln_data.get('cvss', {}).get('base_score', 0)
            if cvss_score < filters['min_cvss']:
                return False
        
        if 'severity' in filters:
            required_severities = filters['severity']
            vuln_severity = vuln_data.get('severity', '').lower()
            if vuln_severity not in [s.lower() for s in required_severities]:
                return False
        
        return True
    
    def _record_vulnerability(self, feed_id: str, vuln_id: str, vuln_data: Dict[str, Any]):
        """Record new vulnerability in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO feed_vulnerabilities
                    (id, feed_id, vulnerability_id, data)
                    VALUES (?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    feed_id,
                    vuln_id,
                    json.dumps(vuln_data)
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to record vulnerability {vuln_id}: {str(e)}")
    
    async def _generate_vulnerability_alert(self, vuln_data: Dict[str, Any], feed: FeedConfiguration):
        """Generate alert for new vulnerability"""
        # Determine priority based on severity/CVSS
        priority = self._determine_priority(vuln_data)
        
        # Create alert
        alert = VulnerabilityAlert(
            id=str(uuid.uuid4()),
            event_type=WebhookEvent.NEW_VULNERABILITY,
            priority=priority,
            vulnerability=vuln_data,
            timestamp=datetime.now().isoformat(),
            metadata={
                "feed_name": feed.name,
                "feed_id": feed.id,
                "source": "vulnerability_feed"
            }
        )
        
        # Send webhook notification
        await self.webhook_manager.send_alert(alert)
        
        logger.info(f"Generated alert for new vulnerability: {vuln_data.get('id')} from {feed.name}")
    
    def _determine_priority(self, vuln_data: Dict[str, Any]) -> NotificationPriority:
        """Determine notification priority based on vulnerability data"""
        severity = vuln_data.get('severity', '').lower()
        cvss_score = vuln_data.get('cvss', {}).get('base_score', 0)
        
        if severity == 'critical' or cvss_score >= 9.0:
            return NotificationPriority.CRITICAL
        elif severity == 'high' or cvss_score >= 7.0:
            return NotificationPriority.HIGH
        elif severity == 'medium' or cvss_score >= 4.0:
            return NotificationPriority.MEDIUM
        else:
            return NotificationPriority.LOW
    
    def _update_feed_check_time(self, feed: FeedConfiguration):
        """Update feed last check time"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE vulnerability_feeds SET last_check = ? WHERE id = ?',
                    (feed.last_check, feed.id)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update feed check time: {str(e)}")
    
    async def stop_monitoring(self):
        """Stop monitoring all feeds"""
        self._running = False
        
        for task in self.monitoring_tasks.values():
            task.cancel()
        
        await asyncio.gather(*self.monitoring_tasks.values(), return_exceptions=True)
        self.monitoring_tasks.clear()
        
        logger.info("Stopped vulnerability feed monitoring")

class RealTimeNotificationSystem:
    """Main real-time notification system"""
    
    def __init__(self):
        self.webhook_manager = WebhookManager()
        self.feed_monitor = VulnerabilityFeedMonitor(self.webhook_manager)
        self._running = False
    
    async def start(self):
        """Start the real-time notification system"""
        self._running = True
        await self.feed_monitor.start_monitoring()
        logger.info("Real-time notification system started")
    
    async def stop(self):
        """Stop the real-time notification system"""
        self._running = False
        await self.feed_monitor.stop_monitoring()
        await self.webhook_manager.close()
        logger.info("Real-time notification system stopped")
    
    def add_webhook(self, url: str, events: List[str], secret: Optional[str] = None) -> str:
        """Add webhook endpoint"""
        webhook_events = [WebhookEvent(event) for event in events]
        return self.webhook_manager.add_webhook(url, webhook_events, secret)
    
    def remove_webhook(self, webhook_id: str) -> bool:
        """Remove webhook endpoint"""
        return self.webhook_manager.remove_webhook(webhook_id)
    
    def add_vulnerability_feed(self, name: str, url: str, poll_interval: int = 3600) -> str:
        """Add vulnerability feed"""
        return self.feed_monitor.add_feed(name, url, poll_interval)
    
    async def send_custom_alert(self, event_type: str, vulnerability_data: Dict[str, Any],
                               priority: str = "medium", metadata: Optional[Dict[str, Any]] = None):
        """Send custom vulnerability alert"""
        alert = VulnerabilityAlert(
            id=str(uuid.uuid4()),
            event_type=WebhookEvent(event_type),
            priority=NotificationPriority(priority),
            vulnerability=vulnerability_data,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        
        await self.webhook_manager.send_alert(alert)
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        webhook_stats = self.webhook_manager.get_webhook_stats()
        
        return {
            "webhooks": webhook_stats,
            "feeds": {
                "total_feeds": len(self.feed_monitor.feeds),
                "active_feeds": len([f for f in self.feed_monitor.feeds.values() if f.active]),
                "monitoring_active": self._running
            },
            "system": {
                "status": "running" if self._running else "stopped",
                "uptime": time.time()  # Would track actual uptime in production
            }
        }

# Global instance
_notification_system = None

def get_notification_system() -> RealTimeNotificationSystem:
    """Get global notification system instance"""
    global _notification_system
    if _notification_system is None:
        _notification_system = RealTimeNotificationSystem()
    return _notification_system