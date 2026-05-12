"""
Threat Intelligence Integration Module
Integrates with open-source threat intelligence platforms (MISP/OpenCTI or mock API)
Provides IP reputation, IOC matching, and threat scoring
"""

import logging
import json
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import hashlib
import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers"""
    
    @abstractmethod
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation"""
        pass
    
    @abstractmethod
    def check_ioc(self, indicator: str, indicator_type: str) -> Dict:
        """Check indicator of compromise"""
        pass


class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock provider for testing - returns realistic-looking mock data"""
    
    def __init__(self):
        """Initialize mock provider with predefined threat data"""
        self.malicious_ips = {
            '192.168.1.1': {'score': 0.95, 'threat_level': 'CRITICAL'},
            '10.0.0.100': {'score': 0.88, 'threat_level': 'HIGH'},
            '172.16.0.50': {'score': 0.72, 'threat_level': 'MEDIUM'},
            '203.0.113.42': {'score': 0.65, 'threat_level': 'MEDIUM'},
            '198.51.100.1': {'score': 0.55, 'threat_level': 'LOW'},
        }
        
        self.malicious_urls = {
            'http://malware-site.com': 0.95,
            'https://phishing-domain.net': 0.88,
            'http://c2-server.ru': 0.92,
        }
        
        self.malicious_hashes = {
            'a1b2c3d4e5f6': 0.98,
            'f6e5d4c3b2a1': 0.95,
            '1234567890ab': 0.87,
        }
        
        self.domains_to_block = {
            'evil.com', 'badactor.net', 'steal-data.org',
            'c2callback.ru', 'exploit-kit.xyz'
        }
    
    def check_ip(self, ip: str) -> Dict:
        """Mock IP reputation check"""
        score = self.malicious_ips.get(ip, {}).get('score', 0.1)
        threat_level = self.malicious_ips.get(ip, {}).get('threat_level', 'NONE')
        
        return {
            'ip': ip,
            'threat_score': score,
            'threat_level': threat_level,
            'is_malicious': score > 0.5,
            'iocs': self._generate_mock_iocs(ip),
            'source': 'mock',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def check_ioc(self, indicator: str, indicator_type: str = 'unknown') -> Dict:
        """Mock IOC check"""
        threat_score = 0.0
        is_malicious = False
        
        if indicator_type == 'url' or indicator.startswith('http'):
            threat_score = self.malicious_urls.get(indicator, 0.1)
        elif indicator_type == 'hash' or len(indicator) == 12:
            threat_score = self.malicious_hashes.get(indicator, 0.1)
        elif indicator_type == 'domain' or '.' in indicator:
            threat_score = 0.9 if indicator in self.domains_to_block else 0.1
        
        is_malicious = threat_score > 0.5
        
        return {
            'indicator': indicator,
            'type': indicator_type,
            'threat_score': threat_score,
            'is_malicious': is_malicious,
            'source': 'mock',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _generate_mock_iocs(self, ip: str) -> List[Dict]:
        """Generate mock related IOCs"""
        if ip == '192.168.1.1':
            return [
                {'type': 'domain', 'value': 'c2.evil.com'},
                {'type': 'url', 'value': 'http://malware-download.net/payload'},
                {'type': 'hash', 'value': 'a1b2c3d4e5f6'}
            ]
        elif ip == '10.0.0.100':
            return [
                {'type': 'domain', 'value': 'phishing-site.net'},
                {'type': 'hash', 'value': 'f6e5d4c3b2a1'}
            ]
        return []


class MISPProvider(ThreatIntelProvider):
    """MISP (Malware Information Sharing Platform) integration"""
    
    def __init__(self, base_url: str, api_key: str):
        """
        Initialize MISP provider
        Args:
            base_url: MISP instance URL (e.g., http://localhost)
            api_key: MISP API key
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'Authorization': self.api_key,
            'Accept': 'application/json'
        })
        
        return session
    
    def check_ip(self, ip: str) -> Dict:
        """Query MISP for IP reputation"""
        try:
            # MISP attribute search
            url = f"{self.base_url}/attributes/search"
            params = {
                'value': ip,
                'type': 'ip-dst|ip-src',
                'limit': 100
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            threat_score = self._calculate_threat_score(data)
            
            return {
                'ip': ip,
                'threat_score': threat_score,
                'is_malicious': threat_score > 0.5,
                'iocs': self._extract_iocs(data),
                'source': 'misp',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.warning(f"MISP check_ip failed for {ip}: {e}")
            return {
                'ip': ip,
                'threat_score': 0.0,
                'is_malicious': False,
                'error': str(e),
                'source': 'misp'
            }
    
    def check_ioc(self, indicator: str, indicator_type: str = 'unknown') -> Dict:
        """Query MISP for indicator"""
        try:
            url = f"{self.base_url}/attributes/search"
            params = {
                'value': indicator,
                'limit': 50
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            threat_score = self._calculate_threat_score(data)
            
            return {
                'indicator': indicator,
                'type': indicator_type,
                'threat_score': threat_score,
                'is_malicious': threat_score > 0.5,
                'source': 'misp',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.warning(f"MISP check_ioc failed for {indicator}: {e}")
            return {
                'indicator': indicator,
                'type': indicator_type,
                'threat_score': 0.0,
                'error': str(e),
                'source': 'misp'
            }
    
    def _calculate_threat_score(self, misp_data: Dict) -> float:
        """Calculate threat score from MISP response"""
        if 'response' not in misp_data:
            return 0.0
        
        attributes = misp_data.get('response', {}).get('Attribute', [])
        if not attributes:
            return 0.0
        
        # Score based on number of detections
        detection_count = len(attributes)
        threat_score = min(detection_count / 10.0, 1.0)
        
        # Boost score if marked as malicious
        for attr in attributes:
            tags = attr.get('Tag', [])
            for tag in tags:
                if 'malware' in tag.get('name', '').lower():
                    threat_score = min(threat_score + 0.3, 1.0)
        
        return threat_score
    
    def _extract_iocs(self, misp_data: Dict) -> List[Dict]:
        """Extract IOCs from MISP response"""
        iocs = []
        
        attributes = misp_data.get('response', {}).get('Attribute', [])
        for attr in attributes:
            iocs.append({
                'type': attr.get('type', 'unknown'),
                'value': attr.get('value', ''),
            })
        
        return iocs[:5]  # Limit to 5


class ThreatIntelCache:
    """In-memory cache for threat intelligence lookups"""
    
    def __init__(self, ttl_seconds: int = 3600):
        """
        Args:
            ttl_seconds: Time-to-live for cache entries
        """
        self.cache = {}
        self.ttl_seconds = ttl_seconds
    
    def get(self, key: str) -> Optional[Dict]:
        """Get cached entry"""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        if datetime.utcnow() > entry['expires']:
            del self.cache[key]
            return None
        
        return entry['data']
    
    def set(self, key: str, data: Dict):
        """Set cache entry"""
        self.cache[key] = {
            'data': data,
            'expires': datetime.utcnow() + timedelta(seconds=self.ttl_seconds)
        }
    
    def clear_expired(self):
        """Remove expired entries"""
        now = datetime.utcnow()
        expired_keys = [
            k for k, v in self.cache.items()
            if now > v['expires']
        ]
        for k in expired_keys:
            del self.cache[k]
        
        return len(expired_keys)


class ThreatIntelligenceManager:
    """Unified threat intelligence manager"""
    
    def __init__(self, 
                 provider: Optional[ThreatIntelProvider] = None,
                 use_cache: bool = True,
                 cache_ttl: int = 3600):
        """
        Args:
            provider: ThreatIntelProvider instance (defaults to MockProvider)
            use_cache: Enable caching
            cache_ttl: Cache TTL in seconds
        """
        self.provider = provider or MockThreatIntelProvider()
        self.cache = ThreatIntelCache(cache_ttl) if use_cache else None
        self.use_cache = use_cache
    
    def get_threat_score(self, ip: str, device_id: str = None, 
                        session_id: str = None) -> float:
        """
        Get threat score for an IP
        Returns: 0-1 threat score
        """
        cache_key = f"ip:{ip}"
        
        # Check cache
        if self.use_cache:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"Threat cache hit for {ip}")
                return cached.get('threat_score', 0.0)
        
        # Query provider
        result = self.provider.check_ip(ip)
        threat_score = result.get('threat_score', 0.0)
        
        # Update cache
        if self.use_cache:
            self.cache.set(cache_key, result)
        
        return threat_score
    
    def check_indicator(self, indicator: str, 
                       indicator_type: str = 'unknown',
                       device_id: str = None) -> Dict:
        """
        Check indicator of compromise
        Returns: IOC data with threat score
        """
        # Detect type if not provided
        if indicator_type == 'unknown':
            indicator_type = self._detect_type(indicator)
        
        cache_key = f"ioc:{indicator_type}:{indicator}"
        
        # Check cache
        if self.use_cache:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"IOC cache hit for {indicator}")
                return cached
        
        # Query provider
        result = self.provider.check_ioc(indicator, indicator_type)
        
        # Update cache
        if self.use_cache:
            self.cache.set(cache_key, result)
        
        return result
    
    def batch_check_ips(self, ips: List[str]) -> Dict[str, float]:
        """Batch check multiple IPs"""
        results = {}
        for ip in ips:
            results[ip] = self.get_threat_score(ip)
        return results
    
    def is_high_risk_ip(self, ip: str, threshold: float = 0.7) -> bool:
        """Check if IP is above risk threshold"""
        return self.get_threat_score(ip) > threshold
    
    def _detect_type(self, indicator: str) -> str:
        """Auto-detect indicator type"""
        # IP address
        if self._is_ip(indicator):
            return 'ip'
        
        # URL
        if indicator.startswith('http://') or indicator.startswith('https://'):
            return 'url'
        
        # Domain
        if '.' in indicator and not self._is_ip(indicator):
            return 'domain'
        
        # Hash (MD5/SHA1/SHA256)
        if re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', indicator, re.I):
            return 'hash'
        
        # Hostname
        if re.match(r'^[a-zA-Z0-9-]+$', indicator):
            return 'hostname'
        
        return 'unknown'
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is IP address"""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'provider': self.provider.__class__.__name__,
            'cache_enabled': self.use_cache,
            'cache_size': len(self.cache.cache) if self.cache else 0
        }


class ThreatContextBuilder:
    """Build comprehensive threat context for a user/device"""
    
    def __init__(self, threat_intel: ThreatIntelligenceManager):
        self.threat_intel = threat_intel
        self.whitelist = set()
        self.blacklist = set()
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist (always trusted)"""
        self.whitelist.add(ip)
    
    def add_to_blacklist(self, ip: str):
        """Add IP to blacklist (always blocked)"""
        self.blacklist.add(ip)
    
    def get_context(self, ip: str, device_id: str = None) -> Dict:
        """
        Get full threat context for an IP
        
        Returns:
            {
                'ip': IP address,
                'threat_score': 0-1,
                'threat_level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE',
                'whitelist_status': bool,
                'blacklist_status': bool,
                'iocs': List[IOC],
                'recommendations': List[str]
            }
        """
        # Check lists
        if ip in self.whitelist:
            return {
                'ip': ip,
                'threat_score': 0.0,
                'threat_level': 'NONE',
                'whitelist_status': True,
                'blacklist_status': False,
                'source': 'whitelist'
            }
        
        if ip in self.blacklist:
            return {
                'ip': ip,
                'threat_score': 1.0,
                'threat_level': 'CRITICAL',
                'whitelist_status': False,
                'blacklist_status': True,
                'source': 'blacklist'
            }
        
        # Query threat intel
        threat_score = self.threat_intel.get_threat_score(ip, device_id)
        threat_level = self._score_to_level(threat_score)
        
        # Get IOCs
        ioc_result = self.threat_intel.provider.check_ioc(ip, 'ip') if hasattr(
            self.threat_intel.provider, 'check_ip'
        ) else {}
        
        iocs = ioc_result.get('iocs', []) if isinstance(ioc_result, dict) else []
        
        # Generate recommendations
        recommendations = self._get_recommendations(threat_level)
        
        return {
            'ip': ip,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'whitelist_status': False,
            'blacklist_status': False,
            'iocs': iocs,
            'recommendations': recommendations
        }
    
    def _score_to_level(self, score: float) -> str:
        """Convert threat score to threat level"""
        if score >= 0.85:
            return 'CRITICAL'
        elif score >= 0.70:
            return 'HIGH'
        elif score >= 0.50:
            return 'MEDIUM'
        elif score >= 0.25:
            return 'LOW'
        else:
            return 'NONE'
    
    def _get_recommendations(self, threat_level: str) -> List[str]:
        """Get security recommendations"""
        recommendations = {
            'CRITICAL': [
                'Force logout immediately',
                'Terminate active sessions',
                'Escalate to SOC',
                'Block all connections from this IP'
            ],
            'HIGH': [
                'Require MFA',
                'Monitor closely',
                'Escalate to SOC',
                'Consider blocking'
            ],
            'MEDIUM': [
                'Log all activity',
                'Monitor for abnormalities',
                'Review recent activity'
            ],
            'LOW': [
                'Standard monitoring'
            ],
            'NONE': [
                'No special action required'
            ]
        }
        return recommendations.get(threat_level, [])


if __name__ == "__main__":
    # Example usage
    
    # Use mock provider
    provider = MockThreatIntelProvider()
    threat_intel = ThreatIntelligenceManager(provider=provider)
    
    # Check IP
    score = threat_intel.get_threat_score('192.168.1.1')
    print(f"Threat score for 192.168.1.1: {score}")
    
    # Check IOC
    result = threat_intel.check_indicator('malware-site.com')
    print(f"IOC check result: {result}")
    
    # Build threat context
    context_builder = ThreatContextBuilder(threat_intel)
    context = context_builder.get_context('192.168.1.1')
    print(f"Threat context: {json.dumps(context, indent=2)}")
