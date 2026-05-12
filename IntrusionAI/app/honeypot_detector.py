"""
Honeypot Integration Module
Detects honeypot interaction and assigns maximum risk score
Integrates with lightweight honeypot systems
"""

import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


class HoneypotResource:
    """Definition of a honeypot resource"""
    
    def __init__(self,
                 honeypot_id: str,
                 resource_type: str,
                 resource_path: str,
                 description: str = ""):
        self.honeypot_id = honeypot_id
        self.resource_type = resource_type  # 'file', 'service', 'account', 'share'
        self.resource_path = resource_path
        self.description = description
        self.created_at = datetime.utcnow()
        self.interaction_count = 0
        self.last_interaction = None
    
    def to_dict(self) -> Dict:
        return {
            'honeypot_id': self.honeypot_id,
            'resource_type': self.resource_type,
            'resource_path': self.resource_path,
            'description': self.description,
            'interaction_count': self.interaction_count,
            'last_interaction': self.last_interaction.isoformat() if self.last_interaction else None
        }


class HoneypotInteraction:
    """Records of honeypot interactions"""
    
    def __init__(self,
                 interaction_id: str,
                 honeypot_id: str,
                 user_id: str,
                 device_id: str,
                 interaction_type: str,  # 'access', 'execution', 'modification'
                 details: Dict,
                 timestamp: datetime = None):
        self.interaction_id = interaction_id
        self.honeypot_id = honeypot_id
        self.user_id = user_id
        self.device_id = device_id
        self.interaction_type = interaction_type
        self.details = details
        self.timestamp = timestamp or datetime.utcnow()
        self.severity = 1.0  # Maximum severity
    
    def to_dict(self) -> Dict:
        return {
            'interaction_id': self.interaction_id,
            'honeypot_id': self.honeypot_id,
            'user_id': self.user_id,
            'device_id': self.device_id,
            'interaction_type': self.interaction_type,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }


class HoneypotDetector:
    """Honeypot trap detection and tracking"""
    
    def __init__(self):
        self.honeypots = {}  # honeypot_id -> HoneypotResource
        self.interactions = []  # List of HoneypotInteraction
        self.user_honeypot_hits = {}  # user_id -> Set of honeypot_ids
    
    def register_honeypot(self,
                         honeypot_id: str,
                         resource_type: str,
                         resource_path: str,
                         description: str = "") -> HoneypotResource:
        """Register a honeypot resource"""
        honeypot = HoneypotResource(honeypot_id, resource_type, resource_path, description)
        self.honeypots[honeypot_id] = honeypot
        logger.info(f"Registered honeypot: {honeypot_id} ({resource_type}) at {resource_path}")
        return honeypot
    
    def create_file_honeypot(self,
                            file_path: str,
                            description: str = "Decoy file") -> HoneypotResource:
        """Create a decoy file honeypot"""
        honeypot_id = self._generate_honeypot_id(file_path)
        return self.register_honeypot(honeypot_id, 'file', file_path, description)
    
    def create_service_honeypot(self,
                               service_name: str,
                               port: int,
                               description: str = "Decoy service") -> HoneypotResource:
        """Create a decoy service honeypot"""
        resource_path = f"{service_name}::{port}"
        honeypot_id = self._generate_honeypot_id(resource_path)
        return self.register_honeypot(honeypot_id, 'service', resource_path, description)
    
    def create_share_honeypot(self,
                             share_path: str,
                             description: str = "Decoy share") -> HoneypotResource:
        """Create a decoy network share honeypot"""
        honeypot_id = self._generate_honeypot_id(share_path)
        return self.register_honeypot(honeypot_id, 'share', share_path, description)
    
    def record_interaction(self,
                          honeypot_id: str,
                          user_id: str,
                          device_id: str,
                          interaction_type: str,
                          details: Dict = None) -> HoneypotInteraction:
        """Record honeypot interaction"""
        if honeypot_id not in self.honeypots:
            logger.warning(f"Interaction with unknown honeypot: {honeypot_id}")
            return None
        
        interaction_id = self._generate_interaction_id(honeypot_id, user_id)
        interaction = HoneypotInteraction(
            interaction_id,
            honeypot_id,
            user_id,
            device_id,
            interaction_type,
            details or {}
        )
        
        self.interactions.append(interaction)
        
        # Update honeypot
        honeypot = self.honeypots[honeypot_id]
        honeypot.interaction_count += 1
        honeypot.last_interaction = interaction.timestamp
        
        # Track user hits
        if user_id not in self.user_honeypot_hits:
            self.user_honeypot_hits[user_id] = set()
        self.user_honeypot_hits[user_id].add(honeypot_id)
        
        logger.critical(
            f"HONEYPOT TRIGGERED: User {user_id} on device {device_id} "
            f"interacted with honeypot {honeypot_id} (type: {interaction_type})"
        )
        
        return interaction
    
    def check_honeypot_interaction(self, user_id: str, resource_path: str) -> Optional[Dict]:
        """Check if a resource path corresponds to a honeypot"""
        for honeypot in self.honeypots.values():
            # Exact match
            if honeypot.resource_path == resource_path:
                return {
                    'is_honeypot': True,
                    'honeypot_id': honeypot.honeypot_id,
                    'resource_type': honeypot.resource_type,
                    'risk_score': 1.0,  # Maximum risk
                    'message': 'CRITICAL: Honeypot triggered'
                }
            
            # Partial match (for shares/directories)
            if honeypot.resource_type in ['share', 'directory']:
                if resource_path.startswith(honeypot.resource_path):
                    return {
                        'is_honeypot': True,
                        'honeypot_id': honeypot.honeypot_id,
                        'resource_type': honeypot.resource_type,
                        'risk_score': 0.95,
                        'message': 'CRITICAL: Honeypot directory accessed'
                    }
        
        return {
            'is_honeypot': False,
            'risk_score': 0.0
        }
    
    def get_user_interactions(self, user_id: str) -> List[Dict]:
        """Get all honeypot interactions for a user"""
        user_interactions = [i for i in self.interactions if i.user_id == user_id]
        return [i.to_dict() for i in user_interactions]
    
    def get_honeypot_statistics(self) -> Dict:
        """Get honeypot system statistics"""
        return {
            'total_honeypots': len(self.honeypots),
            'by_type': self._count_by_type(),
            'total_interactions': len(self.interactions),
            'users_triggered': len(self.user_honeypot_hits),
            'most_triggered': self._get_most_triggered_honeypots(5)
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count honeypots by type"""
        counts = {}
        for honeypot in self.honeypots.values():
            rtype = honeypot.resource_type
            counts[rtype] = counts.get(rtype, 0) + 1
        return counts
    
    def _get_most_triggered_honeypots(self, limit: int = 5) -> List[Dict]:
        """Get most frequently triggered honeypots"""
        honeypot_hits = {}
        for honeypot_id, honeypot in self.honeypots.items():
            honeypot_hits[honeypot_id] = honeypot.interaction_count
        
        sorted_honeypots = sorted(
            honeypot_hits.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [
            {
                'honeypot_id': hid,
                'interaction_count': count,
                'honeypot_type': self.honeypots[hid].resource_type,
                'resource_path': self.honeypots[hid].resource_path
            }
            for hid, count in sorted_honeypots
        ]
    
    def _generate_honeypot_id(self, resource_path: str) -> str:
        """Generate honeypot ID from resource path"""
        hash_val = hashlib.sha256(resource_path.encode()).hexdigest()[:8]
        return f"honeypot_{hash_val}"
    
    def _generate_interaction_id(self, honeypot_id: str, user_id: str) -> str:
        """Generate interaction ID"""
        timestamp = datetime.utcnow().isoformat()
        raw = f"{honeypot_id}:{user_id}:{timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def alert_suspicious_access(self, honeypot_id: str, user_id: str) -> Dict:
        """Generate alert for honeypot access"""
        honeypot = self.honeypots.get(honeypot_id)
        
        if not honeypot:
            return {'error': f'Honeypot {honeypot_id} not found'}
        
        return {
            'alert_type': 'HONEYPOT_TRIGGERED',
            'severity': 'CRITICAL',
            'user_id': user_id,
            'honeypot_id': honeypot_id,
            'resource_type': honeypot.resource_type,
            'resource_path': honeypot.resource_path,
            'timestamp': datetime.utcnow().isoformat(),
            'risk_score': 1.0,
            'recommended_action': [
                'Immediately investigate user activity',
                'Check for concurrent suspicious activities',
                'Consider isolating user device',
                'Review honeypot logs for details',
                'Check if account is compromised'
            ]
        }


class HoneypotIntegrationManager:
    """High-level honeypot integration and orchestration"""
    
    def __init__(self):
        self.detector = HoneypotDetector()
        self.common_honeypots = self._create_default_honeypots()
    
    def _create_default_honeypots(self) -> List[HoneypotResource]:
        """Create default honeypot resources"""
        honeypots = []
        
        # Decoy files
        honeypots.append(self.detector.create_file_honeypot(
            'C:\\Users\\Administrator\\Documents\\admin_credentials.txt',
            'Decoy admin credentials file'
        ))
        
        honeypots.append(self.detector.create_file_honeypot(
            '/root/.ssh/id_rsa',
            'Decoy SSH private key'
        ))
        
        # Decoy shares
        honeypots.append(self.detector.create_share_honeypot(
            '\\\\honeypot-server\\confidential',
            'Decoy sensitive share'
        ))
        
        honeypots.append(self.detector.create_share_honeypot(
            '\\\\backup-server\\backup',
            'Decoy backup share'
        ))
        
        # Decoy services
        honeypots.append(self.detector.create_service_honeypot(
            'FTP',
            21,
            'Decoy FTP service'
        ))
        
        honeypots.append(self.detector.create_service_honeypot(
            'TelnetD',
            23,
            'Decoy Telnet service'
        ))
        
        return honeypots
    
    def check_resource_access(self,
                             user_id: str,
                             device_id: str,
                             resource_path: str) -> Dict:
        """Check if resource is a honeypot"""
        result = self.detector.check_honeypot_interaction(user_id, resource_path)
        
        if result['is_honeypot']:
            # Record interaction
            self.detector.record_interaction(
                result['honeypot_id'],
                user_id,
                device_id,
                'access',
                {'resource_path': resource_path}
            )
            
            # Generate alert
            alert = self.detector.alert_suspicious_access(
                result['honeypot_id'],
                user_id
            )
            
            return {
                **result,
                'alert': alert
            }
        
        return result
    
    def get_honeypot_summary(self) -> Dict:
        """Get complete honeypot system summary"""
        return {
            'statistics': self.detector.get_honeypot_statistics(),
            'honeypots': [h.to_dict() for h in self.detector.honeypots.values()],
            'recent_interactions': [
                i.to_dict() for i in self.detector.interactions[-10:]
            ]
        }


if __name__ == "__main__":
    # Example usage
    manager = HoneypotIntegrationManager()
    
    # Check access to honeypot
    result = manager.check_resource_access(
        'attacker_user',
        'compromised_device',
        'C:\\Users\\Administrator\\Documents\\admin_credentials.txt'
    )
    
    print(f"Access check result: {result}")
    
    # Get summary
    summary = manager.get_honeypot_summary()
    print(f"Honeypot summary: Triggered {summary['statistics']['total_interactions']} times")
