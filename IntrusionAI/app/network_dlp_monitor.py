"""
Network Behavior Monitoring & Data Loss Prevention (DLP) Module
Detects unusual outbound connections, data exfiltration patterns
Monitors file access frequency and large file transfers
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict
import re

logger = logging.getLogger(__name__)


class NetworkFlow:
    """Represents a network flow/connection"""
    
    def __init__(self,
                 flow_id: str,
                 user_id: str,
                 device_id: str,
                 src_ip: str,
                 dst_ip: str,
                 dst_port: int,
                 protocol: str,
                 bytes_sent: int,
                 bytes_received: int,
                 timestamp: datetime,
                 connection_duration: int = 0):
        self.flow_id = flow_id
        self.user_id = user_id
        self.device_id = device_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received
        self.timestamp = timestamp
        self.connection_duration = connection_duration
        self.is_anomalous = False
        self.risk_score = 0.0
    
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received
    
    def to_dict(self) -> Dict:
        return {
            'flow_id': self.flow_id,
            'user_id': self.user_id,
            'device_id': self.device_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'total_bytes': self.total_bytes(),
            'duration': self.connection_duration,
            'is_anomalous': self.is_anomalous,
            'risk_score': self.risk_score,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkBehaviorMonitor:
    """Monitor network behavior patterns"""
    
    def __init__(self):
        self.flows = []  # Recent flows
        self.user_flow_stats = defaultdict(lambda: {
            'total_flows': 0,
            'total_bytes': 0,
            'unique_destinations': set(),
            'connections': []
        })
        
        # Suspicious destinations
        self.suspicious_destinations = {
            '203.0.113.0/24',  # Documentation IP range
            '198.51.100.0/24',  # Documentation IP range
            '192.0.2.0/24',     # Documentation IP range
        }
        
        # Suspicious ports
        self.suspicious_ports = {
            4444, 5555, 6666, 6667,  # Common C2 ports
            22,    # SSH to unexpected destination
            3389,  # RDP
            445,   # SMB
            139    # NetBIOS
        }
    
    def add_flow(self, flow: NetworkFlow) -> Dict:
        """Add network flow and check for anomalies"""
        self.flows.append(flow)
        
        # Keep only recent flows (last hour)
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        self.flows = [f for f in self.flows if f.timestamp > cutoff_time]
        
        # Update user statistics
        stats = self.user_flow_stats[flow.user_id]
        stats['total_flows'] += 1
        stats['total_bytes'] += flow.total_bytes()
        stats['unique_destinations'].add(flow.dst_ip)
        stats['connections'].append(flow)
        
        # Analyze for anomalies
        anomaly_info = self._detect_anomaly(flow)
        flow.is_anomalous = anomaly_info['is_anomalous']
        flow.risk_score = anomaly_info['risk_score']
        
        return anomaly_info
    
    def _detect_anomaly(self, flow: NetworkFlow) -> Dict:
        """Detect if flow is anomalous"""
        risk_score = 0.0
        anomalies = []
        
        # Check 1: Suspicious destination port
        if flow.dst_port in self.suspicious_ports:
            risk_score += 0.25
            anomalies.append('suspicious_port')
        
        # Check 2: Unusual port (high numbers)
        if flow.dst_port > 10000:
            risk_score += 0.15
            anomalies.append('unusual_high_port')
        
        # Check 3: Large data transfer
        if flow.bytes_sent > 100_000_000 or flow.bytes_received > 100_000_000:  # >100MB
            risk_score += 0.30
            anomalies.append('large_transfer')
        
        # Check 4: Outbound to suspicious destination
        if self._is_suspicious_destination(flow.dst_ip):
            risk_score += 0.35
            anomalies.append('suspicious_destination')
        
        # Check 5: New destination for user
        user_dests = self.user_flow_stats[flow.user_id]['unique_destinations']
        if flow.dst_ip not in user_dests and len(user_dests) > 0:
            risk_score += 0.15
            anomalies.append('new_destination')
        
        # Check 6: Multiple connections to different ports on same IP
        user_flows = self.user_flow_stats[flow.user_id]['connections']
        same_ip_dests = [f.dst_port for f in user_flows if f.dst_ip == flow.dst_ip]
        if len(set(same_ip_dests)) >= 5:
            risk_score += 0.25
            anomalies.append('port_scanning')
        
        return {
            'is_anomalous': risk_score > 0.5,
            'risk_score': min(risk_score, 1.0),
            'anomalies': anomalies
        }
    
    def _is_suspicious_destination(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        # Very simplified check
        if ip.startswith('203.0.113') or ip.startswith('198.51.100'):
            return True
        return False
    
    def detect_data_exfiltration(self, user_id: str, 
                                threshold_bytes: int = 500_000_000) -> List[Dict]:
        """
        Detect potential data exfiltration
        Returns: List of suspicious patterns
        """
        warnings = []
        
        stats = self.user_flow_stats[user_id]
        
        # Check total bytes transferred
        if stats['total_bytes'] > threshold_bytes:
            warnings.append({
                'type': 'high_volume_transfer',
                'user_id': user_id,
                'total_bytes': stats['total_bytes'],
                'threshold': threshold_bytes,
                'risk_score': 0.7
            })
        
        # Check for unusual pattern: many connections with small/medium volumes
        recent_connections = stats['connections'][-20:] if stats['connections'] else []
        
        if len(recent_connections) >= 10:
            avg_bytes = sum(f.total_bytes() for f in recent_connections) / len(recent_connections)
            
            # Pattern: Many connections, each transferring data
            if avg_bytes > 1_000_000:  # >1MB each
                warnings.append({
                    'type': 'repeated_large_transfers',
                    'user_id': user_id,
                    'connection_count': len(recent_connections),
                    'avg_bytes_per_connection': avg_bytes,
                    'risk_score': 0.8
                })
        
        return warnings
    
    def get_user_network_profile(self, user_id: str) -> Dict:
        """Get network behavior profile for user"""
        stats = self.user_flow_stats.get(user_id, {})
        
        if not stats.get('connections'):
            return {'user_id': user_id, 'message': 'No network activity'}
        
        connections = stats['connections']
        
        return {
            'user_id': user_id,
            'total_flows': stats['total_flows'],
            'total_bytes': stats['total_bytes'],
            'unique_destinations': len(stats['unique_destinations']),
            'avg_bytes_per_flow': stats['total_bytes'] / stats['total_flows'] if stats['total_flows'] > 0 else 0,
            'common_ports': self._get_common_ports(connections),
            'last_activity': connections[-1].timestamp.isoformat() if connections else None
        }
    
    def _get_common_ports(self, connections: List[NetworkFlow]) -> List[Tuple[int, int]]:
        """Get most common destination ports"""
        port_counts = defaultdict(int)
        for flow in connections:
            port_counts[flow.dst_port] += 1
        
        return sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]


class DataLossPreventionMonitor:
    """Monitor file access, USB usage, and large transfers"""
    
    def __init__(self):
        self.file_accesses = []
        self.usb_events = []
        self.large_transfers = []
        self.user_file_stats = defaultdict(lambda: defaultdict(int))
    
    def log_file_access(self,
                       user_id: str,
                       device_id: str,
                       file_path: str,
                       access_type: str,
                       file_size: int,
                       timestamp: datetime = None):
        """Log file access"""
        timestamp = timestamp or datetime.utcnow()
        
        access = {
            'user_id': user_id,
            'device_id': device_id,
            'file_path': file_path,
            'access_type': access_type,
            'file_size': file_size,
            'timestamp': timestamp
        }
        
        self.file_accesses.append(access)
        
        # Keep only recent
        cutoff_time = datetime.utcnow() - timedelta(days=7)
        self.file_accesses = [a for a in self.file_accesses if a['timestamp'] > cutoff_time]
        
        # Update stats
        self.user_file_stats[user_id][file_path] += 1
        
        # Check for suspicious pattern
        return self._check_file_access_anomaly(user_id, file_path)
    
    def _check_file_access_anomaly(self, user_id: str, file_path: str) -> Dict:
        """Check for unusual file access patterns"""
        risk_score = 0.0
        anomalies = []
        
        # Check 1: Sensitive file extensions
        sensitive_extensions = {'.xlsx', '.docx', '.pdf', '.pptx', '.sql', '.csv', '.json', '.key', '.pem'}
        if any(file_path.endswith(ext) for ext in sensitive_extensions):
            risk_score += 0.20
            anomalies.append('sensitive_file_type')
        
        # Check 2: System files
        if file_path.startswith('C:\\Windows') or file_path.startswith('/etc'):
            risk_score += 0.15
            anomalies.append('system_file_access')
        
        # Check 3: Rapid repeated access
        recent_accesses = [
            a for a in self.file_accesses
            if a['user_id'] == user_id and a['file_path'] == file_path and
            a['timestamp'] > datetime.utcnow() - timedelta(minutes=5)
        ]
        
        if len(recent_accesses) > 10:  # >10 accesses in 5 minutes
            risk_score += 0.25
            anomalies.append('rapid_access_pattern')
        
        return {
            'risk_score': min(risk_score, 1.0),
            'anomalies': anomalies,
            'is_anomalous': risk_score > 0.3
        }
    
    def log_usb_event(self,
                     user_id: str,
                     device_id: str,
                     usb_device: str,
                     event_type: str,  # 'connected', 'disconnected', 'data_written'
                     bytes_written: int = 0,
                     timestamp: datetime = None):
        """Log USB device event"""
        timestamp = timestamp or datetime.utcnow()
        
        event = {
            'user_id': user_id,
            'device_id': device_id,
            'usb_device': usb_device,
            'event_type': event_type,
            'bytes_written': bytes_written,
            'timestamp': timestamp
        }
        
        self.usb_events.append(event)
        
        # Check risk
        risk = 0.0
        if event_type == 'data_written' and bytes_written > 100_000_000:  # >100MB
            risk = 0.8
        elif event_type in ['connected', 'disconnected']:
            risk = 0.3
        
        return {
            'risk_score': risk,
            'is_anomalous': risk > 0.5,
            'message': f"USB {event_type}: {usb_device}"
        }
    
    def log_large_transfer(self,
                          user_id: str,
                          device_id: str,
                          source: str,
                          destination: str,
                          bytes_transferred: int,
                          timestamp: datetime = None):
        """Log large file transfer"""
        timestamp = timestamp or datetime.utcnow()
        
        transfer = {
            'user_id': user_id,
            'device_id': device_id,
            'source': source,
            'destination': destination,
            'bytes': bytes_transferred,
            'timestamp': timestamp
        }
        
        self.large_transfers.append(transfer)
        
        # Calculate risk
        risk = min(bytes_transferred / 1_000_000_000, 1.0)  # Risk proportional to size (up to 1GB)
        
        return {
            'risk_score': risk,
            'is_anomalous': risk > 0.5,
            'message': f"Large transfer: {bytes_transferred / 1_000_000:.1f}MB"
        }
    
    def get_dlp_violations(self, user_id: str, hours: int = 24) -> List[Dict]:
        """Get DLP violations for user"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        violations = []
        
        # File access violations
        file_violations = [
            a for a in self.file_accesses
            if a['user_id'] == user_id and a['timestamp'] > cutoff_time
        ]
        for violation in file_violations:
            if self._check_file_access_anomaly(user_id, violation['file_path'])['is_anomalous']:
                violations.append({
                    'type': 'file_access',
                    'file_path': violation['file_path'],
                    'timestamp': violation['timestamp'].isoformat()
                })
        
        # USB violations
        usb_violations = [
            e for e in self.usb_events
            if e['user_id'] == user_id and e['timestamp'] > cutoff_time
            and e['event_type'] == 'data_written' and e['bytes_written'] > 100_000_000
        ]
        violations.extend([
            {
                'type': 'usb_data_transfer',
                'usb_device': v['usb_device'],
                'bytes': v['bytes_written'],
                'timestamp': v['timestamp'].isoformat()
            }
            for v in usb_violations
        ])
        
        # Large transfer violations
        large_transfers = [
            t for t in self.large_transfers
            if t['user_id'] == user_id and t['timestamp'] > cutoff_time
            and t['bytes'] > 500_000_000
        ]
        violations.extend([
            {
                'type': 'large_transfer',
                'source': t['source'],
                'destination': t['destination'],
                'bytes': t['bytes'],
                'timestamp': t['timestamp'].isoformat()
            }
            for t in large_transfers
        ])
        
        return violations
    
    def get_dlp_summary(self) -> Dict:
        """Get DLP monitoring summary"""
        return {
            'total_file_accesses': len(self.file_accesses),
            'total_usb_events': len(self.usb_events),
            'large_transfers': len(self.large_transfers),
            'dates_covered': {
                'earliest': min([a['timestamp'] for a in self.file_accesses]).isoformat() if self.file_accesses else None,
                'latest': max([a['timestamp'] for a in self.file_accesses]).isoformat() if self.file_accesses else None
            }
        }


if __name__ == "__main__":
    # Network monitoring example
    net_monitor = NetworkBehaviorMonitor()
    
    flow = NetworkFlow(
        'flow_1',
        'user1',
        'device1',
        '192.168.1.100',
        '203.0.113.42',
        4444,
        'TCP',
        50_000_000,
        100_000_000,
        datetime.utcnow()
    )
    
    result = net_monitor.add_flow(flow)
    print(f"Flow anomaly: {result}")
    
    # DLP monitoring example
    dlp = DataLossPreventionMonitor()
    
    file_access = dlp.log_file_access(
        'user1', 'device1',
        'C:\\Users\\user1\\Documents\\confidential.xlsx',
        'read',
        5_000_000
    )
    print(f"File access risk: {file_access}")
    
    usb_event = dlp.log_usb_event(
        'user1', 'device1',
        'USB_Drive_XYZ',
        'data_written',
        200_000_000
    )
    print(f"USB event risk: {usb_event}")
