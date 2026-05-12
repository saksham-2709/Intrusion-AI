"""
Multi-Source Correlation Engine
Correlates behavioral data, process logs, and network logs
Uses time-windowed analysis for event aggregation
Creates unified anomaly scoring
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import hashlib
from enum import Enum

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events that can be correlated"""
    BEHAVIORAL = "behavioral"
    PROCESS_LOG = "process_log"
    NETWORK_LOG = "network_log"
    FILE_ACCESS = "file_access"
    AUTHENTICATION = "authentication"
    SECURITY_ALERT = "security_alert"
    SYSTEM_EVENT = "system_event"


class CorrelationEvent:
    """Individual event to be correlated"""
    
    def __init__(self, 
                 event_id: str,
                 event_type: EventType,
                 user_id: str,
                 device_id: str,
                 timestamp: datetime,
                 data: Dict,
                 severity: float = 0.5):
        """
        Args:
            event_id: Unique event identifier
            event_type: Type of event
            user_id: User associated with event
            device_id: Device associated with event
            timestamp: Event timestamp
            data: Event-specific data
            severity: 0-1 severity score
        """
        self.event_id = event_id
        self.event_type = event_type
        self.user_id = user_id
        self.device_id = device_id
        self.timestamp = timestamp
        self.data = data
        self.severity = severity
        self.correlation_id = None  # Set by correlator
    
    def to_dict(self) -> Dict:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'device_id': self.device_id,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity,
            'correlation_id': self.correlation_id
        }


class CorrelationPattern:
    """Represents a correlated pattern of events"""
    
    def __init__(self, 
                 correlation_id: str,
                 pattern_name: str,
                 user_id: str,
                 device_id: str,
                 events: List[CorrelationEvent]):
        self.correlation_id = correlation_id
        self.pattern_name = pattern_name
        self.user_id = user_id
        self.device_id = device_id
        self.events = events
        self.created_at = datetime.utcnow()
        self.severity = self._calculate_severity()
        self.confidence = self._calculate_confidence()
    
    def _calculate_severity(self) -> float:
        """Calculate aggregate severity"""
        if not self.events:
            return 0.0
        
        # Weight by time proximity (more recent = higher weight)
        now = datetime.utcnow()
        weighted_severity = 0.0
        
        for event in self.events:
            time_delta = (now - event.timestamp).total_seconds()
            # Exponential decay (half-life: 1 hour)
            time_weight = np.exp(-time_delta / 3600.0)
            weighted_severity += event.severity * time_weight
        
        return weighted_severity / len(self.events)
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence in pattern (based on event count and consistency)"""
        event_count = len(self.events)
        
        # More events = higher confidence
        confidence_from_count = min(event_count / 5.0, 1.0)
        
        # Consistency in severities
        severities = [e.severity for e in self.events]
        consistency = 1.0 - np.std(severities) if len(severities) > 1 else 0.5
        
        return (confidence_from_count + consistency) / 2.0
    
    def to_dict(self) -> Dict:
        return {
            'correlation_id': self.correlation_id,
            'pattern_name': self.pattern_name,
            'user_id': self.user_id,
            'device_id': self.device_id,
            'event_count': len(self.events),
            'severity': self.severity,
            'confidence': self.confidence,
            'created_at': self.created_at.isoformat(),
            'events': [e.to_dict() for e in self.events],
            'pattern_summary': self._generate_summary()
        }
    
    def _generate_summary(self) -> str:
        """Generate human-readable pattern summary"""
        event_types = [e.event_type.value for e in self.events]
        type_counts = {}
        for et in event_types:
            type_counts[et] = type_counts.get(et, 0) + 1
        
        type_summary = ', '.join([f"{count} {t}" for t, count in type_counts.items()])
        return f"{self.pattern_name}: {type_summary}"


class EventCorrelationEngine:
    """Main correlation engine"""
    
    def __init__(self, 
                 time_window_seconds: int = 300,
                 max_events_per_window: int = 1000):
        """
        Args:
            time_window_seconds: Time window for correlation (default: 5 minutes)
            max_events_per_window: Maximum events to keep per window
        """
        self.time_window_seconds = time_window_seconds
        self.max_events_per_window = max_events_per_window
        
        # Event buffers
        self.event_buffer = deque(maxlen=max_events_per_window)
        self.user_time_buffer = defaultdict(lambda: deque())  # By user
        self.device_time_buffer = defaultdict(lambda: deque())  # By device
        
        # Correlation patterns detected
        self.patterns = []
        self.correlation_counter = 0
        
        # Pattern rules
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> Dict:
        """Initialize correlation rules"""
        return {
            'rapid_file_access': {
                'description': 'Multiple file accesses in short time',
                'event_types': [EventType.FILE_ACCESS],
                'min_events': 3,
                'time_window': 60,  # 1 minute
                'severity_multiplier': 1.5
            },
            'process_chain': {
                'description': 'Suspicious process execution chain',
                'event_types': [EventType.PROCESS_LOG],
                'triggers': ['cmd', 'powershell', 'whoami', 'ipconfig'],
                'severity_multiplier': 2.0
            },
            'network_anomaly': {
                'description': 'Unusual network activity pattern',
                'event_types': [EventType.NETWORK_LOG],
                'min_events': 5,
                'severity_multiplier': 1.8
            },
            'auth_anomaly': {
                'description': 'Multiple authentication attempts',
                'event_types': [EventType.AUTHENTICATION],
                'min_events': 3,
                'time_window': 180,  # 3 minutes
                'severity_multiplier': 2.5
            },
            'data_exfiltration': {
                'description': 'Large data transfer detected',
                'event_types': [EventType.NETWORK_LOG, EventType.FILE_ACCESS],
                'min_events': 2,
                'severity_multiplier': 3.0
            }
        }
    
    def add_event(self, event: CorrelationEvent) -> bool:
        """
        Add event to buffer
        Returns: True if event was added
        """
        # Add to main buffer
        self.event_buffer.append(event)
        
        # Add to user-specific buffer
        self.user_time_buffer[event.user_id].append(event)
        
        # Add to device-specific buffer
        self.device_time_buffer[event.device_id].append(event)
        
        # Clean old entries
        self._cleanup_buffers()
        
        return True
    
    def _cleanup_buffers(self):
        """Remove events older than time window"""
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.time_window_seconds)
        
        # Clean user buffers
        for user_id in list(self.user_time_buffer.keys()):
            while self.user_time_buffer[user_id] and self.user_time_buffer[user_id][0].timestamp < cutoff_time:
                self.user_time_buffer[user_id].popleft()
        
        # Clean device buffers
        for device_id in list(self.device_time_buffer.keys()):
            while self.device_time_buffer[device_id] and self.device_time_buffer[device_id][0].timestamp < cutoff_time:
                self.device_time_buffer[device_id].popleft()
    
    def correlate(self) -> List[CorrelationPattern]:
        """
        Perform correlation on buffered events
        Returns: List of detected patterns
        """
        detected_patterns = []
        
        # Check each rule
        for rule_name, rule_config in self.rules.items():
            patterns = self._apply_rule(rule_name, rule_config)
            detected_patterns.extend(patterns)
        
        # Check temporal correlations (events close in time)
        temporal_patterns = self._find_temporal_correlations()
        detected_patterns.extend(temporal_patterns)
        
        self.patterns.extend(detected_patterns)
        
        return detected_patterns
    
    def _apply_rule(self, rule_name: str, rule_config: Dict) -> List[CorrelationPattern]:
        """Apply a specific rule to detect patterns"""
        patterns = []
        
        # Match by event types
        target_types = rule_config.get('event_types', [])
        matching_events = [e for e in self.event_buffer if e.event_type in target_types]
        
        if not matching_events:
            return patterns
        
        # Rule-specific logic
        if rule_name == 'rapid_file_access':
            patterns.extend(self._detect_rapid_file_access(matching_events, rule_config))
        elif rule_name == 'process_chain':
            patterns.extend(self._detect_process_chain(matching_events, rule_config))
        elif rule_name == 'network_anomaly':
            patterns.extend(self._detect_network_anomaly(matching_events, rule_config))
        elif rule_name == 'auth_anomaly':
            patterns.extend(self._detect_auth_anomaly(matching_events, rule_config))
        elif rule_name == 'data_exfiltration':
            patterns.extend(self._detect_data_exfiltration(matching_events, rule_config))
        
        return patterns
    
    def _detect_rapid_file_access(self, events: List[CorrelationEvent], 
                                  config: Dict) -> List[CorrelationPattern]:
        """Detect rapid file access pattern"""
        patterns = []
        user_groups = defaultdict(list)
        
        for event in events:
            user_groups[event.user_id].append(event)
        
        for user_id, user_events in user_groups.items():
            if len(user_events) >= config['min_events']:
                # Check time proximity
                sorted_events = sorted(user_events, key=lambda e: e.timestamp)
                time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
                
                if time_span <= config['time_window']:
                    for event in user_events:
                        event.severity *= config['severity_multiplier']
                    
                    pattern = CorrelationPattern(
                        correlation_id=self._generate_correlation_id(),
                        pattern_name='Rapid File Access',
                        user_id=user_id,
                        device_id=user_events[0].device_id,
                        events=user_events
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_process_chain(self, events: List[CorrelationEvent], 
                             config: Dict) -> List[CorrelationPattern]:
        """Detect suspicious process execution chain"""
        patterns = []
        
        triggers = config.get('triggers', [])
        suspicious_events = []
        
        for event in events:
            if 'process_name' in event.data:
                for trigger in triggers:
                    if trigger.lower() in event.data['process_name'].lower():
                        suspicious_events.append(event)
                        event.severity = min(event.severity * config['severity_multiplier'], 1.0)
        
        if suspicious_events:
            # Group by user and device
            for user_id in set(e.user_id for e in suspicious_events):
                user_events = [e for e in suspicious_events if e.user_id == user_id]
                
                pattern = CorrelationPattern(
                    correlation_id=self._generate_correlation_id(),
                    pattern_name='Process Chain Detected',
                    user_id=user_id,
                    device_id=user_events[0].device_id,
                    events=user_events
                )
                patterns.append(pattern)
        
        return patterns
    
    def _detect_network_anomaly(self, events: List[CorrelationEvent], 
                               config: Dict) -> List[CorrelationPattern]:
        """Detect unusual network activity"""
        patterns = []
        user_groups = defaultdict(list)
        
        for event in events:
            user_groups[event.user_id].append(event)
        
        for user_id, user_events in user_groups.items():
            if len(user_events) >= config['min_events']:
                # Check for volume anomaly
                total_bytes = sum(e.data.get('bytes', 0) for e in user_events)
                
                for event in user_events:
                    event.severity *= config['severity_multiplier']
                
                pattern = CorrelationPattern(
                    correlation_id=self._generate_correlation_id(),
                    pattern_name='Network Anomaly Detected',
                    user_id=user_id,
                    device_id=user_events[0].device_id,
                    events=user_events
                )
                patterns.append(pattern)
        
        return patterns
    
    def _detect_auth_anomaly(self, events: List[CorrelationEvent], 
                            config: Dict) -> List[CorrelationPattern]:
        """Detect authentication anomalies"""
        patterns = []
        user_groups = defaultdict(list)
        
        for event in events:
            user_groups[event.user_id].append(event)
        
        for user_id, user_events in user_groups.items():
            failed_events = [e for e in user_events if e.data.get('status') == 'failed']
            
            if len(failed_events) >= config['min_events']:
                sorted_events = sorted(failed_events, key=lambda e: e.timestamp)
                time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
                
                if time_span <= config['time_window']:
                    for event in failed_events:
                        event.severity = min(event.severity * config['severity_multiplier'], 1.0)
                    
                    pattern = CorrelationPattern(
                        correlation_id=self._generate_correlation_id(),
                        pattern_name='Multiple Failed Authentications',
                        user_id=user_id,
                        device_id=failed_events[0].device_id,
                        events=failed_events
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_data_exfiltration(self, events: List[CorrelationEvent], 
                                 config: Dict) -> List[CorrelationPattern]:
        """Detect data exfiltration attempts"""
        patterns = []
        
        # Find file access + network activity combinations
        file_events = defaultdict(list)
        network_events = defaultdict(list)
        
        for event in events:
            if event.event_type == EventType.FILE_ACCESS:
                file_events[event.user_id].append(event)
            elif event.event_type == EventType.NETWORK_LOG:
                network_events[event.user_id].append(event)
        
        # Find correlations
        for user_id in file_events:
            if user_id in network_events:
                combined = file_events[user_id] + network_events[user_id]
                
                if len(combined) >= config['min_events']:
                    for event in combined:
                        event.severity = min(event.severity * config['severity_multiplier'], 1.0)
                    
                    pattern = CorrelationPattern(
                        correlation_id=self._generate_correlation_id(),
                        pattern_name='Potential Data Exfiltration',
                        user_id=user_id,
                        device_id=combined[0].device_id,
                        events=combined
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _find_temporal_correlations(self) -> List[CorrelationPattern]:
        """Find correlations based on temporal proximity"""
        patterns = []
        
        # Group events by user and device
        user_device_events = defaultdict(list)
        
        for event in self.event_buffer:
            key = (event.user_id, event.device_id)
            user_device_events[key].append(event)
        
        # Check each group for temporal clustering
        for (user_id, device_id), events in user_device_events.items():
            if len(events) >= 3:
                sorted_events = sorted(events, key=lambda e: e.timestamp)
                
                # Check clustering
                time_gaps = []
                for i in range(1, len(sorted_events)):
                    gap = (sorted_events[i].timestamp - sorted_events[i-1].timestamp).total_seconds()
                    time_gaps.append(gap)
                
                avg_gap = np.mean(time_gaps)
                
                # If events are clustered (small gaps), create pattern
                if avg_gap < 30:  # Less than 30 seconds apart
                    pattern = CorrelationPattern(
                        correlation_id=self._generate_correlation_id(),
                        pattern_name='Temporal Event Clustering',
                        user_id=user_id,
                        device_id=device_id,
                        events=sorted_events
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def get_patterns_for_user(self, user_id: str) -> List[CorrelationPattern]:
        """Get all patterns for a specific user"""
        return [p for p in self.patterns if p.user_id == user_id]
    
    def get_patterns_for_device(self, device_id: str) -> List[CorrelationPattern]:
        """Get all patterns for a specific device"""
        return [p for p in self.patterns if p.device_id == device_id]
    
    def get_recent_patterns(self, hours: int = 24) -> List[CorrelationPattern]:
        """Get patterns from recent time period"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [p for p in self.patterns if p.created_at > cutoff]
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID"""
        self.correlation_counter += 1
        timestamp = datetime.utcnow().isoformat()
        raw = f"{timestamp}:{self.correlation_counter}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def get_correlation_summary(self) -> Dict:
        """Get summary of correlations"""
        if not self.patterns:
            return {
                'total_patterns': 0,
                'pattern_types': {}
            }
        
        pattern_types = defaultdict(int)
        for pattern in self.patterns:
            pattern_types[pattern.pattern_name] += 1
        
        total_events = sum(len(p.events) for p in self.patterns)
        
        return {
            'total_patterns': len(self.patterns),
            'pattern_types': dict(pattern_types),
            'total_correlated_events': total_events,
            'avg_events_per_pattern': total_events / len(self.patterns),
            'avg_severity': np.mean([p.severity for p in self.patterns]),
            'recent_patterns_24h': len(self.get_recent_patterns(24))
        }


if __name__ == "__main__":
    # Example usage
    engine = EventCorrelationEngine(time_window_seconds=600)
    
    # Create sample events
    now = datetime.utcnow()
    
    # File access events
    for i in range(4):
        event = CorrelationEvent(
            event_id=f"event_{i}",
            event_type=EventType.FILE_ACCESS,
            user_id="user123",
            device_id="device_abc",
            timestamp=now - timedelta(seconds=i*10),
            data={'file_path': f'/data/sensitive_{i}.csv'},
            severity=0.6
        )
        engine.add_event(event)
    
    # Network event
    net_event = CorrelationEvent(
        event_id="net_event_1",
        event_type=EventType.NETWORK_LOG,
        user_id="user123",
        device_id="device_abc",
        timestamp=now,
        data={'destination_ip': '203.0.113.42', 'bytes': 5000000},
        severity=0.7
    )
    engine.add_event(net_event)
    
    # Run correlation
    patterns = engine.correlate()
    
    print(f"Detected {len(patterns)} patterns")
    for pattern in patterns:
        print(f"  - {pattern.pattern_name}: severity={pattern.severity:.2f}, confidence={pattern.confidence:.2f}")
    
    # Summary
    summary = engine.get_correlation_summary()
    print(f"\nSummary: {summary}")
