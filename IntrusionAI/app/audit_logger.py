"""
Compliance & Audit Logging Module
Structured logging for compliance requirements
ELK Stack ready logging with exportable reports
"""

import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum
from io import StringIO
import csv

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Log severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    AUDIT = "AUDIT"  # Specific to compliance


class AuditAction(Enum):
    """Types of auditable actions"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    DATA_ACCESSED = "data_accessed"
    DATA_MODIFIED = "data_modified"
    DATA_DELETED = "data_deleted"
    CONFIG_CHANGED = "config_changed"
    ALERT_GENERATED = "alert_generated"
    ALERT_ACKNOWLEDGED = "alert_acknowledged"
    RESPONSE_ACTION_EXECUTED = "response_action_executed"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    THREAT_DETECTED = "threat_detected"
    EXCEPTION_RAISED = "exception_raised"


class AuditLogEntry:
    """Single audit log entry"""
    
    def __init__(self, 
                 timestamp: datetime,
                 action: AuditAction,
                 user_id: str = None,
                 resource_type: str = None,
                 resource_id: str = None,
                 details: Dict = None,
                 severity: Severity = Severity.INFO,
                 source: str = "IntrusionAI"):
        self.timestamp = timestamp
        self.action = action
        self.user_id = user_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.details = details or {}
        self.severity = severity
        self.source = source
        self.event_id = self._generate_event_id()
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import hashlib
        raw = f"{self.timestamp.isoformat()}{self.user_id}{self.action.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'action': self.action.value,
            'user_id': self.user_id,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'severity': self.severity.value,
            'source': self.source,
            'details': self.details
        }
    
    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(self.to_dict())
    
    def __repr__(self) -> str:
        return f"AuditLogEntry({self.action.value}, user={self.user_id}, ts={self.timestamp.isoformat()})"


class AuditLogger:
    """Central audit logger with compliance features"""
    
    def __init__(self, max_entries: int = 10000):
        self.entries = []
        self.max_entries = max_entries
        self.created_at = datetime.utcnow()
    
    def log(self,
            action: AuditAction,
            user_id: str = None,
            resource_type: str = None,
            resource_id: str = None,
            details: Dict = None,
            severity: Severity = Severity.INFO) -> AuditLogEntry:
        """Log an auditable action"""
        entry = AuditLogEntry(
            timestamp=datetime.utcnow(),
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            severity=severity
        )
        
        self.entries.append(entry)
        
        # Keep only recent entries
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]
        
        # Also log to Python logger
        logger.info(f"AUDIT: {entry.action.value} | user={user_id} | resource={resource_type}/{resource_id}")
        
        return entry
    
    def log_user_action(self, user_id: str, action: AuditAction, 
                       details: Dict = None, severity: Severity = Severity.INFO):
        """Log user action"""
        return self.log(action, user_id=user_id, details=details, severity=severity)
    
    def log_data_access(self, user_id: str, resource_path: str, 
                       access_type: str = "read"):
        """Log data access"""
        return self.log(
            AuditAction.DATA_ACCESSED,
            user_id=user_id,
            resource_type="file",
            resource_id=resource_path,
            details={'access_type': access_type}
        )
    
    def log_policy_violation(self, user_id: str, violation_type: str, 
                            details: Dict = None):
        """Log policy violation"""
        return self.log(
            AuditAction.POLICY_VIOLATION,
            user_id=user_id,
            details={**(details or {}), 'violation_type': violation_type},
            severity=Severity.WARNING
        )
    
    def log_anomaly(self, user_id: str, anomaly_type: str, 
                   risk_score: float, details: Dict = None):
        """Log detected anomaly"""
        return self.log(
            AuditAction.ANOMALY_DETECTED,
            user_id=user_id,
            details={
                **(details or {}),
                'anomaly_type': anomaly_type,
                'risk_score': risk_score
            },
            severity=Severity.WARNING if risk_score > 0.7 else Severity.INFO
        )
    
    def log_threat(self, threat_type: str, threat_source: str, 
                  severity: Severity = Severity.CRITICAL, details: Dict = None):
        """Log detected threat"""
        return self.log(
            AuditAction.THREAT_DETECTED,
            resource_type=threat_type,
            resource_id=threat_source,
            details=details,
            severity=severity
        )
    
    def log_response_action(self, user_id: str, action_type: str, 
                           action_id: str, status: str):
        """Log automated response action"""
        return self.log(
            AuditAction.RESPONSE_ACTION_EXECUTED,
            user_id=user_id,
            resource_type=action_type,
            resource_id=action_id,
            details={'status': status},
            severity=Severity.AUDIT
        )
    
    def search(self,
              user_id: str = None,
              action: AuditAction = None,
              severity: Severity = None,
              start_time: datetime = None,
              end_time: datetime = None) -> List[AuditLogEntry]:
        """Search audit log with filters"""
        results = self.entries
        
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        
        if action:
            results = [e for e in results if e.action == action]
        
        if severity:
            results = [e for e in results if e.severity == severity]
        
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]
        
        return results
    
    def get_user_activity(self, user_id: str) -> List[Dict]:
        """Get all activity for a user"""
        entries = self.search(user_id=user_id)
        return [e.to_dict() for e in entries]
    
    def get_critical_events(self) -> List[AuditLogEntry]:
        """Get all critical/error severity events"""
        return [e for e in self.entries if e.severity in [Severity.CRITICAL, Severity.ERROR]]
    
    def get_violation_summary(self, days: int = 30) -> Dict:
        """Summary of policy violations"""
        cutoff_time = datetime.utcnow()
        
        violations = self.search(
            action=AuditAction.POLICY_VIOLATION,
            start_time=cutoff_time - __import__('datetime').timedelta(days=days)
        )
        
        # Group by user
        by_user = {}
        for violation in violations:
            if violation.user_id not in by_user:
                by_user[violation.user_id] = []
            by_user[violation.user_id].append(violation)
        
        return {
            'period_days': days,
            'total_violations': len(violations),
            'users_with_violations': len(by_user),
            'violations_by_user': {
                uid: len(v) for uid, v in by_user.items()
            }
        }
    
    def export_to_json(self, filepath: str = None) -> str:
        """Export logs to JSON format"""
        data = {
            'exported_at': datetime.utcnow().isoformat(),
            'entry_count': len(self.entries),
            'entries': [e.to_dict() for e in self.entries]
        }
        
        json_str = json.dumps(data, indent=2)
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_str)
        
        return json_str
    
    def export_to_csv(self, filepath: str = None) -> str:
        """Export logs to CSV format"""
        output = StringIO()
        
        if not self.entries:
            return ""
        
        fieldnames = ['event_id', 'timestamp', 'action', 'user_id', 'resource_type', 
                     'resource_id', 'severity', 'source']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for entry in self.entries:
            row = {
                'event_id': entry.event_id,
                'timestamp': entry.timestamp.isoformat(),
                'action': entry.action.value,
                'user_id': entry.user_id or '',
                'resource_type': entry.resource_type or '',
                'resource_id': entry.resource_id or '',
                'severity': entry.severity.value,
                'source': entry.source
            }
            writer.writerow(row)
        
        csv_str = output.getvalue()
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(csv_str)
        
        return csv_str
    
    def get_statistics(self) -> Dict:
        """Get audit log statistics"""
        if not self.entries:
            return {
                'total_entries': 0,
                'created_at': self.created_at.isoformat()
            }
        
        # Action distribution
        action_counts = {}
        for entry in self.entries:
            key = entry.action.value
            action_counts[key] = action_counts.get(key, 0) + 1
        
        # Severity distribution
        severity_counts = {}
        for entry in self.entries:
            key = entry.severity.value
            severity_counts[key] = severity_counts.get(key, 0) + 1
        
        # User activity
        user_counts = {}
        for entry in self.entries:
            if entry.user_id:
                key = entry.user_id
                user_counts[key] = user_counts.get(key, 0) + 1
        
        return {
            'total_entries': len(self.entries),
            'created_at': self.created_at.isoformat(),
            'first_entry': self.entries[0].timestamp.isoformat() if self.entries else None,
            'last_entry': self.entries[-1].timestamp.isoformat() if self.entries else None,
            'action_distribution': action_counts,
            'severity_distribution': severity_counts,
            'unique_users': len(user_counts),
            'most_active_users': sorted(
                [(u, c) for u, c in user_counts.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }


class ComplianceReporter:
    """Generate compliance reports"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def generate_activity_report(self, user_id: str, days: int = 30) -> Dict:
        """Generate user activity report"""
        from datetime import timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        
        activity = self.audit_logger.search(user_id=user_id, start_time=cutoff_time)
        
        return {
            'user_id': user_id,
            'report_period': f"Last {days} days",
            'generated_at': datetime.utcnow().isoformat(),
            'activity_count': len(activity),
            'actions': [e.to_dict() for e in activity],
            'action_summary': self._summarize_actions(activity)
        }
    
    def generate_incident_report(self, incident_id: str, details: Dict = None) -> Dict:
        """Generate incident report"""
        return {
            'incident_id': incident_id,
            'generated_at': datetime.utcnow().isoformat(),
            'details': details or {},
            'related_logs': self.audit_logger.search(
                severity=Severity.CRITICAL
            )[-10:]  # Last 10 critical events
        }
    
    def generate_compliance_report(self, days: int = 30) -> Dict:
        """Generate overall compliance report"""
        from datetime import timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        
        # Get recent logs
        recent_logs = [e for e in self.audit_logger.entries if e.timestamp >= cutoff_time]
        
        # Count violations
        violations = [e for e in recent_logs if e.action == AuditAction.POLICY_VIOLATION]
        
        # Count anomalies
        anomalies = [e for e in recent_logs if e.action == AuditAction.ANOMALY_DETECTED]
        
        # Count threats
        threats = [e for e in recent_logs if e.action == AuditAction.THREAT_DETECTED]
        
        return {
            'report_period': f"Last {days} days",
            'generated_at': datetime.utcnow().isoformat(),
            'total_events': len(recent_logs),
            'policy_violations': len(violations),
            'anomalies_detected': len(anomalies),
            'threats_detected': len(threats),
            'critical_events': len([e for e in recent_logs if e.severity == Severity.CRITICAL]),
            'audit_log_stats': self.audit_logger.get_statistics()
        }
    
    def _summarize_actions(self, entries: List[AuditLogEntry]) -> Dict:
        """Summarize actions in entries"""
        summary = {}
        for entry in entries:
            key = entry.action.value
            summary[key] = summary.get(key, 0) + 1
        return summary


if __name__ == "__main__":
    # Example usage
    logger_instance = AuditLogger()
    
    # Log various actions
    logger_instance.log_user_action('john.doe', AuditAction.USER_LOGIN)
    logger_instance.log_data_access('john.doe', '/data/report.xlsx')
    logger_instance.log_anomaly('john.doe', 'unusual_hours', 0.75)
    logger_instance.log_threat('malware', '192.168.1.1', Severity.CRITICAL)
    
    # Get statistics
    stats = logger_instance.get_statistics()
    print(f"Audit log stats: {stats}")
    
    # Generate reports
    reporter = ComplianceReporter(logger_instance)
    compliance = reporter.generate_compliance_report(1)
    print(f"Compliance report: {compliance}")
