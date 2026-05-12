"""
IntrusionAI - Comprehensive Integration Orchestrator
Ties together all modules for unified UEBA + behavioral intelligence system
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import json

from app.ml_pipeline import MLPipeline
from app.threat_intelligence import ThreatIntelligenceManager, MockThreatIntelProvider
from app.peer_group_analysis import PeerGroupAnalyzer
from app.correlation_engine import EventCorrelationEngine, CorrelationEvent, EventType
from app.soar_engine import SOAREngine, RiskBasedPlaybookSelector, create_default_playbooks
from app.attack_path_analyzer import AttackPathAnalyzer, AttackPathDetector
from app.risk_profiling import RiskProfilingEngine, RiskScoreCalculator
from app.audit_logger import AuditLogger, AuditAction, Severity
from app.network_dlp_monitor import NetworkBehaviorMonitor, DataLossPreventionMonitor
from app.honeypot_detector import HoneypotIntegrationManager

logger = logging.getLogger(__name__)


class IntrusionAIOrchestrator:
    """Main orchestrator coordinating all modules"""
    
    def __init__(self, config: Dict = None):
        """
        Initialize IntrusionAI system
        Args:
            config: System configuration
        """
        self.config = config or self._get_default_config()
        
        # Initialize all modules
        logger.info("Initializing IntrusionAI components...")
        
        # ML & Anomaly Detection
        self.ml_pipeline = MLPipeline(
            use_isolation_forest=True,
            use_lof=True,
            use_autoencoder=False
        )
        
        # Threat Intelligence
        threat_provider = MockThreatIntelProvider()
        self.threat_intel = ThreatIntelligenceManager(
            provider=threat_provider,
            use_cache=True
        )
        
        # Peer Group Analysis
        self.peer_analyzer = PeerGroupAnalyzer(clustering_method='kmeans', n_clusters=5)
        
        # Event Correlation
        self.correlator = EventCorrelationEngine(time_window_seconds=300)
        
        # SOAR Automation
        self.soar = SOAREngine()
        create_default_playbooks(self.soar)
        self.playbook_selector = RiskBasedPlaybookSelector(self.soar)
        self._setup_playbook_mappings()
        
        # Attack Path Analysis
        self.attack_analyzer = AttackPathAnalyzer()
        self.attack_detector = AttackPathDetector(self.attack_analyzer)
        
        # Risk Profiling
        self.risk_profiler = RiskProfilingEngine()
        
        # Audit Logging
        self.audit_logger = AuditLogger()
        
        # Network & DLP Monitoring
        self.network_monitor = NetworkBehaviorMonitor()
        self.dlp_monitor = DataLossPreventionMonitor()
        
        # Honeypot Integration
        self.honeypot_manager = HoneypotIntegrationManager()
        
        logger.info("IntrusionAI initialized successfully")
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'ml_enabled': True,
            'threat_intel_enabled': True,
            'peer_analysis_enabled': True,
            'correlation_enabled': True,
            'attack_path_enabled': True,
            'dlp_enabled': True,
            'honeypot_enabled': True,
            'auto_response_enabled': True
        }
    
    def _setup_playbook_mappings(self):
        """Setup risk-based playbook mappings"""
        self.playbook_selector.register_playbook('CRITICAL', 'critical_incident')
        self.playbook_selector.register_playbook('HIGH', 'high_incident')
        self.playbook_selector.register_playbook('MEDIUM', 'medium_incident')
    
    def process_user_event(self,
                          user_id: str,
                          device_id: str,
                          features: Dict,
                          metadata: Dict = None) -> Dict:
        """
        Process a user activity event through full pipeline
        
        Returns:
            {
                'risk_score': final 0-1 risk score,
                'risk_level': 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW',
                'findings': list of findings,
                'actions': recommended/executed actions,
                'timestamp': analysis timestamp
            }
        """
        self.audit_logger.log(
            AuditAction.ANOMALY_DETECTED,
            user_id=user_id,
            details={'device_id': device_id}
        )
        
        findings = []
        
        # 1. ML Anomaly Detection
        ml_result = None
        if self.config['ml_enabled']:
            ml_result = self._run_ml_detection(features)
            if ml_result['is_anomalous']:
                findings.append({
                    'type': 'behavioral_anomaly',
                    'score': ml_result['anomaly_score'],
                    'details': ml_result
                })
        
        # 2. Threat Intelligence
        threat_score = 0.0
        if self.config['threat_intel_enabled'] and 'ip_address' in features:
            threat_score = self.threat_intel.get_threat_score(
                features['ip_address'],
                device_id
            )
            if threat_score > 0.5:
                findings.append({
                    'type': 'threat_intelligence',
                    'score': threat_score,
                    'ip': features['ip_address']
                })
        
        # 3. Peer Group Analysis
        peer_deviation = 0.0
        if self.config['peer_analysis_enabled']:
            try:
                peer_result = self.peer_analyzer.calculate_peer_deviation(user_id, features)
                peer_deviation = peer_result.get('deviation_score', 0.0)
                if peer_result.get('is_deviant'):
                    findings.append({
                        'type': 'peer_group_deviation',
                        'score': peer_deviation,
                        'details': peer_result
                    })
            except:
                logger.warn("Peer analysis failed")
        
        # 4. Network Monitoring
        network_risk = 0.0
        if self.config['dlp_enabled'] and 'network_flow' in features:
            flow_result = self.network_monitor.add_flow(features['network_flow'])
            if flow_result['is_anomalous']:
                network_risk = flow_result['risk_score']
                findings.append({
                    'type': 'network_anomaly',
                    'score': network_risk,
                    'details': flow_result
                })
        
        # 5. DLP Monitoring
        dlp_risk = 0.0
        if self.config['dlp_enabled'] and 'file_access' in features:
            dlp_result = self.dlp_monitor.log_file_access(
                user_id, device_id,
                features['file_access'].get('path', ''),
                features['file_access'].get('type', 'read'),
                features['file_access'].get('size', 0)
            )
            if dlp_result['is_anomalous']:
                dlp_risk = dlp_result['risk_score']
                findings.append({
                    'type': 'dlp_violation',
                    'score': dlp_risk,
                    'details': dlp_result
                })
        
        # 6. Honeypot Detection
        honeypot_risk = 0.0
        if self.config['honeypot_enabled'] and 'resource_path' in features:
            honeypot_result = self.honeypot_manager.check_resource_access(
                user_id, device_id,
                features['resource_path']
            )
            if honeypot_result['is_honeypot']:
                honeypot_risk = 1.0  # Maximum risk
                findings.append({
                    'type': 'honeypot_triggered',
                    'score': 1.0,
                    'alert': honeypot_result.get('alert')
                })
        
        # 7. Calculate Final Risk Score
        final_risk, risk_level = RiskScoreCalculator.calculate_final_risk(
            behavioral_score=ml_result['anomaly_score'] if ml_result else 0.0,
            threat_score=threat_score,
            peer_deviation_score=peer_deviation,
            network_risk_score=network_risk,
            dlp_risk_score=dlp_risk,
            attack_path_risk=0.0  # Calculate separately
        )
        
        # 8. Update Risk Profile
        self.risk_profiler.update_user_risk(
            user_id, datetime.utcnow(), final_risk
        )
        
        # 9. SOAR Response
        actions = []
        if self.config['auto_response_enabled'] and risk_level in ['CRITICAL', 'HIGH']:
            actions = self._execute_response(user_id, device_id, risk_level, findings)
        
        return {
            'user_id': user_id,
            'device_id': device_id,
            'timestamp': datetime.utcnow().isoformat(),
            'risk_score': final_risk,
            'risk_level': risk_level,
            'findings': findings,
            'actions': actions,
            'component_scores': {
                'behavioral': ml_result['anomaly_score'] if ml_result else 0.0,
                'threat_intelligence': threat_score,
                'peer_deviation': peer_deviation,
                'network': network_risk,
                'dlp': dlp_risk,
                'honeypot': honeypot_risk
            }
        }
    
    def _run_ml_detection(self, features: Dict) -> Dict:
        """Run ML anomaly detection"""
        try:
            import pandas as pd
            
            # Convert features to DataFrame if not already
            if isinstance(features, dict):
                features_df = pd.DataFrame([features])
            else:
                features_df = features
            
            result = self.ml_pipeline.predict(features_df)
            
            return {
                'is_anomalous': result['is_anomaly'][0],
                'anomaly_score': result['anomaly_score'][0],
                'confidence': result['confidence'][0],
                'individual_scores': {
                    k: v[0] for k, v in result['individual_scores'].items()
                }
            }
        except Exception as e:
            logger.error(f"ML detection failed: {e}")
            return {'is_anomalous': False, 'anomaly_score': 0.0, 'confidence': 0.0}
    
    def _execute_response(self, user_id: str, device_id: str, 
                         risk_level: str, findings: List[Dict]) -> List[Dict]:
        """Execute automated response"""
        context = {
            'user_id': user_id,
            'device_id': device_id,
            'alert_id': f"alert_{datetime.utcnow().timestamp()}",
            'risk_level': risk_level,
            'findings_count': len(findings)
        }
        
        results = self.playbook_selector.execute_for_risk_level(risk_level, context)
        
        # Flatten results
        actions = []
        for playbook_actions in results:
            for action in playbook_actions:
                actions.append(action.to_dict())
        
        # Log response actions
        for action in actions:
            self.audit_logger.log(
                AuditAction.RESPONSE_ACTION_EXECUTED,
                user_id=user_id,
                resource_type=action['action_type'],
                resource_id=action['action_id'],
                details={'status': action['status']}
            )
        
        return actions
    
    def get_user_dashboard(self, user_id: str) -> Dict:
        """Get comprehensive dashboard for user"""
        profile = self.risk_profiler.get_user_profile(user_id)
        
        if not profile:
            return {'user_id': user_id, 'message': 'No profile data'}
        
        return {
            'user_id': user_id,
            'risk_profile': profile.to_dict(),
            'timeline': profile.get_risk_timeline(30),
            'honeypot_interactions': len(self.honeypot_manager.detector.get_user_interactions(user_id)),
            'dlp_violations': len(self.dlp_monitor.get_dlp_violations(user_id, 24))
        }
    
    def get_organization_summary(self) -> Dict:
        """Get organization-wide summary"""
        return {
            'organization_risk': self.risk_profiler.get_organization_risk(),
            'high_risk_users': self.risk_profiler.get_high_risk_users(0.7, 7),
            'honeypot_summary': self.honeypot_manager.detector.get_honeypot_statistics(),
            'audit_stats': self.audit_logger.get_statistics(),
            'threat_intel_stats': self.threat_intel.get_statistics()
        }
    
    def health_check(self) -> Dict:
        """Check system health"""
        return {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'modules': {
                'ml_pipeline': 'ready',
                'threat_intel': 'ready',
                'peer_analyzer': 'ready' if self.peer_analyzer.user_profiles else 'no_data',
                'correlator': 'ready',
                'soar': 'ready',
                'attack_analyzer': 'ready',
                'risk_profiler': 'ready',
                'audit_logger': 'ready',
                'network_monitor': 'ready',
                'dlp_monitor': 'ready',
                'honeypot': f"{len(self.honeypot_manager.detector.honeypots)} honeypots active"
            }
        }


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize orchestrator
    orchestrator = IntrusionAIOrchestrator()
    
    # Health check
    health = orchestrator.health_check()
    print(f"\nSystem Health: {health['status']}")
    
    # Simulate an event
    test_event = {
        'keystroke_speed': 65.5,
        'mouse_speed': 150.2,
        'app_diversity': 4,
        'working_hours_deviation': 0.2,
        'ip_address': '192.168.1.100',
        'network_flow': None  # Will be populated if needed
    }
    
    print("\nProcessing test event...")
    result = orchestrator.process_user_event(
        'test_user', 'test_device', test_event
    )
    
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Score: {result['risk_score']:.2f}")
    print(f"Findings: {len(result['findings'])}")
    
    # Get organization summary
    print("\nOrganization Summary:")
    summary = orchestrator.get_organization_summary()
    print(f"  Honeypots: {summary['honeypot_summary']['total_honeypots']}")
