"""
SOAR-lite Automated Response Engine
Rule-based automation for threat response
Executes response playbooks based on risk levels
"""

import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of automated response actions"""
    FORCE_LOGOUT = "force_logout"
    BLOCK_ACCESS = "block_access"
    TRIGGER_MFA = "trigger_mfa"
    REVOKE_TOKEN = "revoke_token"
    ISOLATE_DEVICE = "isolate_device"
    TERMINATE_SESSION = "terminate_session"
    NOTIFY_ADMIN = "notify_admin"
    ESCALATE_ALERT = "escalate_alert"
    SNAPSHOT_DEVICE = "snapshot_device"
    DISABLE_ACCOUNT = "disable_account"
    RESTRICT_NETWORK = "restrict_network"
    KILL_PROCESS = "kill_process"


class ActionStatus(Enum):
    """Status of an action"""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Action:
    """Individual response action"""
    action_id: str
    action_type: ActionType
    parameters: Dict
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = None
    executed_at: datetime = None
    error_message: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'action_type': self.action_type.value,
            'parameters': self.parameters,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'error_message': self.error_message
        }


class Playbook:
    """Collection of actions to execute in response to threats"""
    
    def __init__(self, playbook_id: str, name: str, description: str = ""):
        self.playbook_id = playbook_id
        self.name = name
        self.description = description
        self.actions = []
        self.conditions = []
        self.created_at = datetime.utcnow()
    
    def add_action(self, action: Action):
        """Add action to playbook"""
        self.actions.append(action)
    
    def add_condition(self, condition: Callable[[Dict], bool]):
        """Add condition that must be met to execute playbook"""
        self.conditions.append(condition)
    
    def should_execute(self, context: Dict) -> bool:
        """Check if all conditions are met"""
        return all(condition(context) for condition in self.conditions)
    
    def to_dict(self) -> Dict:
        return {
            'playbook_id': self.playbook_id,
            'name': self.name,
            'description': self.description,
            'action_count': len(self.actions),
            'condition_count': len(self.conditions),
            'created_at': self.created_at.isoformat()
        }


class SOAREngine:
    """SOAR-lite automation engine"""
    
    def __init__(self):
        self.playbooks = {}
        self.executed_actions = []
        self.action_handlers = {}
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default action handlers"""
        self.action_handlers[ActionType.FORCE_LOGOUT] = self._handle_force_logout
        self.action_handlers[ActionType.BLOCK_ACCESS] = self._handle_block_access
        self.action_handlers[ActionType.TRIGGER_MFA] = self._handle_trigger_mfa
        self.action_handlers[ActionType.REVOKE_TOKEN] = self._handle_revoke_token
        self.action_handlers[ActionType.ISOLATE_DEVICE] = self._handle_isolate_device
        self.action_handlers[ActionType.NOTIFY_ADMIN] = self._handle_notify_admin
        self.action_handlers[ActionType.ESCALATE_ALERT] = self._handle_escalate_alert
        self.action_handlers[ActionType.DISABLE_ACCOUNT] = self._handle_disable_account
    
    def register_action_handler(self, action_type: ActionType, handler: Callable):
        """Register custom action handler"""
        self.action_handlers[action_type] = handler
    
    def create_playbook(self, playbook_id: str, name: str, 
                       description: str = "") -> Playbook:
        """Create new playbook"""
        playbook = Playbook(playbook_id, name, description)
        self.playbooks[playbook_id] = playbook
        logger.info(f"Created playbook: {name}")
        return playbook
    
    def add_playbook(self, playbook: Playbook):
        """Register playbook"""
        self.playbooks[playbook.playbook_id] = playbook
    
    def execute_playbook(self, playbook_id: str, context: Dict) -> List[Action]:
        """
        Execute playbook
        Returns: List of executed actions
        """
        if playbook_id not in self.playbooks:
            logger.error(f"Playbook {playbook_id} not found")
            return []
        
        playbook = self.playbooks[playbook_id]
        
        # Check conditions
        if not playbook.should_execute(context):
            logger.info(f"Playbook {playbook_id} conditions not met, skipping")
            return []
        
        executed = []
        for action in playbook.actions:
            result = self.execute_action(action, context)
            executed.append(result)
        
        logger.info(f"Executed playbook {playbook_id} with {len(executed)} actions")
        return executed
    
    def execute_action(self, action: Action, context: Dict) -> Action:
        """Execute single action"""
        action.status = ActionStatus.EXECUTING
        
        try:
            handler = self.action_handlers.get(action.action_type)
            
            if not handler:
                logger.warning(f"No handler for action type {action.action_type.value}")
                action.status = ActionStatus.FAILED
                action.error_message = "No handler registered"
            else:
                # Execute handler
                result = handler(action, context)
                
                if result:
                    action.status = ActionStatus.SUCCESS
                    action.executed_at = datetime.utcnow()
                    logger.info(f"Action {action.action_id} executed successfully")
                else:
                    action.status = ActionStatus.FAILED
                    action.error_message = "Handler returned False"
        
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Error executing action {action.action_id}: {e}")
        
        self.executed_actions.append(action)
        return action
    
    # Default action handlers
    def _handle_force_logout(self, action: Action, context: Dict) -> bool:
        """Force user logout"""
        user_id = action.parameters.get('user_id')
        logger.info(f"[SIMULATED] Force logging out user {user_id}")
        # In production: send RPC to terminate all sessions
        return True
    
    def _handle_block_access(self, action: Action, context: Dict) -> bool:
        """Block user access"""
        user_id = action.parameters.get('user_id')
        resource = action.parameters.get('resource', 'all')
        logger.info(f"[SIMULATED] Blocking access to {resource} for user {user_id}")
        # In production: update access control lists
        return True
    
    def _handle_trigger_mfa(self, action: Action, context: Dict) -> bool:
        """Trigger MFA requirement"""
        user_id = action.parameters.get('user_id')
        logger.info(f"[SIMULATED] Requiring MFA for user {user_id}")
        # In production: update user MFA settings
        return True
    
    def _handle_revoke_token(self, action: Action, context: Dict) -> bool:
        """Revoke authentication token"""
        token = action.parameters.get('token')
        logger.info(f"[SIMULATED] Revoking token")
        # In production: revoke token in token store
        return True
    
    def _handle_isolate_device(self, action: Action, context: Dict) -> bool:
        """Isolate device from network"""
        device_id = action.parameters.get('device_id')
        logger.info(f"[SIMULATED] Isolating device {device_id} from network")
        # In production: update network policies
        return True
    
    def _handle_terminate_session(self, action: Action, context: Dict) -> bool:
        """Terminate active session"""
        session_id = action.parameters.get('session_id')
        logger.info(f"[SIMULATED] Terminating session {session_id}")
        # In production: kill session
        return True
    
    def _handle_notify_admin(self, action: Action, context: Dict) -> bool:
        """Notify administrator"""
        message = action.parameters.get('message')
        severity = action.parameters.get('severity', 'HIGH')
        logger.info(f"[NOTIFY] [{severity}] {message}")
        # In production: send email/alert
        return True
    
    def _handle_escalate_alert(self, action: Action, context: Dict) -> bool:
        """Escalate alert to SOC"""
        alert_id = action.parameters.get('alert_id')
        logger.info(f"[ESCALATE] Alert {alert_id} escalated to SOC")
        # In production: create incident ticket
        return True
    
    def _handle_snapshot_device(self, action: Action, context: Dict) -> bool:
        """Create device snapshot for forensics"""
        device_id = action.parameters.get('device_id')
        logger.info(f"[SNAPSHOT] Creating forensic snapshot of device {device_id}")
        # In production: trigger snapshot collection
        return True
    
    def _handle_disable_account(self, action: Action, context: Dict) -> bool:
        """Disable user account"""
        user_id = action.parameters.get('user_id')
        reason = action.parameters.get('reason', 'Security threat detected')
        logger.info(f"[DISABLE] Disabling account {user_id}: {reason}")
        # In production: disable account in directory
        return True
    
    def _handle_restrict_network(self, action: Action, context: Dict) -> bool:
        """Apply network restrictions"""
        user_id = action.parameters.get('user_id')
        restrictions = action.parameters.get('restrictions', {})
        logger.info(f"[RESTRICT] Applying network restrictions to {user_id}: {restrictions}")
        # In production: update firewall rules
        return True
    
    def _handle_kill_process(self, action: Action, context: Dict) -> bool:
        """Kill suspicious process"""
        device_id = action.parameters.get('device_id')
        process_name = action.parameters.get('process_name')
        logger.info(f"[KILL] Killing process {process_name} on device {device_id}")
        # In production: send kill signal to process
        return True
    
    def get_action_history(self, limit: int = 100) -> List[Dict]:
        """Get execution history"""
        return [a.to_dict() for a in self.executed_actions[-limit:]]
    
    def get_actions_by_status(self, status: ActionStatus) -> List[Action]:
        """Get actions by status"""
        return [a for a in self.executed_actions if a.status == status]


class RiskBasedPlaybookSelector:
    """Automatically select appropriate playbooks based on risk level"""
    
    def __init__(self, soar_engine: SOAREngine):
        self.soar_engine = soar_engine
        self.playbook_mappings = {}  # Risk level -> List of playbook IDs
    
    def register_playbook(self, risk_level: str, playbook_id: str):
        """
        Register playbook for risk level
        Args:
            risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            playbook_id: Playbook to execute
        """
        if risk_level not in self.playbook_mappings:
            self.playbook_mappings[risk_level] = []
        
        self.playbook_mappings[risk_level].append(playbook_id)
    
    def select_playbooks(self, risk_level: str) -> List[str]:
        """Get playbooks for risk level"""
        playbooks = self.playbook_mappings.get(risk_level, [])
        
        # Execute parent risk levels too (e.g., CRITICAL includes HIGH)
        levels_to_include = []
        if risk_level == 'CRITICAL':
            levels_to_include = ['CRITICAL', 'HIGH', 'MEDIUM']
        elif risk_level == 'HIGH':
            levels_to_include = ['HIGH', 'MEDIUM']
        elif risk_level == 'MEDIUM':
            levels_to_include = ['MEDIUM']
        
        all_playbooks = []
        for level in levels_to_include:
            all_playbooks.extend(self.playbook_mappings.get(level, []))
        
        return list(set(all_playbooks))  # Remove duplicates
    
    def execute_for_risk_level(self, risk_level: str, context: Dict) -> List[List[Action]]:
        """Execute all playbooks for risk level"""
        playbook_ids = self.select_playbooks(risk_level)
        
        results = []
        for playbook_id in playbook_ids:
            actions = self.soar_engine.execute_playbook(playbook_id, context)
            results.append(actions)
        
        return results


def create_default_playbooks(soar_engine: SOAREngine) -> SOAREngine:
    """Create default response playbooks"""
    
    # Critical Risk Playbook - Maximum response
    critical_playbook = soar_engine.create_playbook(
        'critical_incident',
        'Critical Incident Response',
        'Maximum response for critical threats'
    )
    critical_playbook.add_action(Action(
        'action_1', ActionType.FORCE_LOGOUT,
        {'user_id': '{user_id}'}
    ))
    critical_playbook.add_action(Action(
        'action_2', ActionType.ISOLATE_DEVICE,
        {'device_id': '{device_id}'}
    ))
    critical_playbook.add_action(Action(
        'action_3', ActionType.SNAPSHOT_DEVICE,
        {'device_id': '{device_id}'}
    ))
    critical_playbook.add_action(Action(
        'action_4', ActionType.NOTIFY_ADMIN,
        {
            'message': 'CRITICAL: User {user_id} on device {device_id} - Immediate action required',
            'severity': 'CRITICAL'
        }
    ))
    critical_playbook.add_action(Action(
        'action_5', ActionType.ESCALATE_ALERT,
        {'alert_id': '{alert_id}'}
    ))
    
    # High Risk Playbook
    high_playbook = soar_engine.create_playbook(
        'high_incident',
        'High Priority Incident Response',
        'Enhanced monitoring and access controls'
    )
    high_playbook.add_action(Action(
        'action_1', ActionType.TRIGGER_MFA,
        {'user_id': '{user_id}'}
    ))
    high_playbook.add_action(Action(
        'action_2', ActionType.RESTRICT_NETWORK,
        {
            'user_id': '{user_id}',
            'restrictions': {'external_access': False}
        }
    ))
    high_playbook.add_action(Action(
        'action_3', ActionType.NOTIFY_ADMIN,
        {
            'message': 'HIGH: User {user_id} showing suspicious activity',
            'severity': 'HIGH'
        }
    ))
    
    # Medium Risk Playbook
    medium_playbook = soar_engine.create_playbook(
        'medium_incident',
        'Medium Priority Incident Response',
        'Enhanced monitoring'
    )
    medium_playbook.add_action(Action(
        'action_1', ActionType.NOTIFY_ADMIN,
        {
            'message': 'MEDIUM: User {user_id} activity requires review',
            'severity': 'MEDIUM'
        }
    ))
    
    return soar_engine


if __name__ == "__main__":
    # Example usage
    engine = SOAREngine()
    
    # Create playbooks
    create_default_playbooks(engine)
    
    # Create selector
    selector = RiskBasedPlaybookSelector(engine)
    selector.register_playbook('CRITICAL', 'critical_incident')
    selector.register_playbook('HIGH', 'high_incident')
    selector.register_playbook('MEDIUM', 'medium_incident')
    
    # Simulate execution
    context = {
        'user_id': 'john.doe',
        'device_id': 'laptop_001',
        'alert_id': 'alert_123',
        'risk_level': 'CRITICAL'
    }
    
    results = selector.execute_for_risk_level('CRITICAL', context)
    
    print(f"Executed {len(results)} playbooks")
    for playbook_actions in results:
        for action in playbook_actions:
            print(f"  - {action.action_type.value}: {action.status.value}")
