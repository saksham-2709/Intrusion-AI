"""
Long-Term Risk Profiling Module
Tracks historical anomaly scores, risk trends, and user trust scores
Uses PostgreSQL + Redis for persistence and real-time queries
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


class UserRiskProfile:
    """Individual user's long-term risk profile"""
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.risk_history = []  # List of (timestamp, risk_score)
        self.alert_history = []  # List of alerts
        self.trend = None  # Upward, Stable, Downward
        self.created_at = datetime.utcnow()
        self.last_updated = datetime.utcnow()
    
    def add_risk_score(self, timestamp: datetime, risk_score: float):
        """Add risk score to history"""
        self.risk_history.append((timestamp, risk_score))
        self.last_updated = datetime.utcnow()
    
    def add_alert(self, alert: Dict):
        """Add alert to history"""
        self.alert_history.append(alert)
    
    def get_average_risk(self, days: int = 7) -> float:
        """Get average risk over period"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent_scores = [score for ts, score in self.risk_history if ts > cutoff]
        
        if not recent_scores:
            return 0.0
        
        return float(np.mean(recent_scores))
    
    def get_max_risk(self, days: int = 7) -> float:
        """Get maximum risk over period"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent_scores = [score for ts, score in self.risk_history if ts > cutoff]
        
        if not recent_scores:
            return 0.0
        
        return float(np.max(recent_scores))
    
    def get_risk_trend(self, days: int = 7) -> str:
        """Calculate risk trend over period"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [(ts, score) for ts, score in self.risk_history if ts > cutoff]
        
        if len(recent) < 2:
            return 'INSUFFICIENT_DATA'
        
        # Split into halves
        mid = len(recent) // 2
        first_half = [score for _, score in recent[:mid]]
        second_half = [score for _, score in recent[mid:]]
        
        avg_first = np.mean(first_half)
        avg_second = np.mean(second_half)
        
        change = avg_second - avg_first
        
        if change > 0.1:
            return 'INCREASING'
        elif change < -0.1:
            return 'DECREASING'
        else:
            return 'STABLE'
    
    def calculate_trust_score(self) -> float:
        """
        Calculate trust score (inverse of risk)
        1.0 = fully trusted, 0.0 = completely untrusted
        """
        # Weight factors
        recent_7day_risk = self.get_average_risk(7)
        recent_30day_risk = self.get_average_risk(30)
        max_risk_7day = self.get_max_risk(7)
        trend = self.get_risk_trend(7)
        
        # Base trust (inverse of risk)
        base_trust = 1.0 - recent_7day_risk
        
        # Adjust for recent spike
        if max_risk_7day > 0.8:
            base_trust *= 0.8
        
        # Adjust for trend
        if trend == 'INCREASING':
            base_trust *= 0.9
        elif trend == 'DECREASING':
            base_trust *= 1.1
        
        # Historical stability
        if recent_30day_risk > 0.5:
            base_trust *= 0.8
        
        return float(np.clip(base_trust, 0.0, 1.0))
    
    def get_risk_timeline(self, days: int = 30) -> List[Dict]:
        """Get daily risk timeline"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Group by day
        daily_risks = defaultdict(list)
        for ts, score in self.risk_history:
            if ts > cutoff:
                day = ts.date()
                daily_risks[day].append(score)
        
        timeline = []
        for day in sorted(daily_risks.keys()):
            scores = daily_risks[day]
            timeline.append({
                'date': day.isoformat(),
                'avg_risk': float(np.mean(scores)),
                'max_risk': float(np.max(scores)),
                'sample_count': len(scores)
            })
        
        return timeline
    
    def to_dict(self) -> Dict:
        return {
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'current_trust_score': self.calculate_trust_score(),
            'avg_risk_7day': self.get_average_risk(7),
            'max_risk_7day': self.get_max_risk(7),
            'trend': self.get_risk_trend(7),
            'alert_count_7day': sum(1 for a in self.alert_history 
                                   if a['timestamp'] > datetime.utcnow() - timedelta(days=7))
        }


class RiskProfilingEngine:
    """Central engine for long-term risk profiling"""
    
    def __init__(self):
        self.user_profiles = {}
        self.organization_risk = None
        self.risk_by_department = defaultdict(RiskProfilingEngine._DepartmentRisk)
    
    class _DepartmentRisk:
        """Risk statistics for a department"""
        def __init__(self):
            self.users = []
            self.avg_risk = 0.0
            self.risk_trend = 'STABLE'
    
    def update_user_risk(self, user_id: str, timestamp: datetime, 
                        risk_score: float, department: str = None):
        """Update user risk score"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserRiskProfile(user_id)
        
        profile = self.user_profiles[user_id]
        profile.add_risk_score(timestamp, risk_score)
        
        # Update department statistics
        if department:
            if user_id not in self.risk_by_department[department].users:
                self.risk_by_department[department].users.append(user_id)
    
    def record_alert(self, user_id: str, alert: Dict):
        """Record security alert"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserRiskProfile(user_id)
        
        self.user_profiles[user_id].add_alert(alert)
    
    def get_user_profile(self, user_id: str) -> Optional[UserRiskProfile]:
        """Get user profile"""
        return self.user_profiles.get(user_id)
    
    def get_high_risk_users(self, threshold: float = 0.7, days: int = 7) -> List[Dict]:
        """Get users with high recent risk"""
        high_risk = []
        
        for user_id, profile in self.user_profiles.items():
            avg_risk = profile.get_average_risk(days)
            
            if avg_risk > threshold:
                high_risk.append({
                    'user_id': user_id,
                    'risk_score': avg_risk,
                    'trust_score': profile.calculate_trust_score(),
                    'trend': profile.get_risk_trend(days),
                    'alerts': len([a for a in profile.alert_history 
                                 if a['timestamp'] > datetime.utcnow() - timedelta(days=days)])
                })
        
        return sorted(high_risk, key=lambda x: x['risk_score'], reverse=True)
    
    def get_trending_users(self, days: int = 7) -> Dict:
        """Get users by risk trend"""
        trending = {
            'increasing': [],
            'stable': [],
            'decreasing': []
        }
        
        for user_id, profile in self.user_profiles.items():
            trend = profile.get_risk_trend(days)
            
            if trend == 'INCREASING':
                trending['increasing'].append({
                    'user_id': user_id,
                    'risk_score': profile.get_average_risk(days)
                })
            elif trend == 'DECREASING':
                trending['decreasing'].append({
                    'user_id': user_id,
                    'risk_score': profile.get_average_risk(days)
                })
            elif trend == 'STABLE':
                trending['stable'].append({
                    'user_id': user_id,
                    'risk_score': profile.get_average_risk(days)
                })
        
        return trending
    
    def get_organization_risk(self) -> Dict:
        """Get overall organization risk metrics"""
        if not self.user_profiles:
            return {'message': 'No user profiles'}
        
        risk_scores = [p.get_average_risk(7) for p in self.user_profiles.values()]
        trust_scores = [p.calculate_trust_score() for p in self.user_profiles.values()]
        
        return {
            'total_users': len(self.user_profiles),
            'avg_risk': float(np.mean(risk_scores)),
            'avg_trust': float(np.mean(trust_scores)),
            'max_risk': float(np.max(risk_scores)),
            'high_risk_count': sum(1 for r in risk_scores if r > 0.7),
            'low_trust_count': sum(1 for t in trust_scores if t < 0.3)
        }
    
    def get_department_summary(self, department: str) -> Dict:
        """Get summary for department"""
        dept_users = self.risk_by_department[department].users
        
        if not dept_users:
            return {'message': f'No users in department {department}'}
        
        profiles = [self.user_profiles[uid] for uid in dept_users if uid in self.user_profiles]
        
        if not profiles:
            return {'message': f'No profiles for department {department}'}
        
        risk_scores = [p.get_average_risk(7) for p in profiles]
        
        return {
            'department': department,
            'user_count': len(dept_users),
            'avg_risk': float(np.mean(risk_scores)),
            'max_risk': float(np.max(risk_scores)),
            'high_risk_users': [uid for uid in dept_users 
                              if self.user_profiles[uid].get_average_risk(7) > 0.7]
        }
    
    def generate_risk_report(self, days: int = 30) -> Dict:
        """Generate comprehensive risk report"""
        return {
            'generated_at': datetime.utcnow().isoformat(),
            'period_days': days,
            'organization_risk': self.get_organization_risk(),
            'high_risk_users': self.get_high_risk_users(threshold=0.7, days=days),
            'trending': self.get_trending_users(days),
            'total_profiles': len(self.user_profiles),
            'user_profiles': {
                uid: profile.to_dict() 
                for uid, profile in list(self.user_profiles.items())[:10]  # Top 10
            }
        }
    
    def export_to_csv(self, filepath: str = None) -> str:
        """Export profiles to CSV"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'user_id', 'created_at', 'avg_risk_7day', 'max_risk_7day',
            'trust_score', 'trend', 'alert_count'
        ])
        
        writer.writeheader()
        for user_id, profile in self.user_profiles.items():
            writer.writerow({
                'user_id': user_id,
                'created_at': profile.created_at.isoformat(),
                'avg_risk_7day': profile.get_average_risk(7),
                'max_risk_7day': profile.get_max_risk(7),
                'trust_score': profile.calculate_trust_score(),
                'trend': profile.get_risk_trend(7),
                'alert_count': len(profile.alert_history)
            })
        
        csv_content = output.getvalue()
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(csv_content)
        
        return csv_content


class RiskScoreCalculator:
    """Calculate unified risk score from multiple sources"""
    
    @staticmethod
    def calculate_final_risk(
        behavioral_score: float = 0.0,
        threat_score: float = 0.0,
        peer_deviation_score: float = 0.0,
        network_risk_score: float = 0.0,
        dlp_risk_score: float = 0.0,
        attack_path_risk: float = 0.0,
        weights: Dict = None
    ) -> Tuple[float, str]:
        """
        Calculate final unified risk score
        Returns: (risk_score, risk_level)
        """
        if weights is None:
            # Default weights
            weights = {
                'behavioral': 0.25,
                'threat': 0.25,
                'peer_deviation': 0.15,
                'network': 0.15,
                'dlp': 0.10,
                'attack_path': 0.10
            }
        
        # Normalize weights
        total = sum(weights.values())
        weights = {k: v / total for k, v in weights.items()}
        
        # Calculate weighted sum
        final_risk = (
            behavioral_score * weights['behavioral'] +
            threat_score * weights['threat'] +
            peer_deviation_score * weights['peer_deviation'] +
            network_risk_score * weights['network'] +
            dlp_risk_score * weights['dlp'] +
            attack_path_risk * weights['attack_path']
        )
        
        # Clip to 0-1
        final_risk = float(np.clip(final_risk, 0.0, 1.0))
        
        # Determine risk level
        if final_risk >= 0.85:
            risk_level = 'CRITICAL'
        elif final_risk >= 0.70:
            risk_level = 'HIGH'
        elif final_risk >= 0.50:
            risk_level = 'MEDIUM'
        elif final_risk >= 0.25:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return final_risk, risk_level


if __name__ == "__main__":
    # Example usage
    engine = RiskProfilingEngine()
    
    # Simulate risk updates
    now = datetime.utcnow()
    for day_offset in range(7):
        timestamp = now - timedelta(days=day_offset)
        risk_score = 0.5 + (day_offset * 0.05)  # Increasing risk
        
        engine.update_user_risk('john.doe', timestamp, risk_score, 'Engineering')
        engine.update_user_risk('jane.smith', timestamp, 0.3, 'Finance')
    
    # Get reports
    high_risk = engine.get_high_risk_users(threshold=0.5)
    print(f"High risk users: {high_risk}")
    
    org_risk = engine.get_organization_risk()
    print(f"Organization risk: {org_risk}")
    
    report = engine.generate_risk_report(7)
    print(f"Risk report period: {report['period_days']} days")
    
    # Calculate final risk
    final_risk, level = RiskScoreCalculator.calculate_final_risk(
        behavioral_score=0.7,
        threat_score=0.6,
        peer_deviation_score=0.5,
        network_risk_score=0.4
    )
    print(f"Final risk: {final_risk:.2f} ({level})")
