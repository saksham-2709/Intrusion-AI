"""
Peer Group Analysis Module
Cluster users based on role/behavior using KMeans or DBSCAN
Compare user behavior against peer group baseline
Detect role deviation anomalies
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import joblib

logger = logging.getLogger(__name__)


class UserProfile:
    """Individual user behavior profile"""
    
    def __init__(self, user_id: str, role: str = None, department: str = None):
        self.user_id = user_id
        self.role = role
        self.department = department
        self.features = {}
        self.sample_count = 0
        self.last_updated = datetime.utcnow()
    
    def update(self, features: Dict[str, float]):
        """Update profile with new features (running average)"""
        self.sample_count += 1
        
        for key, value in features.items():
            if key not in self.features:
                self.features[key] = value
            else:
                # Running average
                old_avg = self.features[key]
                self.features[key] = (old_avg * (self.sample_count - 1) + value) / self.sample_count
        
        self.last_updated = datetime.utcnow()
    
    def get_vector(self, feature_names: List[str]) -> np.ndarray:
        """Get feature vector for clustering"""
        return np.array([self.features.get(name, 0.0) for name in feature_names])
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            'user_id': self.user_id,
            'role': self.role,
            'department': self.department,
            'features': self.features,
            'sample_count': self.sample_count,
            'last_updated': self.last_updated.isoformat()
        }


class BaselineMetrics:
    """Calculate and store peer group baseline metrics"""
    
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.data = []
        self.mean = {}
        self.stddev = {}
        self.percentile_95 = {}
        self.is_fitted = False
    
    def add_sample(self, vector: np.ndarray):
        """Add sample to baseline"""
        self.data.append(vector)
    
    def fit(self):
        """Calculate baseline statistics"""
        if len(self.data) == 0:
            raise ValueError("No data to fit")
        
        data_array = np.array(self.data)
        
        for i, name in enumerate(self.feature_names):
            values = data_array[:, i]
            self.mean[name] = float(np.mean(values))
            self.stddev[name] = float(np.std(values))
            self.percentile_95[name] = float(np.percentile(values, 95))
        
        self.is_fitted = True
    
    def get_deviation_score(self, user_vector: np.ndarray) -> float:
        """
        Calculate deviation from baseline (0-1)
        Higher = more deviation
        """
        if not self.is_fitted:
            raise ValueError("Baseline not fitted")
        
        deviations = []
        
        for i, name in enumerate(self.feature_names):
            if self.stddev[name] > 0:
                z_score = abs((user_vector[i] - self.mean[name]) / self.stddev[name])
                # Sigmoid normalization to 0-1
                deviation = 1.0 / (1.0 + np.exp(-z_score))
            else:
                deviation = 0.0 if user_vector[i] == self.mean[name] else 1.0
            
            deviations.append(deviation)
        
        return float(np.mean(deviations))
    
    def get_anomaly_features(self, user_vector: np.ndarray) -> Dict[str, float]:
        """Get detailed anomaly scores per feature"""
        anomalies = {}
        
        for i, name in enumerate(self.feature_names):
            if self.stddev[name] > 0:
                z_score = abs((user_vector[i] - self.mean[name]) / self.stddev[name])
                anomalies[name] = min(z_score / 3.0, 1.0)  # Normalize by 3-sigma
            else:
                anomalies[name] = 0.0 if user_vector[i] == self.mean[name] else 1.0
        
        return anomalies
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            'feature_names': self.feature_names,
            'mean': self.mean,
            'stddev': self.stddev,
            'percentile_95': self.percentile_95
        }


class PeerGroup:
    """Cluster of users with similar behavior"""
    
    def __init__(self, group_id: str, group_name: str, role: str = None, 
                 department: str = None, cluster_label: int = None):
        self.group_id = group_id
        self.group_name = group_name
        self.role = role
        self.department = department
        self.cluster_label = cluster_label
        self.members = set()
        self.baseline = None
        self.created_at = datetime.utcnow()
    
    def add_member(self, user_id: str):
        """Add user to group"""
        self.members.add(user_id)
    
    def remove_member(self, user_id: str):
        """Remove user from group"""
        self.members.discard(user_id)
    
    def get_member_count(self) -> int:
        """Get number of members"""
        return len(self.members)
    
    def set_baseline(self, baseline: BaselineMetrics):
        """Set baseline for this group"""
        self.baseline = baseline
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            'group_id': self.group_id,
            'group_name': self.group_name,
            'role': self.role,
            'department': self.department,
            'cluster_label': self.cluster_label,
            'member_count': self.get_member_count(),
            'members': list(self.members),
            'created_at': self.created_at.isoformat(),
            'baseline': self.baseline.to_dict() if self.baseline else None
        }


class UserClustering:
    """User clustering engine using KMeans or DBSCAN"""
    
    def __init__(self, method: str = 'kmeans', n_clusters: int = 5):
        """
        Initialize clustering engine
        Args:
            method: 'kmeans' or 'dbscan'
            n_clusters: Number of clusters (for kmeans)
        """
        if method not in ['kmeans', 'dbscan']:
            raise ValueError("Method must be 'kmeans' or 'dbscan'")
        
        self.method = method
        self.n_clusters = n_clusters
        self.clusterer = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_fitted = False
    
    def fit(self, X: pd.DataFrame) -> np.ndarray:
        """
        Fit clustering model
        Returns: cluster labels
        """
        self.feature_names = X.columns.tolist()
        X_scaled = self.scaler.fit_transform(X)
        
        if self.method == 'kmeans':
            self.clusterer = KMeans(
                n_clusters=self.n_clusters,
                random_state=42,
                n_init=10
            )
            labels = self.clusterer.fit_predict(X_scaled)
        else:  # dbscan
            self.clusterer = DBSCAN(eps=0.5, min_samples=5)
            labels = self.clusterer.fit_predict(X_scaled)
        
        self.is_fitted = True
        return labels
    
    def predict_cluster(self, X: pd.DataFrame) -> np.ndarray:
        """Predict cluster labels for new data"""
        if not self.is_fitted:
            raise ValueError("Clustering not fitted")
        
        X_scaled = self.scaler.transform(X)
        
        if self.method == 'kmeans':
            return self.clusterer.predict(X_scaled)
        else:
            # DBSCAN doesn't support predict, use nearest neighbor approximation
            return self._predict_dbscan(X_scaled)
    
    def _predict_dbscan(self, X_scaled: np.ndarray) -> np.ndarray:
        """Approximate prediction for DBSCAN using nearest neighbors"""
        from sklearn.neighbors import NearestNeighbors
        
        neighbors = NearestNeighbors(n_neighbors=1)
        neighbors.fit(self.clusterer.components_)
        
        distances, indices = neighbors.kneighbors(X_scaled)
        return self.clusterer.labels_[indices].flatten()
    
    def get_silhouette_score(self, X: pd.DataFrame) -> float:
        """Calculate silhouette score (higher is better)"""
        if not self.is_fitted:
            raise ValueError("Clustering not fitted")
        
        X_scaled = self.scaler.transform(X)
        labels = self.predict_cluster(X)
        
        if len(np.unique(labels)) > 1:
            return silhouette_score(X_scaled, labels)
        return 0.0
    
    def save(self, path: str):
        """Save clustering model"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(self.clusterer, path / 'clusterer.pkl')
        joblib.dump(self.scaler, path / 'scaler.pkl')
        joblib.dump(self.feature_names, path / 'features.pkl')
        joblib.dump(self.method, path / 'method.pkl')
    
    @classmethod
    def load(cls, path: str) -> 'UserClustering':
        """Load clustering model"""
        path = Path(path)
        
        clusterer = joblib.load(path / 'clusterer.pkl')
        scaler = joblib.load(path / 'scaler.pkl')
        features = joblib.load(path / 'features.pkl')
        method = joblib.load(path / 'method.pkl')
        
        clustering = cls(method=method)
        clustering.clusterer = clusterer
        clustering.scaler = scaler
        clustering.feature_names = features
        clustering.is_fitted = True
        
        return clustering


class PeerGroupAnalyzer:
    """Unified peer group analysis system"""
    
    def __init__(self, clustering_method: str = 'kmeans', n_clusters: int = 5):
        self.clustering = UserClustering(clustering_method, n_clusters)
        self.user_profiles = {}
        self.peer_groups = {}
        self.feature_names = None
        self.clustering_performed = False
    
    def add_user_data(self, user_id: str, features: Dict[str, float], 
                     role: str = None, department: str = None):
        """Add or update user behavioral data"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(user_id, role, department)
        
        self.user_profiles[user_id].update(features)
        
        # Track feature names
        if self.feature_names is None:
            self.feature_names = list(features.keys())
    
    def perform_clustering(self) -> Dict:
        """Perform clustering on user profiles"""
        if not self.user_profiles:
            raise ValueError("No user profiles to cluster")
        
        # Build feature matrix
        user_ids = sorted(self.user_profiles.keys())
        feature_matrix = []
        
        for user_id in user_ids:
            vector = self.user_profiles[user_id].get_vector(self.feature_names)
            feature_matrix.append(vector)
        
        X = pd.DataFrame(feature_matrix, columns=self.feature_names)
        
        # Cluster
        labels = self.clustering.fit(X)
        
        # Create peer groups
        self.peer_groups = {}
        unique_labels = np.unique(labels)
        
        for cluster_label in unique_labels:
            group_id = f"pg_{cluster_label}_{int(datetime.utcnow().timestamp())}"
            group_name = f"Peer Group {cluster_label}"
            
            group = PeerGroup(
                group_id=group_id,
                group_name=group_name,
                cluster_label=cluster_label
            )
            
            # Add members
            for i, uid in enumerate(user_ids):
                if labels[i] == cluster_label:
                    group.add_member(uid)
            
            # Calculate baseline
            group_indices = np.where(labels == cluster_label)[0]
            group_features = X.iloc[group_indices]
            
            baseline = BaselineMetrics(self.feature_names)
            for _, row in group_features.iterrows():
                baseline.add_sample(row.values)
            baseline.fit()
            
            group.set_baseline(baseline)
            self.peer_groups[group_id] = group
        
        self.clustering_performed = True
        
        return {
            'cluster_count': len(self.peer_groups),
            'silhouette_score': self.clustering.get_silhouette_score(X),
            'peer_groups': {gid: g.to_dict() for gid, g in self.peer_groups.items()}
        }
    
    def get_user_peer_group(self, user_id: str) -> Optional[PeerGroup]:
        """Find which peer group a user belongs to"""
        for group in self.peer_groups.values():
            if user_id in group.members:
                return group
        return None
    
    def calculate_peer_deviation(self, user_id: str, 
                                 features: Dict[str, float]) -> Dict:
        """
        Calculate how much user deviates from peer baseline
        Returns: {
            'peer_group': PeerGroup info,
            'deviation_score': 0-1,
            'anomaly_details': features with high deviation
        }
        """
        if not self.clustering_performed:
            raise ValueError("Clustering not performed yet")
        
        peer_group = self.get_user_peer_group(user_id)
        if not peer_group:
            return {
                'error': f'User {user_id} not in any peer group'
            }
        
        # Get feature vector
        if user_id in self.user_profiles:
            user_vector = self.user_profiles[user_id].get_vector(self.feature_names)
        else:
            user_vector = np.array([features.get(name, 0.0) for name in self.feature_names])
        
        # Calculate deviation
        deviation_score = peer_group.baseline.get_deviation_score(user_vector)
        anomalies = peer_group.baseline.get_anomaly_features(user_vector)
        
        # Find top anomalies
        top_anomalies = sorted(
            [(name, score) for name, score in anomalies.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'peer_group': peer_group.to_dict(),
            'deviation_score': deviation_score,
            'anomaly_details': dict(top_anomalies),
            'is_deviant': deviation_score > 0.6  # Threshold for deviation
        }
    
    def get_peer_statistics(self, group_id: str) -> Dict:
        """Get statistics for a peer group"""
        if group_id not in self.peer_groups:
            return {'error': f'Group {group_id} not found'}
        
        group = self.peer_groups[group_id]
        
        return {
            'group_id': group_id,
            'group_name': group.group_name,
            'member_count': group.get_member_count(),
            'members': list(group.members),
            'baseline_metrics': group.baseline.to_dict() if group.baseline else None
        }
    
    def recommend_peer_groups(self, user_id: str, n_recommendations: int = 3) -> List[Dict]:
        """Recommend peer groups for a user (e.g., for transitioning roles)"""
        if user_id not in self.user_profiles:
            return []
        
        user_profile = self.user_profiles[user_id]
        user_vector = user_profile.get_vector(self.feature_names)
        
        # Calculate similarity to each group baseline
        similarities = []
        
        for group_id, group in self.peer_groups.items():
            if group.baseline:
                # Cosine similarity
                baseline_vector = np.array([
                    group.baseline.mean.get(name, 0.0)
                    for name in self.feature_names
                ])
                
                similarity = np.dot(user_vector, baseline_vector) / (
                    np.linalg.norm(user_vector) * np.linalg.norm(baseline_vector) + 1e-8
                )
                
                similarities.append({
                    'group_id': group_id,
                    'group_name': group.group_name,
                    'similarity_score': similarity,
                    'member_count': group.get_member_count()
                })
        
        # Sort by similarity
        similarities.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        return similarities[:n_recommendations]
    
    def save(self, path: str):
        """Save analyzer state"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save clustering model
        self.clustering.save(str(path / 'clustering'))
        
        # Save profiles
        profiles = {
            uid: profile.to_dict()
            for uid, profile in self.user_profiles.items()
        }
        joblib.dump(profiles, path / 'profiles.pkl')
        
        # Save peer groups
        groups = {
            gid: group.to_dict()
            for gid, group in self.peer_groups.items()
        }
        joblib.dump(groups, path / 'groups.pkl')
        joblib.dump(self.feature_names, path / 'features.pkl')
        joblib.dump(self.clustering_performed, path / 'clustering_done.pkl')
    
    @classmethod
    def load(cls, path: str) -> 'PeerGroupAnalyzer':
        """Load analyzer state"""
        path = Path(path)
        
        analyzer = cls()
        analyzer.clustering = UserClustering.load(str(path / 'clustering'))
        
        profiles_dict = joblib.load(path / 'profiles.pkl')
        for user_id, profile_dict in profiles_dict.items():
            profile = UserProfile(user_id, profile_dict['role'], profile_dict['department'])
            profile.features = profile_dict['features']
            profile.sample_count = profile_dict['sample_count']
            analyzer.user_profiles[user_id] = profile
        
        analyzer.feature_names = joblib.load(path / 'features.pkl')
        analyzer.clustering_performed = joblib.load(path / 'clustering_done.pkl')
        
        logger.info(f"Loaded peer group analyzer with {len(analyzer.user_profiles)} profiles")
        return analyzer


if __name__ == "__main__":
    # Example usage
    analyzer = PeerGroupAnalyzer(clustering_method='kmeans', n_clusters=3)
    
    # Add sample users
    for user_id in ['user1', 'user2', 'user3', 'user4', 'user5']:
        features = {
            'keystroke_speed': np.random.normal(60, 10),
            'mouse_speed': np.random.normal(100, 20),
            'app_diversity': np.random.normal(5, 1),
            'working_hours_deviation': np.random.normal(0.2, 0.1)
        }
        analyzer.add_user_data(user_id, features, role='engineer')
    
    # Perform clustering
    result = analyzer.perform_clustering()
    print(f"Clustering result: {result}")
    
    # Check peer deviation
    deviation = analyzer.calculate_peer_deviation('user1', {
        'keystroke_speed': 100,
        'mouse_speed': 200,
        'app_diversity': 3,
        'working_hours_deviation': 0.8
    })
    print(f"Deviation: {deviation}")
