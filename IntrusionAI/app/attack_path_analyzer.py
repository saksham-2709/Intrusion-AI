"""
Attack Path Analysis Module
Graph-based modeling of processes, files, and network connections
Detects suspicious execution chains and privilege escalation
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from enum import Enum
import json

import networkx as nx
import numpy as np

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of graph nodes"""
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    NETWORK_ADDRESS = "network_address"
    REGISTRY = "registry"
    SERVICE = "service"


class EdgeType(Enum):
    """Types of edges (relationships)"""
    EXECUTES = "executes"  # Process executes another process
    ACCESSES = "accesses"  # Process accesses file
    CREATES = "creates"    # Process creates file
    CONNECTS = "connects"  # Process connects to network
    LOADS = "loads"        # Process loads DLL
    WRITES_REGISTRY = "writes_registry"
    STARTS_SERVICE = "starts_service"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class GraphNode:
    """Node in attack path graph"""
    
    def __init__(self, node_id: str, node_type: NodeType, properties: Dict = None):
        self.node_id = node_id
        self.node_type = node_type
        self.properties = properties or {}
        self.risk_score = 0.0
        self.created_at = datetime.utcnow()
    
    def to_dict(self) -> Dict:
        return {
            'node_id': self.node_id,
            'node_type': self.node_type.value,
            'properties': self.properties,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat()
        }


class GraphEdge:
    """Edge in attack path graph"""
    
    def __init__(self, source: str, target: str, edge_type: EdgeType, 
                 weight: float = 1.0, timestamp: datetime = None):
        self.source = source
        self.target = target
        self.edge_type = edge_type
        self.weight = weight
        self.timestamp = timestamp or datetime.utcnow()
        self.evidence = []  # Events supporting this edge
    
    def add_evidence(self, evidence: Dict):
        """Add event evidence for this edge"""
        self.evidence.append(evidence)
    
    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'target': self.target,
            'edge_type': self.edge_type.value,
            'weight': self.weight,
            'timestamp': self.timestamp.isoformat(),
            'evidence_count': len(self.evidence)
        }


class AttackPathAnalyzer:
    """Build and analyze attack graphs"""
    
    def __init__(self):
        # Directed graph for attack paths
        self.graph = nx.DiGraph()
        self.nodes = {}  # node_id -> GraphNode
        self.edges = {}  # (source, target) -> GraphEdge
        
        # Risk propagation settings
        self.suspicious_processes = {
            'cmd.exe', 'powershell.exe', 'whoami.exe', 'ipconfig.exe',
            'net.exe', 'tasklist.exe', 'systeminfo.exe', 'wmic.exe',
            'psexec.exe', 'mimikatz.exe', 'procdump.exe', 'winrar.exe'
        }
        
        self.suspicious_files = {
            '.bat', '.ps1', '.cmd', '.exe', '.dll', '.zip', '.rar'
        }
    
    def add_node(self, node_id: str, node_type: NodeType, 
                properties: Dict = None) -> GraphNode:
        """Add node to graph"""
        if node_id not in self.nodes:
            node = GraphNode(node_id, node_type, properties)
            self.nodes[node_id] = node
            self.graph.add_node(node_id, node_type=node_type.value)
            return node
        return self.nodes[node_id]
    
    def add_edge(self, source: str, target: str, edge_type: EdgeType,
                weight: float = 1.0, evidence: Dict = None) -> GraphEdge:
        """Add edge to graph"""
        # Ensure nodes exist
        if source not in self.nodes:
            self.add_node(source, NodeType.PROCESS)
        if target not in self.nodes:
            self.add_node(target, NodeType.PROCESS)
        
        edge_key = (source, target, edge_type.value)
        
        if edge_key not in self.edges:
            edge = GraphEdge(source, target, edge_type, weight)
            self.edges[edge_key] = edge
            self.graph.add_edge(source, target, 
                               edge_type=edge_type.value, 
                               weight=weight)
        else:
            edge = self.edges[edge_key]
        
        if evidence:
            edge.add_evidence(evidence)
        
        return edge
    
    def record_process_execution(self, parent_process: str,
                                child_process: str,
                                user_id: str,
                                timestamp: datetime = None):
        """Record process execution"""
        self.add_edge(
            parent_process, child_process,
            EdgeType.EXECUTES,
            weight=2.0,  # Higher weight for execution
            evidence={
                'type': 'process_execution',
                'parent': parent_process,
                'child': child_process,
                'user': user_id,
                'timestamp': timestamp or datetime.utcnow()
            }
        )
        
        # Check for suspicious process
        if self._is_suspicious_process(child_process):
            self.nodes[child_process].risk_score = 0.8
    
    def record_file_access(self, process: str, file_path: str,
                          access_type: str,
                          timestamp: datetime = None):
        """Record file access"""
        edge_type = EdgeType.ACCESSES
        if access_type == 'create':
            edge_type = EdgeType.CREATES
        
        self.add_edge(
            process, file_path,
            edge_type,
            weight=1.5,
            evidence={
                'type': 'file_access',
                'access_type': access_type,
                'timestamp': timestamp or datetime.utcnow()
            }
        )
        
        # Check for suspicious file
        if self._is_suspicious_file(file_path):
            self.nodes[file_path].risk_score = 0.7
    
    def record_network_connection(self, process: str, dest_ip: str,
                                 dest_port: int,
                                 timestamp: datetime = None):
        """Record network connection"""
        target_id = f"{dest_ip}:{dest_port}"
        
        self.add_node(target_id, NodeType.NETWORK_ADDRESS, {
            'ip': dest_ip,
            'port': dest_port
        })
        
        self.add_edge(
            process, target_id,
            EdgeType.CONNECTS,
            weight=1.5,
            evidence={
                'type': 'network_connection',
                'destination': dest_ip,
                'port': dest_port,
                'timestamp': timestamp or datetime.utcnow()
            }
        )
    
    def _is_suspicious_process(self, process_name: str) -> bool:
        """Check if process is suspicious"""
        process_lower = process_name.lower()
        return any(sus in process_lower for sus in self.suspicious_processes)
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file extension is suspicious"""
        return any(file_path.endswith(ext) for ext in self.suspicious_files)
    
    def propagate_risk(self):
        """Propagate risk scores through graph"""
        # Initialize
        for node_id, node in self.nodes.items():
            if node.risk_score == 0.0:
                # Check if it's a suspicious node
                if node.node_type == NodeType.PROCESS and self._is_suspicious_process(node_id):
                    node.risk_score = 0.6
                elif node.node_type == NodeType.FILE and self._is_suspicious_file(node_id):
                    node.risk_score = 0.5
        
        # Propagate using PageRank-like algorithm
        # High-risk processes create high-risk paths
        for _ in range(3):  # 3 iterations
            for source, target in self.graph.edges():
                source_node = self.nodes.get(source)
                target_node = self.nodes.get(target)
                
                if source_node and target_node:
                    # Propagate risk from source to target
                    edge_weight = self.graph[source][target].get('weight', 1.0)
                    propagated_risk = source_node.risk_score * 0.7 * edge_weight / 2.0
                    target_node.risk_score = min(
                        target_node.risk_score + propagated_risk,
                        1.0
                    )
    
    def detect_suspicious_paths(self, user_id: str = None, 
                               max_path_length: int = 5) -> List[List[str]]:
        """
        Detect suspicious attack paths
        Returns: List of paths where each node has high risk
        """
        suspicious_paths = []
        
        # Find all nodes with risk_score > 0.5
        high_risk_nodes = [
            node_id for node_id, node in self.nodes.items()
            if node.risk_score > 0.5
        ]
        
        if not high_risk_nodes:
            return suspicious_paths
        
        # Find paths between high-risk nodes
        for start_node in high_risk_nodes:
            try:
                for end_node in high_risk_nodes:
                    if start_node != end_node:
                        # Find all simple paths
                        try:
                            paths = nx.all_simple_paths(
                                self.graph, start_node, end_node,
                                cutoff=max_path_length
                            )
                            for path in paths:
                                avg_risk = np.mean([
                                    self.nodes[n].risk_score for n in path
                                ])
                                if avg_risk > 0.5:
                                    suspicious_paths.append(path)
                        except nx.NetworkXNoPath:
                            pass
            except Exception as e:
                logger.debug(f"Error finding paths from {start_node}: {e}")
        
        return suspicious_paths
    
    def detect_privilege_escalation(self) -> List[Dict]:
        """Detect privilege escalation attempts"""
        escalations = []
        
        # Look for processes that create other processes with higher privileges
        for source, target in self.graph.edges():
            source_node = self.nodes.get(source)
            target_node = self.nodes.get(target)
            
            if source_node and target_node:
                if (source_node.properties.get('privilege_level', 'user') == 'user' and
                    target_node.properties.get('privilege_level', 'user') == 'admin'):
                    
                    escalations.append({
                        'from_process': source,
                        'to_process': target,
                        'from_privilege': 'user',
                        'to_privilege': 'admin',
                        'risk_score': target_node.risk_score
                    })
        
        return escalations
    
    def detect_lateral_movement(self) -> List[Dict]:
        """Detect lateral movement (access to multiple systems)"""
        lateral_movements = []
        
        # Group by user
        user_network_accesses = {}
        
        for edge_id, edge in self.edges.items():
            source, target, _ = edge_id
            
            # Find network connections
            if edge.edge_type == EdgeType.CONNECTS:
                # Get associated user from source process
                for evidence in edge.evidence:
                    user = evidence.get('user')
                    if user:
                        if user not in user_network_accesses:
                            user_network_accesses[user] = []
                        user_network_accesses[user].append(target)
        
        # Detect if user accessing multiple systems
        for user, targets in user_network_accesses.items():
            if len(set(targets)) >= 3:  # Multiple different targets
                lateral_movements.append({
                    'user_id': user,
                    'target_count': len(set(targets)),
                    'targets': list(set(targets)),
                    'risk_score': 0.8
                })
        
        return lateral_movements
    
    def get_attack_tree(self, root_node: str) -> Dict:
        """
        Get attack tree rooted at a node
        Returns: Tree structure with risk scores
        """
        tree = {
            'root': root_node,
            'risk_score': self.nodes.get(root_node, GraphNode('', NodeType.PROCESS)).risk_score,
            'children': []
        }
        
        # BFS to build tree
        visited = set()
        queue = [(root_node, tree)]
        
        while queue:
            current_node, parent_dict = queue.pop(0)
            
            if current_node in visited:
                continue
            visited.add(current_node)
            
            # Get children
            for neighbor in self.graph.successors(current_node):
                neighbor_node = self.nodes.get(neighbor)
                if neighbor_node:
                    child = {
                        'node': neighbor,
                        'risk_score': neighbor_node.risk_score,
                        'children': []
                    }
                    parent_dict['children'].append(child)
                    queue.append((neighbor, child))
        
        return tree
    
    def get_graph_statistics(self) -> Dict:
        """Get graph statistics"""
        return {
            'node_count': len(self.nodes),
            'edge_count': len(self.edges),
            'high_risk_nodes': sum(1 for n in self.nodes.values() if n.risk_score > 0.5),
            'density': nx.density(self.graph) if len(self.nodes) > 0 else 0,
            'avg_degree': sum(dict(self.graph.degree()).values()) / len(self.nodes) if len(self.nodes) > 0 else 0
        }
    
    def get_critical_nodes(self, top_k: int = 10) -> List[Dict]:
        """Get most critical nodes by centrality"""
        # Calculate betweenness centrality
        try:
            centrality = nx.betweenness_centrality(self.graph)
        except:
            centrality = {}
        
        critical = []
        for node_id, cent in sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:top_k]:
            node = self.nodes.get(node_id)
            if node:
                critical.append({
                    'node_id': node_id,
                    'centrality': cent,
                    'risk_score': node.risk_score,
                    'type': node.node_type.value
                })
        
        return critical
    
    def to_dict(self) -> Dict:
        """Serialize graph"""
        return {
            'nodes': {nid: n.to_dict() for nid, n in self.nodes.items()},
            'edges': {str(k): e.to_dict() for k, e in self.edges.items()},
            'statistics': self.get_graph_statistics()
        }


class AttackPathDetector:
    """High-level detector for attack patterns"""
    
    def __init__(self, analyzer: AttackPathAnalyzer):
        self.analyzer = analyzer
        self.detected_patterns = []
    
    def analyze_session(self, user_id: str) -> Dict:
        """Analyze session for attack patterns"""
        detector_results = {
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'findings': []
        }
        
        # Propagate risk
        self.analyzer.propagate_risk()
        
        # Check for suspicious paths
        suspicious_paths = self.analyzer.detect_suspicious_paths(user_id)
        if suspicious_paths:
            detector_results['findings'].append({
                'type': 'suspicious_paths',
                'count': len(suspicious_paths),
                'paths': suspicious_paths[:5]  # Top 5
            })
        
        # Check for privilege escalation
        escalations = self.analyzer.detect_privilege_escalation()
        if escalations:
            detector_results['findings'].append({
                'type': 'privilege_escalation',
                'count': len(escalations),
                'escalations': escalations
            })
        
        # Check for lateral movement
        lateral = self.analyzer.detect_lateral_movement()
        if lateral:
            detector_results['findings'].append({
                'type': 'lateral_movement',
                'count': len(lateral),
                'movements': lateral
            })
        
        # Get critical nodes
        critical = self.analyzer.get_critical_nodes(5)
        if critical:
            detector_results['findings'].append({
                'type': 'critical_nodes',
                'count': len(critical),
                'nodes': critical
            })
        
        # Calculate overall risk
        detector_results['overall_risk'] = self._calculate_overall_risk(detector_results['findings'])
        
        self.detected_patterns.append(detector_results)
        return detector_results
    
    def _calculate_overall_risk(self, findings: List[Dict]) -> float:
        """Calculate overall risk from findings"""
        if not findings:
            return 0.0
        
        risk_scores = []
        for finding in findings:
            if finding['type'] == 'suspicious_paths':
                risk_scores.append(0.9)
            elif finding['type'] == 'privilege_escalation':
                risk_scores.append(0.95)
            elif finding['type'] == 'lateral_movement':
                risk_scores.append(0.85)
            elif finding['type'] == 'critical_nodes':
                risk_scores.append(0.7)
        
        return np.mean(risk_scores) if risk_scores else 0.0


if __name__ == "__main__":
    # Example usage
    analyzer = AttackPathAnalyzer()
    
    # Build graph
    analyzer.record_process_execution('explorer.exe', 'cmd.exe', 'user1')
    analyzer.record_process_execution('cmd.exe', 'powershell.exe', 'user1')
    analyzer.record_file_access('powershell.exe', 'C:\\Windows\\System32\\dumpstate.exe', 'create')
    analyzer.record_network_connection('cmd.exe', '203.0.113.42', 4444)
    
    # Analyze
    detector = AttackPathDetector(analyzer)
    results = detector.analyze_session('user1')
    
    print(json.dumps(results, indent=2))
