from collections import defaultdict
from typing import List, Set, Dict

from models.severity import IdentitySeverity
from modules.graph.models import AttackEdge, AttackPath

class IdentityAttackGraph:
    def __init__(self):
        # Maps source principal to a list of edges they can take
        self._adj_list: Dict[str, List[AttackEdge]] = defaultdict(list)
        # To avoid loops
        self.nodes: Set[str] = set()
        
    def add_edge(self, edge: AttackEdge):
        """Adds a path from source identity directly to target."""
        self._adj_list[edge.source_principal].append(edge)
        self.nodes.add(edge.source_principal)
        if edge.outcome and edge.outcome.target_identity:
            self.nodes.add(edge.outcome.target_identity)
            
    def _find_paths(
        self, 
        current_principal: str, 
        min_severity: IdentitySeverity,
        visited_principals: Set[str],
        visited_templates: Set[str],
        current_path: List[AttackEdge],
        current_depth: int,
        max_depth: int = 6
    ) -> List[AttackPath]:
        """DFS con poda de profundidad y protección de loops para identificar cadenas lógicas."""
        paths = []
        
        if current_depth >= max_depth:
            return paths
        
        for edge in self._adj_list[current_principal]:
            # AVOID TEMPLATE LOOPS (don't enroll the same template twice in a chain)
            if edge.template_name in visited_templates:
                continue
                
            full_edges = current_path + [edge]
            
            # Check if we hit interesting severities
            if edge.outcome.severity.value >= min_severity.value:
                desc_steps = []
                for step_edge in full_edges:
                    etype = step_edge.edge_type.name if hasattr(step_edge, "edge_type") else "ENROLL"
                    desc_steps.append(f"[{step_edge.source_principal}] --({etype})--> [{step_edge.template_name}] => [{step_edge.outcome.target_identity}] ({step_edge.outcome.severity.name})")
                    
                paths.append(
                    AttackPath(
                        edges=full_edges,
                        max_severity=edge.outcome.severity,
                        description=" | ".join(desc_steps)
                    )
                )
                
            # Identity chaining validation
            next_principal = edge.outcome.target_identity
            
            # If the next identity is known in our graph and we haven't visited it yet
            if next_principal and next_principal not in visited_principals and next_principal in self._adj_list:
                visited_principals.add(next_principal)
                visited_templates.add(edge.template_name)
                
                paths.extend(
                    self._find_paths(
                        next_principal, 
                        min_severity, 
                        visited_principals,
                        visited_templates,
                        full_edges,
                        current_depth + 1,
                        max_depth
                    )
                )
                
                visited_principals.remove(next_principal)
                visited_templates.remove(edge.template_name)
                
        return paths

    def find_paths_to_severity(self, start_principals: Set[str], min_severity: IdentitySeverity, max_depth: int = 6) -> List[AttackPath]:
        """
        Busca todos los caminos lógicos respetando el max_depth.
        Retorna los paths deduplicados y ordenados por Impacto Descendente, Longitud Ascendente.
        """
        all_paths: List[AttackPath] = []
        
        for start_node in start_principals:
            if start_node in self._adj_list:
                visited_principals = set([start_node])
                visited_templates = set()
                found = self._find_paths(start_node, min_severity, visited_principals, visited_templates, [], 0, max_depth)
                all_paths.extend(found)
                
        # Deduplication
        unique_paths = {}
        for p in all_paths:
            if p.description not in unique_paths:
                unique_paths[p.description] = p
                
        paths_list = list(unique_paths.values())
        
        # Sort Top Chains: Max Severity First, Shortest Path First
        paths_list.sort(key=lambda p: (-p.max_severity.value, len(p.edges)))
        
        return paths_list
