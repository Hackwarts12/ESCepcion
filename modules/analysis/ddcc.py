from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

from models.capabilities import PKICapability
from models.context import DirectoryContext
from models.severity import IdentitySeverity
from modules.graph.models import AttackEdge, AttackPath, AttackEdgeType
from modules.graph.attack_graph import IdentityAttackGraph
from modules.inference.consequence_engine import infer_template_capabilities
from modules.inference.severity_evaluator import evaluate_severity

@dataclass
class DDCCEvaluationSummary:
    sources_used: List[str] = field(default_factory=list)
    total_templates_evaluated: int = 0
    published_templates_count: int = 0
    templates_with_effective_enroll_count: int = 0
    templates_with_low_trust_intersection_count: int = 0
    discarded_not_published: int = 0
    discarded_no_enroll_principals: int = 0
    discarded_no_low_trust_intersection: int = 0
    discarded_manager_approval: int = 0
    discarded_authorized_signatures: int = 0
    discarded_flag_restrictions: int = 0 # e.g. requires lab validation
    total_edges_generated: int = 0
    deterministic_edges_created: int = 0
    risk_edges_created: int = 0
    total_paths_attempted: int = 0

@dataclass
class NearMissPath:
    template_name: str
    published: bool
    effective_enroll_principals: List[str]
    low_trust_intersection: bool
    friction_factors: List[str]
    severity: str

@dataclass
class DomainCompromiseReport:
    is_compromisable: bool
    deterministic_critical_paths: List[AttackPath] = field(default_factory=list)
    non_deterministic_risk_paths: List[AttackPath] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    evaluation_summary: DDCCEvaluationSummary = field(default_factory=DDCCEvaluationSummary)
    near_miss_paths: List[NearMissPath] = field(default_factory=list)
    near_misses: List[NearMissPath] = field(default_factory=list)
    confidence_level: str = "UNKNOWN"
    root_cause_analysis: List[str] = field(default_factory=list)
    # TAREA 3: Expose in-memory graphs so serializers can dump nodes/edges
    deterministic_graph: Optional[IdentityAttackGraph] = field(default=None)
    risk_graph: Optional[IdentityAttackGraph] = field(default=None)

    def __post_init__(self):
        if self.near_miss_paths and not self.near_misses:
            self.near_misses = self.near_miss_paths
        elif self.near_misses and not self.near_miss_paths:
            self.near_miss_paths = self.near_misses


DDCCReport = DomainCompromiseReport

# Define low-privileged/highly-populated groups to detect systemic escalation
LOW_TRUST_PRINCIPALS = {
    "Domain Users", 
    "Authenticated Users", 
    "Everyone", 
    "Computers",
    "Domain Computers"
}

def is_domain_deterministically_compromisable(
    templates: List[dict],
    target_principals_override: Set[str] = None,
    max_depth: int = 6,
    dir_context: DirectoryContext = None
) -> DomainCompromiseReport:
    """
    Orquesta la creación del grafo, la inferencia de capacidades y 
    la búsqueda de caminos hacia L3+. Genera métricas extendidas de telemetría.
    """
    if dir_context is None:
        dir_context = DirectoryContext()
        
    deterministic_graph = IdentityAttackGraph()
    risk_graph = IdentityAttackGraph()
    evidence = []
    
    start_nodes = target_principals_override if target_principals_override else LOW_TRUST_PRINCIPALS
    
    summary = DDCCEvaluationSummary(sources_used=list(start_nodes))
    summary.total_templates_evaluated = len(templates)
    near_miss_candidates = []
    
    for tpl in templates:
        name = tpl.get("name", "UnknownTemplate")
        principals_with_enroll = tpl.get("effective_enroll_principals", [])
        
        if not tpl.get("is_published", False):
            summary.discarded_not_published += 1
            continue

        summary.published_templates_count += 1
            
        if not principals_with_enroll:
            summary.discarded_no_enroll_principals += 1
            continue

        summary.templates_with_effective_enroll_count += 1
            
        # Low Trust Intersection Check
        low_trust_intersection = any(p in start_nodes for p in principals_with_enroll)
        if not low_trust_intersection:
            summary.discarded_no_low_trust_intersection += 1
            # We don't continue yet because it might be a hop 2 template, 
            # but we record it for near misses if the template itself is highly vulnerable.
        else:
            summary.templates_with_low_trust_intersection_count += 1
            
        consequences = infer_template_capabilities(tpl)
        has_critical_capability = False
        friction_factors = []
        if tpl.get("requires_manager_approval", False):
            friction_factors.append("Manager Approval")
            summary.discarded_manager_approval += 1
        if tpl.get("requires_agent_signature", False):
            friction_factors.append("Authorized Signatures")
            summary.discarded_authorized_signatures += 1
            
        for cq in consequences:
            if cq.capability == PKICapability.RequiresLabValidation:
                summary.discarded_flag_restrictions += 1
                continue
                
            for source_principal in principals_with_enroll:
                outcome = evaluate_severity(cq, original_target_identity="Unknown/Arbitrary Target", dir_context=dir_context)
                
                if outcome.severity in (IdentitySeverity.L3_PRIVILEGED_AUTH, IdentitySeverity.L4_IDENTITY_MINTING, IdentitySeverity.L5_AUTH_AUTHORITY):
                    has_critical_capability = True
                
                # Para MVP asumimos Enroll si está en efectivos
                edge = AttackEdge(
                    source_principal=source_principal,
                    edge_type=AttackEdgeType.ENROLL,
                    template_name=name,
                    capability=cq.capability,
                    outcome=outcome,
                    explanations=cq.explanations
                )
                
                # Split graphs strictly based on determinism AND high confidence
                is_pure_deterministic = cq.is_deterministic and cq.raw_evidence.get('confidence') != 'requires_lab_validation'
                
                if is_pure_deterministic:
                    summary.total_edges_generated += 1
                    summary.deterministic_edges_created += 1
                    deterministic_graph.add_edge(edge)
                else:
                    summary.risk_edges_created += 1
                    risk_graph.add_edge(edge)
                    
        # Collect near misses
        if has_critical_capability and (friction_factors or not low_trust_intersection):
            near_miss_candidates.append(NearMissPath(
                template_name=name,
                published=True,
                effective_enroll_principals=principals_with_enroll,
                low_trust_intersection=low_trust_intersection,
                friction_factors=friction_factors,
                severity="High/Medium Contextual"
            ))
            
    summary.total_paths_attempted = (len(deterministic_graph.nodes) * 2) + (len(risk_graph.nodes) * 2)  # Proxy stat
                
    start_nodes = target_principals_override if target_principals_override else LOW_TRUST_PRINCIPALS
    
    det_starts = [start for start in start_nodes if start in deterministic_graph.nodes]
    risk_starts = [start for start in start_nodes if start in risk_graph.nodes]
    
    det_critical_paths = deterministic_graph.find_paths_to_severity(det_starts, min_severity=IdentitySeverity.L3_PRIVILEGED_AUTH, max_depth=max_depth)
    risk_paths = risk_graph.find_paths_to_severity(risk_starts, min_severity=IdentitySeverity.L3_PRIVILEGED_AUTH, max_depth=max_depth)
    
    if det_critical_paths:
        evidence.append(f"Domain is COMPROMISABLE! Found {len(det_critical_paths)} deterministic escalation paths from low-trust groups.")
        for path in det_critical_paths:
            evidence.append(f"Deterministic Path: {path.description}")
    else:
        evidence.append("Domain does not appear deterministically compromisable from standard low-trust groups via AD CS alone based on current mappings.")

    if risk_paths:
        evidence.append(f"Found {len(risk_paths)} elevated Risk Paths that require Manager Approval or Signatures (Human-in-the-loop).")

    
    # Confidence Level Heuristic
    confidence_level = "HIGH"
    if summary.total_templates_evaluated == 0:
        confidence_level = "LOW"
    elif summary.discarded_not_published > (summary.total_templates_evaluated * 0.8):
        confidence_level = "MEDIUM" # Most templates aren't published, maybe missing data
        
    root_cause = []
    if not det_critical_paths:
        if summary.discarded_no_low_trust_intersection > 0 and summary.total_edges_generated == 0:
            root_cause.append("Enrollment permissions are heavily restricted to Tier 0/1 administrative groups. Low-trust initial access cannot interact with critical templates.")
        if summary.discarded_manager_approval > 0 or summary.discarded_authorized_signatures > 0:
            root_cause.append("Human-in-the-loop friction (Manager Approval or Authorized Signatures) successfully prevents deterministic remote exploitation.")
        if summary.discarded_flag_restrictions > 0:
            root_cause.append("Template logic uses strict, unexploitable Application Policies or unknown EKUs that degrade capabilities confidently.")
        if not root_cause:
            root_cause.append("Standard identity hygiene correctly mapped: No L3+ authorization elevation possible from the defined low-trust entrypoints.")

    report = DomainCompromiseReport(
        is_compromisable=len(det_critical_paths) > 0,
        deterministic_critical_paths=det_critical_paths,
        non_deterministic_risk_paths=risk_paths,
        evidence=evidence,
        evaluation_summary=summary,
        near_miss_paths=near_miss_candidates[:5],
        confidence_level=confidence_level,
        root_cause_analysis=root_cause,
        # TAREA 3: Expose graphs for PKI graph serialization
        deterministic_graph=deterministic_graph,
        risk_graph=risk_graph,
    )

    return report
