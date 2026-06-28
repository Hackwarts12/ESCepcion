from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum, auto
from models.capabilities import PKICapability
from models.severity import IdentityOutcome, IdentitySeverity

class AttackEdgeType(Enum):
    ENROLL = auto()
    AUTOENROLL = auto()
    TEMPLATE_WRITE = auto()
    EA_ISSUE = auto()
    SUBCA_ISSUE = auto()

@dataclass
class AttackEdge:
    source_principal: str      # e.g. "Domain Users"
    edge_type: AttackEdgeType
    template_name: str
    capability: PKICapability
    outcome: IdentityOutcome
    explanations: List[str]

@dataclass
class AttackPath:
    start_principal: str
    edges: List[AttackEdge] = field(default_factory=list)
    max_severity: Optional[IdentitySeverity] = None
    description: str = ""
    is_deterministic: bool = True
    confidence: str = "unknown"
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.max_severity is None:
            self.max_severity = self._compute_max_severity()
        if not self.description:
            self.description = self._compute_description()
        if self.edges:
            self.confidence = self._compute_confidence()
            if not self.reasons:
                self.reasons = self._compute_reasons()

    def add_edge(self, edge: AttackEdge):
        self.edges.append(edge)
        self.max_severity = self._compute_max_severity()
        if not self.description or self.description == self._compute_description(from_edges=[]):
            self.description = self._compute_description()
        self.confidence = self._compute_confidence()
        if not self.reasons:
            self.reasons = self._compute_reasons()

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def severity(self) -> int:
        return int(self.max_severity.value) if self.max_severity else 0

    def _compute_max_severity(self) -> Optional[IdentitySeverity]:
        if not self.edges:
            return None
        severities = [e.outcome.severity for e in self.edges if getattr(e, "outcome", None) and getattr(e.outcome, "severity", None)]
        return max(severities) if severities else None

    def _compute_confidence(self) -> str:
        if not self.edges:
            return "unknown"
        outcome = self.edges[-1].outcome
        evidence = getattr(outcome, "evidence", None) or {}
        if isinstance(evidence, dict):
            return str(evidence.get("confidence", "unknown") or "unknown")
        return "unknown"

    def _compute_reasons(self) -> List[str]:
        if not self.edges:
            return []
        outcome = self.edges[-1].outcome
        evidence = getattr(outcome, "evidence", None) or {}
        if isinstance(evidence, dict):
            sr = evidence.get("severity_reasons", [])
            return list(sr) if isinstance(sr, list) else []
        return []

    def _compute_description(self, from_edges: Optional[List[AttackEdge]] = None) -> str:
        edges = self.edges if from_edges is None else from_edges
        if not edges:
            return f"{self.start_principal}"
        last = edges[-1]
        target = getattr(last.outcome, "target_identity", "Unknown") if getattr(last, "outcome", None) else "Unknown"
        return f"{self.start_principal} -> {target} ({len(edges)} hops)"
