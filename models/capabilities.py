from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum, auto

class PKICapability(Enum):
    CanPKINITUser = auto()         # Authentication directly (ClientAuth, Smartcard Logon)
    CanSmartcardLogon = auto()     # Authentication directly (Smartcard Logon)
    CanIssueOtherCerts = auto()    # Enrollment Agent (Certificate Request Agent)
    CanSubordinateCA = auto()      # SubCA
    CanWriteDACL = auto()          # Access Control modification
    CanAnyPurposeAuth = auto()     # AnyPurpose EKU
    RequiresLabValidation = auto() # Ambiguous / None of the above

@dataclass
class EvidenceRecord:
    source_principal: str
    template: str
    published: bool
    effective_rights: List[str]
    observed_ekus: List[str]
    observed_flags: List[str]
    issuance_reqs: Dict[str, Any]
    inferred_capabilities: List[str]
    confidence: str # "high", "medium", "requires_lab"
    notes: List[str]

@dataclass(frozen=True)
class AuthenticationConsequence:
    capability: PKICapability
    is_deterministic: bool         # False si requiere Manager Approval o Authorized Signatures (Human-in-the-loop)
    subject_alt_name_enabled: bool # ENROLLEE_SUPPLIES_SUBJECT mapping
    can_target_arbitrary: bool     # Validates SAN rules + Directory requirements
    can_target_privileged: bool    # Validates lack of constraints against DA targeting
    explanations: List[str]
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
