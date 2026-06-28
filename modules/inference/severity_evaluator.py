from typing import List, Dict, Any
from models.capabilities import AuthenticationConsequence, PKICapability
from models.severity import IdentityOutcome, IdentitySeverity
from models.context import DirectoryContext

def evaluate_severity(consequence: AuthenticationConsequence, original_target_identity: str, dir_context: DirectoryContext = None) -> IdentityOutcome:
    """
    Determina la severidad L1-L5 con reglas conservadoras y estrictas.
    Retorna un IdentityOutcome expandido con confidence y reasons.
    """
    severity = IdentitySeverity.L0_NONE
    target_identity = original_target_identity
    confidence = consequence.raw_evidence.get('confidence', 'medium')
    reasons = []
    
    cap = consequence.capability

    # 1. Self Auth Check
    if (cap == PKICapability.CanPKINITUser or cap == PKICapability.CanSmartcardLogon) and not consequence.can_target_arbitrary:
        severity = IdentitySeverity.L1_SELF_AUTH
        target_identity = "Self"
        reasons.append("Authentication allowed but targeting is restricted to self.")
        
    # 2. Arbitrary User / Privileged User target
    if (cap == PKICapability.CanPKINITUser or cap == PKICapability.CanSmartcardLogon) and consequence.can_target_arbitrary:
        
        # Validar con el contexto si original_target es privilegiado
        is_target_privileged = False
        if dir_context and dir_context.is_privileged(original_target_identity):
            is_target_privileged = True
            
        if consequence.can_target_privileged and is_target_privileged:
            # L3 Requiere un target privilegiado EXPLICITO y CONOCIDO.
            severity = IdentitySeverity.L3_PRIVILEGED_AUTH
            target_identity = f"Targeted Privileged User: {original_target_identity}"
            reasons.append("Template allows arbitrary SAN without constraints AND target resolves to a known Privileged Group.")
            if dir_context and dir_context.privileged_targets_resolution == "partial":
                confidence = "medium"
        else:
            severity = IdentitySeverity.L2_ARBITRARY_USER
            target_identity = "Arbitrary Standard User (Or Target Not Discovered As Privileged)"
            reasons.append("Template allows arbitrary targeting but either constraints apply or explicitly validated target is not definitively privileged.")

    # 3. Identity Minting (Enrollment Agent)
    if cap == PKICapability.CanIssueOtherCerts:
        if consequence.can_target_privileged:
            severity = IdentitySeverity.L4_IDENTITY_MINTING
            target_identity = "Identity Minter (Enrollment Agent) - Unconstrained"
            reasons.append("Enrollment Agent privileges available without signature constraints.")
        else:
            severity = IdentitySeverity.L2_ARBITRARY_USER
            target_identity = "Identity Minter (Constrained)"
            reasons.append("Enrollment Agent available but constrained by issuance friction.")
        
    # 4. Authentication Authority (SubCA)
    if cap == PKICapability.CanSubordinateCA:
        if consequence.can_target_privileged:
            severity = IdentitySeverity.L5_AUTH_AUTHORITY
            target_identity = "Authentication Authority (SubCA)"
            reasons.append("SubCA privileges acquired dynamically without manager approval.")
        else:
            severity = IdentitySeverity.L2_ARBITRARY_USER
            target_identity = "SubCA Restricted"
            reasons.append("SubCA template found but requires interaction/friction to exploit.")

    # 5. AnyPurpose EKU
    if cap == PKICapability.CanAnyPurposeAuth:
        if consequence.can_target_arbitrary:
            severity = IdentitySeverity.L2_ARBITRARY_USER
            target_identity = "Potential Arbitrary Target (AnyPurpose)"
            reasons.append("AnyPurpose EKU allowed with SAN features. Highly dependent on CA/DC configuration.")
        else:
            severity = IdentitySeverity.L1_SELF_AUTH
            target_identity = "Potential Self-Auth (AnyPurpose)"
            reasons.append("AnyPurpose EKU allowed for self-auth. Highly dependent on CA/DC configuration.")
        confidence = "requires_lab_validation"

    # 6. Unknown/Lab Validation
    if cap == PKICapability.RequiresLabValidation:
        severity = IdentitySeverity.L0_NONE
        target_identity = "Unknown"
        confidence = "requires_lab_validation"
        reasons.append("Unknown EKUs identified. Needs physical lab verification.")
        
    # 7. Access Control Modifications (Edge case templates)
    if cap == PKICapability.CanWriteDACL:
        if original_target_identity.lower() == "ca_object":
            severity = IdentitySeverity.L5_AUTH_AUTHORITY
            reasons.append("Access Control manipulation against CA Object mapped directly to Authority Takeover.")
        else:
            severity = IdentitySeverity.L3_PRIVILEGED_AUTH
            target_identity = f"Access Control Modifier for {original_target_identity}"
            confidence = "medium"
            reasons.append("Template Takeover: Execution modeled via explicit TEMPLATE_WRITE -> TEMPLATE_MODIFIED -> ENROLL steps.")
            
    consequence.raw_evidence["severity_reasons"] = reasons
    consequence.raw_evidence["confidence"] = confidence
        
    return IdentityOutcome(
        severity=severity,
        target_identity=target_identity,
        source_capability=consequence.capability,
        evidence=consequence.raw_evidence
    )
