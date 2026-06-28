from typing import List, Dict, Any
from models.capabilities import AuthenticationConsequence, PKICapability, EvidenceRecord
from models.context import DirectoryContext
from models.eku_registry import (
    EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON, EKU_PKINIT_CLIENT,
    EKU_CERT_REQ_AGENT, EKU_ANY_PURPOSE, EKU_SUBCA, is_identity_eku,
    KNOWN_IDENTITY_EKUS
)

# Name Flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

def can_target_arbitrary_user(template_dict: dict, ca_dict: dict = None) -> bool:
    """
    Verifica explícitamente si el Subject/SAN es controlable o si permite UPN arbitrary.
    Solo evalúa flags técnicos de la plantilla o el override ESC6 a nivel de CA.
    """
    name_flags = template_dict.get("name_flags", 0)
    
    # ESC1 direct flag
    if name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
        return True
    
    if name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME:
        return True
        
    # Check CA-Level SAN Override (ESC6 partial implementation)
    if ca_dict and ca_dict.get("editf_attributesubjectaltname2") == True:
        return True
        
    return False

def can_target_privileged_user(template_dict: dict, ca_dict: dict = None, dir_context: DirectoryContext = None) -> bool:
    """
    Depende de can_target_arbitrary_user == True Y sin fricciones de Manager Approval u otras.
    Si hay una validación manual, se asume que el Manager/Agente no permitirá suplantar a un Admin.
    Revisa si los signers son estrictamente Low Trust (escalación silenciosa).
    """
    if not can_target_arbitrary_user(template_dict, ca_dict):
        return False
        
    req_manager_approval = "Manager Approval" in template_dict.get("issuance_policies", []) or \
                           template_dict.get("requires_manager_approval", False)
    
    # Signer Evaluation
    req_agent_signature = "Agent Signature" in template_dict.get("issuance_policies", []) or \
                          template_dict.get("requires_agent_signature", False)
                          
    authorized_signers = template_dict.get("authorized_signers", [])
    
    # Si requiere firma pero podemos comprobar que NO son administradores sino gente rasa:
    if req_agent_signature and dir_context and authorized_signers:
        # Check if ALL signers are low-trust (assuming we have a helper to check this)
        # For now, MVP: if ANY of the signers is low-privileged, it's still friction but severe.
        # But mathematically it is STILL friction. They are not direct, we just assume L2.
        pass
        
    if req_manager_approval or req_agent_signature:
        return False
        
    return True

def infer_template_capabilities(
    template_dict: dict, 
    source_principal: str = "Unknown", 
    ca_dict: dict = None,
    dir_context: DirectoryContext = None
) -> List[AuthenticationConsequence]:
    capabilities = []
    explanations = []
    
    ekus = template_dict.get("ekus", [])
    app_policies = template_dict.get("application_policies", [])
    
    # Unified policies list to search for Enrollment Agent or identities
    all_policies = ekus + app_policies
    
    # Filter Unknown EKUs (ignore app_policies for this check to not throw warnings on standard metadata)
    unknown_ekus = [eku for eku in ekus if not is_identity_eku(eku) and eku != EKU_ANY_PURPOSE]
    
    # Check interaction friction (Human-in-the-loop)
    req_manager_approval = "Manager Approval" in template_dict.get("issuance_policies", []) or \
                           template_dict.get("requires_manager_approval", False)
    req_agent_signature = "Agent Signature" in template_dict.get("issuance_policies", []) or \
                          template_dict.get("requires_agent_signature", False)
    
    authorized_signers = template_dict.get("authorized_signers", [])                      
    is_deterministic = not (req_manager_approval or req_agent_signature)
    
    # Targeting Capabilities
    can_arbitrary = can_target_arbitrary_user(template_dict, ca_dict)
    can_privileged = can_target_privileged_user(template_dict, ca_dict, dir_context)
    san_enabled = can_arbitrary # Implicit by logic
    
    # Friction severity scaler for evidence (Signers check)
    signer_risk_context = ""
    if req_agent_signature and dir_context and authorized_signers:
        # Simplification: If "Domain Users" or similar can sign, mark the evidence as critical risk
        low_trust_signers = [s for s in authorized_signers if not dir_context.is_privileged(s)]
        if low_trust_signers:
            signer_risk_context = f"WARNING! Authorized Signers include Low-Trust subjects: {low_trust_signers}. This Risk Path is highly viable."
            # Note: Determinism is explicitly kept False to avoid polluting pure graph.


    raw_evidence = EvidenceRecord(
        source_principal=source_principal,
        template=template_dict.get("name", "Unknown"),
        published=template_dict.get("is_published", False),
        effective_rights=template_dict.get("effective_enroll_principals", []),
        observed_ekus=ekus,
        observed_flags=[f"NameFlag={template_dict.get('name_flags', 0)}"],
        issuance_reqs={"manager_approval": req_manager_approval, "agent_signature": req_agent_signature, "authorized_signers": authorized_signers},
        inferred_capabilities=[],
        confidence="high" if is_deterministic else "medium",
        notes=[f"Unknown EKUs ignored: {unknown_ekus}"] if unknown_ekus else []
    )
    
    if signer_risk_context:
        raw_evidence.notes.append(signer_risk_context)
        
    if ca_dict and ca_dict.get("editf_attributesubjectaltname2") == True:
        raw_evidence.notes.append("CA-Level override EDITF_ATTRIBUTESUBJECTALTNAME2 detected. SAN mapping is globally capable.")

    # 1. Can we auth? Strictly map OIDs
    can_auth = False
    if EKU_CLIENT_AUTH in ekus or EKU_SMARTCARD_LOGON in ekus or EKU_PKINIT_CLIENT in ekus:
        can_auth = True
    
    if can_auth:
        cap = PKICapability.CanPKINITUser if (EKU_CLIENT_AUTH in ekus or EKU_PKINIT_CLIENT in ekus) else PKICapability.CanSmartcardLogon
        
        if can_arbitrary:
            explanations.append(f"Template '{template_dict.get('name')}' allows Client Authentication AND enrollee supplies subject.")
        else:
            explanations.append(f"Template '{template_dict.get('name')}' allows Client Authentication for the enrollee (Self-Auth).")
            
        evidences = raw_evidence.__dict__.copy()
        evidences["inferred_capabilities"] = [cap.name]
        
        capabilities.append(
            AuthenticationConsequence(
                capability=cap,
                is_deterministic=is_deterministic,
                subject_alt_name_enabled=san_enabled,
                can_target_arbitrary=can_arbitrary,
                can_target_privileged=can_privileged,
                explanations=explanations.copy(),
                raw_evidence=evidences
            )
        )
        explanations.clear()

    # 2. Can we issue other certs? (Enrollment Agent via EKU or App Policies)
    if EKU_CERT_REQ_AGENT in all_policies:
        explanations.append(f"Template '{template_dict.get('name')}' has Certificate Request Agent OID (Identity Minting).")
        evidences = raw_evidence.__dict__.copy()
        evidences["inferred_capabilities"] = [PKICapability.CanIssueOtherCerts.name]
        
        capabilities.append(
            AuthenticationConsequence(
                capability=PKICapability.CanIssueOtherCerts,
                is_deterministic=is_deterministic,
                subject_alt_name_enabled=san_enabled,
                can_target_arbitrary=can_arbitrary,
                can_target_privileged=can_privileged,
                explanations=explanations.copy(),
                raw_evidence=evidences
            )
        )
        explanations.clear()
        
    # 3. Subordinate CA Check
    if EKU_SUBCA in ekus or template_dict.get("is_ca", False):
        explanations.append(f"Template '{template_dict.get('name')}' defines a Subordinate CA.")
        evidences = raw_evidence.__dict__.copy()
        evidences["inferred_capabilities"] = [PKICapability.CanSubordinateCA.name]
        
        capabilities.append(
            AuthenticationConsequence(
                capability=PKICapability.CanSubordinateCA,
                is_deterministic=is_deterministic,
                subject_alt_name_enabled=san_enabled,
                can_target_arbitrary=can_arbitrary,
                can_target_privileged=can_privileged,
                explanations=explanations.copy(),
                raw_evidence=evidences
            )
        )
        explanations.clear()
        
    # 4. Unknown or AnyPurpose (Conservador)
    has_known_eku = any(eku in ekus for eku in KNOWN_IDENTITY_EKUS)
    
    if EKU_ANY_PURPOSE in ekus:
        explanations.append(f"Template '{template_dict.get('name')}' has AnyPurpose EKU. Can be used for auth conceptually but requires lab verification in context.")
        evidences = raw_evidence.__dict__.copy()
        evidences["inferred_capabilities"] = [PKICapability.CanAnyPurposeAuth.name]
        evidences["confidence"] = "requires_lab_validation"
        
        capabilities.append(
            AuthenticationConsequence(
                capability=PKICapability.CanAnyPurposeAuth,
                is_deterministic=False, # AnyPurpose always forces non-deterministic due to patching unknowns
                subject_alt_name_enabled=san_enabled,
                can_target_arbitrary=can_arbitrary,
                can_target_privileged=can_privileged,
                explanations=explanations.copy(),
                raw_evidence=evidences
            )
        )
        explanations.clear()
        
    elif unknown_ekus or not has_known_eku:
        explanations.append(f"Template '{template_dict.get('name')}' has Unknown EKUs. Requires Lab Validation. Confidence reduced.")
        
        evidences = raw_evidence.__dict__.copy()
        evidences["inferred_capabilities"] = [PKICapability.RequiresLabValidation.name]
        evidences["confidence"] = "requires_lab_validation"
        
        capabilities.append(
            AuthenticationConsequence(
                capability=PKICapability.RequiresLabValidation,
                is_deterministic=False, # Nunca es determinístico si no conocemos el OID
                subject_alt_name_enabled=san_enabled,
                can_target_arbitrary=can_arbitrary,
                can_target_privileged=can_privileged,
                explanations=explanations.copy(),
                raw_evidence=evidences
            )
        )
        explanations.clear()
        
    return capabilities
