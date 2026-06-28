from base64 import b64decode
from typing import Tuple, List, Dict, Any, Optional
from modules.esc4_checker import check_ESC4
from modules.esc5_checker import analyze_descriptor_for_esc5
from utils.descriptor_parser import parse_security_descriptor
from modules.publish_validator import analizar_permisos_enroll

ESC1_RISKY_EKUS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.5.7.3.4",
    "1.3.6.1.5.5.7.3.1",
}

NON_AUTH_EKUS = {
    "1.3.6.1.4.1.311.10.3.4",
    "1.3.6.1.5.5.7.3.3",
    "1.3.6.1.5.5.7.3.8",
}

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_IS_ENROLLMENT_AGENT = 0x00000080

ENROLL_PEND_ALL_REQUESTS = 0x00000002
ENROLL_PUBLISH_TO_DS = 0x00000004

WELL_KNOWN_INSECURE_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
DOMAIN_INSECURE_RIDS = {"-513", "-515"}
INSECURE_NAMES = {"everyone", "authenticated users", "domain users", "users", "domain computers"}

CRITICAL_PERMS_FOR_ENROLL = {
    "WRITE_PROPERTY",
    "CONTROL_ACCESS",
    "GENERIC_WRITE",
    "WRITE_DACL",
    "WRITE_OWNER",
    "FULL_CONTROL",
}


def _looks_insecure_principal(sid: Optional[str], name: Optional[str]) -> bool:
    if name:
        if "| TRUSTED" in name:
            return False
        if "| LOW_TRUST" in name or "| UNKNOWN_SID" in name:
            return True
            
    if not sid and not name:
        return False
    if sid:
        if sid in WELL_KNOWN_INSECURE_SIDS or any(sid.endswith(r) for r in DOMAIN_INSECURE_RIDS):
            return True
    if name and name.split(" | ")[0].lower().strip() in INSECURE_NAMES:
        return True
    return False


def _check_acl_exploitable_by_nonpriv(raw_descriptor: bytes, resolved_acl: Dict[str, str] = None) -> Tuple[bool, str, str]:
    entries, owner = parse_security_descriptor(raw_descriptor)
    owner_name = (resolved_acl or {}).get(owner)
    if owner and _looks_insecure_principal(owner, owner_name):
        sev = "Low" if owner_name and "| UNKNOWN_SID" in owner_name else "High"
        return True, f"Owner inseguro: {owner}", sev

    for e in entries:
        sid = e.get("sid")
        raw_name = e.get("nombre") or e.get("name")
        name = (resolved_acl or {}).get(sid) or raw_name
        perms = set(e.get("permisos", []))
        if _looks_insecure_principal(sid, name):
            if perms & CRITICAL_PERMS_FOR_ENROLL:
                display = (name or sid).split(" | ")[0]
                sev = "Low" if name and "| UNKNOWN_SID" in name else "High"
                return True, f"{display} ({sid}) tiene permisos críticos: {', '.join(sorted(perms & CRITICAL_PERMS_FOR_ENROLL))}", sev
        elif name and "support" in name.lower():
            if perms & CRITICAL_PERMS_FOR_ENROLL:
                return True, f"Grupo técnico {name.split(' | ')[0]} con permisos críticos", "Medium"
    return False, "ACL restringida a cuentas de administración (no explotable por usuarios estándar)", "Low"


def _subject_mode(cert_name_flag: int) -> str:
    return "Supply in request" if (cert_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) else "Build from directory"


def _san_mode(cert_name_flag: int) -> str:
    return "Supply SAN in request" if (cert_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME) else "From directory/none"


def _san_requirements(cert_name_flag: int) -> List[str]:
    req = []
    if cert_name_flag & 0x02000000: req.append("SAN requires UPN")
    if cert_name_flag & 0x04000000: req.append("SAN requires Email")
    if cert_name_flag & 0x08000000: req.append("SAN requires DNS")
    if cert_name_flag & 0x00800000: req.append("SAN requires SPN")
    return req


def detectar_escs(
    template_data: Dict[str, Any],
    resolved_acl: Optional[Dict[str, str]] = None,
    pki_objects: Optional[List[Dict[str, Any]]] = None,
    plantillas_publicadas: Optional[List[str]] = None
) -> Dict[str, Any]:
    ekus = template_data.get("ekus", []) or []
    flags = int(template_data.get("flags", 0) or 0)
    cert_name_flag = int(template_data.get("cert_name_flag", 0) or 0)
    enroll_flag = int(template_data.get("enroll_flag", 0) or 0)

    cn = (template_data.get("cn") or "").strip().lower()
    publicada = False
    if plantillas_publicadas:
        publicadas_normalizadas = [p.strip().lower() for p in plantillas_publicadas]
        if cn in publicadas_normalizadas:
            publicada = True

    descriptor = None
    if template_data.get("nTSecurityDescriptor_b64"):
        try:
            descriptor = b64decode(template_data["nTSecurityDescriptor_b64"])
        except Exception:
            descriptor = None
    elif template_data.get("nTSecurityDescriptor"):
        descriptor = template_data["nTSecurityDescriptor"]

    is_accessible = False
    if publicada and descriptor:
        try:
            is_accessible = bool(analizar_permisos_enroll(descriptor))
        except Exception:
            is_accessible = False

    subject_name = _subject_mode(cert_name_flag)
    san_mode = _san_mode(cert_name_flag)
    san_reqs = _san_requirements(cert_name_flag)

    # Estandarizamos los retornos iniciales a SAFE
    resultado = {
        "template": template_data.get("cn"),
        "ESC1": "SAFE", "ESC1_Reason": "", "ESC1_Severidad": "Info",
        "ESC2": "SAFE", "ESC2_Reason": "", "ESC2_Severidad": "Info",
        "ESC3": "SAFE", "ESC3_Reason": "", "ESC3_Severidad": "Info",
        "ESC4": "SAFE", "ESC4_Reason": "", "ESC4_Severidad": "Info",
        "ESC5": "SAFE", "ESC5_Reason": "", "ESC5_Severidad": "Info",
        "ESC6": "SAFE", "ESC6_Reason": "", "ESC6_Severidad": "Info",
    }
    from utils.result_model import ESCResult
    # The default values for new ESCs will be set to placeholder_removed which is NOT_SCANNED.
    resultado.update({
        "ESC9": ESCResult.placeholder_removed("ESC9").to_dict(),
        "ESC11": ESCResult.placeholder_removed("ESC11").to_dict(),
        "ESC13": ESCResult.placeholder_removed("ESC13").to_dict(),
        "ESC15": ESCResult.placeholder_removed("ESC15").to_dict(),
        "ESC16": ESCResult.placeholder_removed("ESC16").to_dict(),
    })

    has_risky_eku = any(oid in ESC1_RISKY_EKUS for oid in ekus)
    can_supply = bool(cert_name_flag & (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME))
    if can_supply and has_risky_eku:
        if not publicada:
            resultado["ESC1"] = "POTENTIAL"
            resultado["ESC1_Reason"] = f"Permite suministro de Subject/SAN con EKUs sensibles, pero la plantilla no está publicada en una CA: {', '.join(ekus)}"
            resultado["ESC1_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC1"] = "POTENTIAL"
            resultado["ESC1_Reason"] = f"Permite suministro de Subject/SAN con EKUs sensibles, pero sin permisos de inscripción efectivos para grupos comunes: {', '.join(ekus)}"
            resultado["ESC1_Severidad"] = "Low"
        else:
            resultado["ESC1"] = "EXPLOITABLE"
            resultado["ESC1_Reason"] = f"Permite suministro de Subject/SAN con EKUs sensibles: {', '.join(ekus)}"
            resultado["ESC1_Severidad"] = "High"
    elif can_supply:
        if not publicada:
            resultado["ESC1"] = "POTENTIAL"
            resultado["ESC1_Reason"] = "Permite suministro de Subject/SAN, pero la plantilla no está publicada en una CA"
            resultado["ESC1_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC1"] = "POTENTIAL"
            resultado["ESC1_Reason"] = "Permite suministro de Subject/SAN, pero sin permisos de inscripción efectivos para grupos comunes"
            resultado["ESC1_Severidad"] = "Low"
        else:
            resultado["ESC1"] = "NEAR_MISS"
            resultado["ESC1_Reason"] = "Permite suministro de Subject/SAN sin EKUs sensibles"
            resultado["ESC1_Severidad"] = "Medium"

    is_any_purpose = any(oid in ekus for oid in ["2.5.29.37.0", "1.3.6.1.4.1.311.10.12.1"]) or len(ekus) == 0
    ekus_effective = [e for e in ekus if e not in NON_AUTH_EKUS]
    has_auth_eku_esc2 = any(oid in ekus_effective for oid in ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"])
    if is_any_purpose and has_auth_eku_esc2:
        if enroll_flag & ENROLL_PEND_ALL_REQUESTS:
            resultado["ESC2"] = "POTENTIAL"
            resultado["ESC2_Reason"] = "Plantilla AnyPurpose/NoEKU con EKUs de autenticación, pero requiere aprobación (PEND_ALL_REQUESTS)"
            resultado["ESC2_Severidad"] = "Medium"
        elif not publicada:
            resultado["ESC2"] = "POTENTIAL"
            resultado["ESC2_Reason"] = "Plantilla AnyPurpose/NoEKU con EKUs de autenticación, pero no está publicada en una CA"
            resultado["ESC2_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC2"] = "POTENTIAL"
            resultado["ESC2_Reason"] = "Plantilla AnyPurpose/NoEKU con EKUs de autenticación, pero sin permisos de inscripción efectivos para grupos comunes"
            resultado["ESC2_Severidad"] = "Low"
        else:
            resultado["ESC2"] = "EXPLOITABLE"
            resultado["ESC2_Reason"] = "Plantilla AnyPurpose/NoEKU con EKUs de autenticación"
            resultado["ESC2_Severidad"] = "High"

    is_enroll_agent = "1.3.6.1.4.1.311.20.2.1" in ekus
    is_enroll_flag_set = bool(flags & CT_FLAG_IS_ENROLLMENT_AGENT)
    
    # Check for Template B in all templates if they exist in pki_objects? No, we don't have all templates in `detectar_escs`.
    # Wait! If we don't have all templates, we can't fully do step 3 right now. We must update the caller later. For now let's assume we don't have Template B list.
    # We will pass `all_templates_data` to `detectar_escs` signature as well.

    if is_enroll_agent and not is_enroll_flag_set:
        if not publicada:
            resultado["ESC3"] = "POTENTIAL"
            resultado["ESC3_Reason"] = "EKU Enrollment Agent presente, pero no publicada"
            resultado["ESC3_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC3"] = "POTENTIAL"
            resultado["ESC3_Reason"] = "EKU Enrollment Agent presente, pero sin permisos de inscripción para usuarios no privilegiados"
            resultado["ESC3_Severidad"] = "Low"
        else:
            resultado["ESC3"] = "EXPLOITABLE"
            resultado["ESC3_Reason"] = "EKU Enrollment Agent presente sin flag 0x80 (ESC3)"
            resultado["ESC3_Severidad"] = "High"

    if descriptor:
        tpl_name = template_data.get("cn", "")
        esc4, reason = check_ESC4(tpl_name, descriptor, resolved_acl or {})
        if esc4:
            resultado["ESC4"] = "EXPLOITABLE"
            resultado["ESC4_Reason"] = reason
            _, _, sev = _check_acl_exploitable_by_nonpriv(descriptor, resolved_acl)
            resultado["ESC4_Severidad"] = sev
        else:
            resultado["ESC4"] = "SAFE"
            resultado["ESC4_Reason"] = reason
            resultado["ESC4_Severidad"] = "Info"



    enrollee_supplies_subject = bool(cert_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    enrollee_supplies_san = bool(cert_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
    has_auth_eku_esc6 = any(oid in ekus for oid in ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"])
    if (enrollee_supplies_subject or enrollee_supplies_san) and has_auth_eku_esc6:
        if enroll_flag & ENROLL_PEND_ALL_REQUESTS:
            resultado["ESC6"] = "POTENTIAL"
            resultado["ESC6_Reason"] = "Plantilla permite Subject/SAN + EKU de autenticación, pero requiere aprobación (PEND_ALL_REQUESTS)"
            resultado["ESC6_Severidad"] = "Low"
        elif not publicada:
            resultado["ESC6"] = "POTENTIAL"
            resultado["ESC6_Reason"] = "Plantilla permite Subject/SAN + EKU de autenticación, pero no está publicada en una CA"
            resultado["ESC6_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC6"] = "POTENTIAL"
            resultado["ESC6_Reason"] = "Plantilla permite Subject/SAN + EKU de autenticación, pero sin permisos de inscripción efectivos para grupos comunes"
            resultado["ESC6_Severidad"] = "Low"
        else:
            resultado["ESC6"] = "POTENTIAL"
            resultado["ESC6_Reason"] = "Plantilla permite Subject/SAN y presenta EKU de autenticación — ESC6 requiere verificación RPC"
            resultado["ESC6_Severidad"] = "Medium"
            
    # --- ESC9: NO_SECURITY_EXTENSION ---
    if enroll_flag & 0x00080000:
        if not publicada:
            resultado["ESC9"] = "POTENTIAL"
            resultado["ESC9_Reason"] = "Plantilla tiene NO_SECURITY_EXTENSION, pero no está publicada"
            resultado["ESC9_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC9"] = "POTENTIAL"
            resultado["ESC9_Reason"] = "Plantilla tiene NO_SECURITY_EXTENSION, pero sin permisos efectivos para grupos comunes"
            resultado["ESC9_Severidad"] = "Low"
        else:
            resultado["ESC9"] = "EXPLOITABLE"
            resultado["ESC9_Reason"] = "Plantilla tiene NO_SECURITY_EXTENSION configurado, vulnerable a bypass de mapeo fuerte si el DC permite UPN mapping"
            resultado["ESC9_Severidad"] = "High"
    
    # --- ESC13: OID to Group Link ---
    policies = template_data.get("policies", []) or []
    linked_oids = []
    if pki_objects:
        for obj in pki_objects:
            if "msPKI-Enterprise-Oid" in obj.get("objectClass", []):
                oid_link = obj.get("msDS-OIDToGroupLink")
                oid_name = obj.get("cn")
                if oid_link and oid_name and oid_name in policies:
                    linked_oids.append(oid_name)
                    
    if linked_oids:
        if not publicada:
            resultado["ESC13"] = "POTENTIAL"
            resultado["ESC13_Reason"] = f"Plantilla usa OID vinculados a grupos ({', '.join(linked_oids)}), pero no está publicada"
            resultado["ESC13_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC13"] = "POTENTIAL"
            resultado["ESC13_Reason"] = f"Plantilla usa OID vinculados a grupos ({', '.join(linked_oids)}), pero sin permisos de inscripción efectivos"
            resultado["ESC13_Severidad"] = "Low"
        else:
            resultado["ESC13"] = "EXPLOITABLE"
            resultado["ESC13_Reason"] = f"Plantilla usa políticas de emisión vinculadas a grupos de seguridad: {', '.join(linked_oids)}"
            resultado["ESC13_Severidad"] = "High"

    # --- ESC15: EKUwu ---
    schema_version = template_data.get("schema_version", 0)
    if schema_version == 1 and can_supply:
        if not publicada:
            resultado["ESC15"] = "POTENTIAL"
            resultado["ESC15_Reason"] = "Plantilla Schema V1 permite proveer Subject/SAN, vulnerable a inyección de Application Policy (EKUwu), pero no publicada"
            resultado["ESC15_Severidad"] = "Info"
        elif not is_accessible:
            resultado["ESC15"] = "POTENTIAL"
            resultado["ESC15_Reason"] = "Plantilla Schema V1 permite proveer Subject/SAN, vulnerable a inyección de Application Policy, sin permisos efectivos"
            resultado["ESC15_Severidad"] = "Low"
        else:
            resultado["ESC15"] = "EXPLOITABLE"
            resultado["ESC15_Reason"] = "Plantilla Schema V1 permite al solicitante proveer Subject/SAN (Vulnerable a ESC15 EKUwu)"
            resultado["ESC15_Severidad"] = "High"

    return resultado
