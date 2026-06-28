from typing import Dict, Any, List
from utils import descriptor_parser

CRITICAL_PERMS_ESC7_CA = {
    "FULL_CONTROL", "GENERIC_ALL", "GENERIC_WRITE",
    "WRITE_DACL", "WRITE_OWNER", "CONTROL_ACCESS", "WRITE_PROPERTY", "DELETE"
}

NON_PRIVILEGED_PRINCIPALS = {
    "everyone", "authenticated users", "domain users", "users", "domain computers"
}

ENROLL_PEND_ALL_REQUESTS = 0x00000002
ENROLL_PUBLISH_TO_DS = 0x00000004


def _is_non_privileged(sid: str, name: str) -> bool:
    if name:
        if "| TRUSTED" in name:
            return False
        if "| LOW_TRUST" in name or "| UNKNOWN_SID" in name:
            return True
    if not sid and not name:
        return False
    sid_lower = sid.lower() if sid else ""
    name_lower = name.split(" | ")[0].lower() if name else ""
    if name_lower in NON_PRIVILEGED_PRINCIPALS:
        return True
    if sid_lower.endswith("-513") or sid_lower.endswith("-515"):
        return True
    if sid_lower in {"s-1-1-0", "s-1-5-11", "s-1-5-32-545"}:
        return True
    return False


def _build_risk_matrix(entries: List[Dict[str, Any]], owner: str, resolved_acl: Dict[str, str]) -> Dict[str, str]:
    matrix = {}
    for e in entries:
        sid = e.get("sid")
        perms = set(e.get("permisos", []))
        name = resolved_acl.get(sid, "")
        if _is_non_privileged(sid or "", name or "") and ("FULL_CONTROL" in perms or "GENERIC_ALL" in perms):
            matrix["nonpriv_full_control"] = "Critical"
        elif _is_non_privileged(sid or "", name or "") and perms & {"WRITE_DACL", "WRITE_OWNER", "CONTROL_ACCESS"}:
            matrix["nonpriv_write_perms"] = "High"
    if owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        matrix["owner_nonprivileged"] = "Medium"
    if not matrix:
        matrix["no_exploitable_acl_found"] = "Low"
    return matrix


def analyze_ca_for_esc7(ca_name: str, descriptor_bytes: bytes, resolved_acl: Dict[str, str], enroll_flags: int = 0) -> Dict[str, Any]:
    entries, owner = descriptor_parser.parse_security_descriptor(descriptor_bytes)
    vulnerable_entries = []
    vulnerable = False
    estado = "SAFE"
    severidad = "Info"
    notas_validacion = []

    if enroll_flags & ENROLL_PEND_ALL_REQUESTS:
        notas_validacion.append("CA requiere aprobación de administrador (PEND_ALL_REQUESTS)")
    if not (enroll_flags & ENROLL_PUBLISH_TO_DS):
        notas_validacion.append("CA no publicada en AD (no PUBLISH_TO_DS)")

    for e in entries:
        sid = e.get("sid")
        perms = set(e.get("permisos", []))
        name = resolved_acl.get(sid, "")
        if _is_non_privileged(sid or "", name or "") and perms & CRITICAL_PERMS_ESC7_CA:
            vulnerable = True
            vulnerable_entries.append({
                "sid": sid,
                "nombre": name or sid,
                "permisos": sorted(list(perms & CRITICAL_PERMS_ESC7_CA))
            })

    if vulnerable_entries:
        if any("FULL_CONTROL" in v["permisos"] or "GENERIC_ALL" in v["permisos"] for v in vulnerable_entries):
            severidad = "Critical"
        else:
            severidad = "High"
    elif owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        vulnerable = True
        severidad = "Medium"
        vulnerable_entries.append({
            "sid": owner,
            "nombre": resolved_acl.get(owner, owner),
            "permisos": ["Owner"]
        })

    if notas_validacion:
        if vulnerable:
            if severidad in {"Critical", "High"}:
                severidad = "Medium"
            reason = f"CA potencialmente vulnerable pero no explotable directamente: {', '.join(notas_validacion)}"
            estado = "NEAR_MISS"
        else:
            reason = f"CA segura o con control administrativo — {'; '.join(notas_validacion)}"
            estado = "SAFE"
    else:
        if vulnerable:
            estado = "EXPLOITABLE"
            reason = "CA con permisos inseguros otorgados a principales no privilegiados que permiten modificar ACL o tomar control de la CA"
        else:
            estado = "SAFE"
            reason = "CA segura sin ACLs modificables por usuarios no privilegiados"

    risk_matrix = _build_risk_matrix(entries, owner, resolved_acl)

    return {
        "ca_name": ca_name,
        "ESC7_CA": estado,
        "ESC7_CA_Reason": reason,
        "ESC7_CA_Severidad": severidad,
        "ESC7_CA_Details": vulnerable_entries,
        "ESC7_CA_RiskMatrix": risk_matrix,
        "ESC7_CA_ValidationNotes": notas_validacion,
    }
