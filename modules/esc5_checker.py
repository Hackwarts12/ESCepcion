from typing import Dict, List, Any
from utils import descriptor_parser

CRITICAL_PERMS_ESC5 = {
    "FULL_CONTROL", "GENERIC_ALL", "GENERIC_WRITE",
    "WRITE_DACL", "WRITE_OWNER", "CONTROL_ACCESS", "WRITE_PROPERTY", "DELETE"
}

NON_PRIVILEGED_PRINCIPALS = {"everyone", "authenticated users", "domain users", "users", "domain computers"}


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
    for e in entries:
        sid = e.get("sid")
        perms = set(e.get("permisos", []))
        name = resolved_acl.get(sid, "")
        if _is_non_privileged(sid or "", name or "") and (perms & {"GENERIC_WRITE", "WRITE_PROPERTY", "CONTROL_ACCESS", "WRITE_DACL", "WRITE_OWNER"}):
            if "nonpriv_full_control" not in matrix:
                matrix["nonpriv_write_perms"] = "High"
    if owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        matrix["owner_nonprivileged"] = "Medium"
    if not matrix:
        matrix["no_exploitable_acl_found"] = "Low"
    return matrix


def analyze_descriptor_for_esc5(name: str, descriptor_bytes: bytes, resolved_acl: Dict[str, str] = None, resolved_sids: Dict[str, str] = None) -> Dict[str, Any]:
    resolved_acl = resolved_acl or resolved_sids or {}
    entries, owner = descriptor_parser.parse_security_descriptor(descriptor_bytes)
    vulnerable_entries = []
    severidad = "Info"
    estado = "SAFE"

    for e in entries:
        sid = e.get("sid")
        perms = set(e.get("permisos", []))
        nombre = resolved_acl.get(sid, "")
        if _is_non_privileged(sid or "", nombre or "") and perms & CRITICAL_PERMS_ESC5:
            estado = "EXPLOITABLE"
            
            display_name = nombre or sid
            if display_name is None:
                display_name = "ACL presente pero principal no identificado → puede requerir privilegios elevados para leer"
            elif display_name.startswith("S-1-"):
                display_name = f"SID no resuelto: {display_name} → verificar manualmente"
                
            vulnerable_entries.append({
                "sid": sid,
                "nombre": display_name,
                "permisos": sorted(list(perms & CRITICAL_PERMS_ESC5))
            })

    if vulnerable_entries:
        severidad = "High"
    elif owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        estado = "EXPLOITABLE"
        severidad = "Medium"
        vulnerable_entries.append({
            "sid": owner,
            "nombre": resolved_acl.get(owner, owner),
            "permisos": ["Owner"]
        })

    reason = "ACL insegura en objeto PKI/CA accesible por usuarios no privilegiados" if estado == "EXPLOITABLE" else "ACL segura"
    risk_matrix = _build_risk_matrix(entries, owner, resolved_acl)
    return {
        "nombre_objeto": name,
        "ESC5": estado,
        "ESC5_Reason": reason,
        "ESC5_Severidad": severidad,
        "ESC5_Details": vulnerable_entries,
        "ESC5_RiskMatrix": risk_matrix
    }
