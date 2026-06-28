from typing import Dict, List, Any
from utils import descriptor_parser

CRITICAL_PERMS_ESC6_CA = {
    "FULL_CONTROL", "GENERIC_ALL", "GENERIC_WRITE",
    "WRITE_DACL", "WRITE_OWNER", "CONTROL_ACCESS", "WRITE_PROPERTY", "DELETE"
}

NON_PRIVILEGED_PRINCIPALS = {"everyone", "authenticated users", "domain users", "users", "domain computers"}

ENROLL_PEND_ALL_REQUESTS = 0x00000002
ENROLL_PUBLISH_TO_DS = 0x00000004


def _is_non_privileged(sid: str, name: str) -> bool:
    if not sid and not name:
        return False
    sid_lower = sid.lower() if sid else ""
    name_lower = name.lower() if name else ""
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
        if _is_non_privileged(sid or "", name or "") and (perms & {"WRITE_DACL", "WRITE_OWNER", "CONTROL_ACCESS", "GENERIC_WRITE"}):
            if "nonpriv_full_control" not in matrix:
                matrix["nonpriv_can_modify_ca"] = "High"
    if owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        matrix["owner_nonprivileged"] = "High"
    if not matrix:
        matrix["no_exploitable_acl_found"] = "Low"
    return matrix


def analyze_ca_for_esc6(
    ca_name: str,
    descriptor_bytes: bytes,
    resolved_acl: Dict[str, str] = None,
    resolved_sids: Dict[str, str] = None,
    enroll_flags: int = 0
) -> Dict[str, Any]:
    resolved_acl = resolved_acl or resolved_sids or {}
    entries, owner = descriptor_parser.parse_security_descriptor(descriptor_bytes)
    vulnerable_entries = []
    vulnerable = False
    severidad = "Low"
    notas_validacion = []

    if enroll_flags & ENROLL_PEND_ALL_REQUESTS:
        notas_validacion.append("CA requiere aprobación de administrador (PEND_ALL_REQUESTS)")
    if not (enroll_flags & ENROLL_PUBLISH_TO_DS):
        notas_validacion.append("CA no publicada en AD (no PUBLISH_TO_DS)")

    for e in entries:
        sid = e.get("sid")
        perms = set(e.get("permisos", []))
        nombre = resolved_acl.get(sid, "")
        if _is_non_privileged(sid or "", nombre or "") and perms & CRITICAL_PERMS_ESC6_CA:
            vulnerable = True
            vulnerable_entries.append({
                "sid": sid,
                "nombre": nombre or sid,
                "permisos": sorted(list(perms & CRITICAL_PERMS_ESC6_CA))
            })

    if vulnerable_entries:
        if any("FULL_CONTROL" in v.get("permisos", []) or "GENERIC_ALL" in v.get("permisos", []) for v in vulnerable_entries):
            severidad = "Critical"
        else:
            severidad = "High"
    elif owner and _is_non_privileged(owner, resolved_acl.get(owner, "")):
        vulnerable = True
        severidad = "High"
        vulnerable_entries.append({
            "sid": owner,
            "nombre": resolved_acl.get(owner, owner),
            "permisos": ["Owner"]
        })

    if notas_validacion:
        if vulnerable:
            severidad = "Medium"
            reason = f"CA potencialmente vulnerable pero no explotable directamente: {', '.join(notas_validacion)}"
        else:
            reason = f"CA segura o con control administrativo — {'; '.join(notas_validacion)}"
    else:
        reason = (
            "CA o Enrollment Service con ACL insegura que permite control a usuarios no privilegiados"
            if vulnerable else
            "CA segura sin accesos indebidos"
        )

    risk_matrix = _build_risk_matrix(entries, owner, resolved_acl)

    return {
        "nombre_objeto": ca_name,
        "ESC6": "EXPLOITABLE" if vulnerable else "SAFE",
        "ESC6_Reason": reason,
        "ESC6_Severidad": severidad,
        "ESC6_Details": vulnerable_entries,
        "ESC6_RiskMatrix": risk_matrix,
        "ESC6_ValidationNotes": notas_validacion
    }

def confirm_via_winreg(ca_host, ca_name, username, password, domain, lmhash='', nthash=''):
    if not ca_host:
        return {"status": "NOT_SCANNED", "reason": "No CA host provided"}
    try:
        from impacket.dcerpc.v5 import transport, rrp
        stringbinding = f'ncacn_np:{ca_host}[\\pipe\\winreg]'
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        ans = rrp.hOpenLocalMachine(dce)
        reg_handle = ans['phKey']

        ca_key = f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
        ans = rrp.hBaseRegOpenKey(dce, reg_handle, ca_key)
        key_handle = ans['phkResult']

        val = rrp.hBaseRegQueryValue(dce, key_handle, 'EditFlags')
        edit_flags = val[1]
        
        rrp.hBaseRegCloseKey(dce, key_handle)
        dce.disconnect()

        # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
        if edit_flags & 0x00040000:
            return {"status": "EXPLOITABLE", "reason": "EDITF_ATTRIBUTESUBJECTALTNAME2 is SET. ESC6 is fully confirmed.", "edit_flags": hex(edit_flags)}
        else:
            return {"status": "NEAR_MISS", "reason": "EDITF_ATTRIBUTESUBJECTALTNAME2 is NOT SET. ESC6 is mitigated.", "edit_flags": hex(edit_flags)}

    except Exception as e:
        return {"status": "NOT_SCANNED", "reason": f"No se pudo conectar via MS-RRP a {ca_host}: {str(e)}"}

analyze_ca_object_for_esc6 = analyze_ca_for_esc6
