from __future__ import annotations
from typing import Dict, Any, Tuple, Set
from utils.descriptor_parser import parse_security_descriptor

WELL_KNOWN_INSECURE_SIDS: Set[str] = {
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
}
DOMAIN_INSECURE_RIDS: Set[str] = {"-513", "-515"}
INSECURE_NAMES: Set[str] = {
    "everyone",
    "authenticated users",
    "users",
    "domain users",
    "domain computers",
    "pre-windows 2000 compatible access",
}

CRITICAL_PERMS: Set[str] = {
    "FULL_CONTROL",
    "GENERIC_ALL",
    "GENERIC_WRITE",
    "WRITE_OWNER",
    "WRITE_DACL",
    "WRITE_PROPERTY",
}

def _looks_insecure_principal(sid: str | None, name: str | None) -> bool:
    if name:
        if "| TRUSTED" in name:
            return False
        if "| LOW_TRUST" in name or "| UNKNOWN_SID" in name:
            return True
            
    if sid:
        if sid in WELL_KNOWN_INSECURE_SIDS:
            return True
        for rid in DOMAIN_INSECURE_RIDS:
            if sid.endswith(rid):
                return True
    if name and " ".join(name.split(" | ")[0].lower().split()) in INSECURE_NAMES:
        return True
    return False

def _fallback_name(sid: str) -> str:
    if sid == "S-1-1-0": return "Everyone"
    if sid == "S-1-5-11": return "Authenticated Users"
    if sid.endswith("-513"): return "Domain Users"
    if sid.endswith("-515"): return "Domain Computers"
    if sid.endswith("-512"): return "Domain Admins"
    if sid.endswith("-519"): return "Enterprise Admins"
    if sid.endswith("-500"): return "Administrator"
    return sid

def _display_name(sid: str, resolved_acl: Dict[str, Any] | None, entry_name: str | None) -> str:
    if resolved_acl and sid in resolved_acl and resolved_acl[sid]:
        return str(resolved_acl[sid])
    if entry_name:
        return entry_name
    return _fallback_name(sid)

def check_ESC4(template_name: str, raw_descriptor: bytes, resolved_acl: Dict[str, Any] | None = None) -> Tuple[bool, str]:
    if not raw_descriptor:
        return False, f"No nTSecurityDescriptor en '{template_name}'."

    acl_entries, owner_sid = parse_security_descriptor(raw_descriptor)

    if owner_sid and _looks_insecure_principal(owner_sid, (resolved_acl or {}).get(owner_sid)):
        owner_name = _display_name(owner_sid, resolved_acl, None)
        return True, f"{owner_name} ({owner_sid}) como owner inseguro en '{template_name}'."

    for entry in acl_entries:
        sid = entry.get("sid")
        entry_name = entry.get("nombre") or entry.get("name")
        perms = set(entry.get("permisos", []))
        obj_type = entry.get("object_type")
        if not sid or not perms:
            continue

        name = _display_name(sid, resolved_acl, entry_name)
        if not _looks_insecure_principal(sid, name):
            continue

        effective_perms = set(perms)
        if "WRITE_PROPERTY" in effective_perms and obj_type:
            effective_perms.discard("WRITE_PROPERTY")

        critical = effective_perms & CRITICAL_PERMS
        if critical:
            return True, f"{name} ({sid}) tiene {', '.join(sorted(critical))} en '{template_name}'."

    return False, f"Sin permisos críticos para principales no privilegiados en '{template_name}'."
