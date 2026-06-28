from __future__ import annotations
from typing import List, Tuple, Dict, Any
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

def _mask_to_names(mask: int) -> List[str]:
    names: List[str] = []
    if mask & 0x10000000: names.append("GENERIC_ALL")
    if mask & 0x40000000: names.append("GENERIC_WRITE")
    if mask & 0x00080000: names.append("WRITE_OWNER")
    if mask & 0x00040000: names.append("WRITE_DACL")
    if mask & 0x00010000: names.append("DELETE")
    if mask & 0x00000020: names.append("WRITE_PROPERTY")
    if mask & 0x00000100: names.append("CONTROL_ACCESS")
    if mask & 0x00000001: names.append("CREATE_CHILD")
    if mask & 0x00000002: names.append("DELETE_CHILD")
    if mask & 0x00000004: names.append("LIST_CONTENTS")
    if mask & 0x00000008: names.append("WRITE_SELF")
    if mask & 0x00000010: names.append("READ_PROPERTY")
    if mask & 0x00000040: names.append("DELETE_TREE")
    if mask & 0x00000080: names.append("LIST_OBJECT")
    return names

def parse_security_descriptor(sd_bytes: bytes) -> Tuple[List[Dict[str, Any]], str | None]:
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(sd_bytes)

    owner_sid = None
    if sd['OwnerSid'] is not None:
        try:
            owner_sid = sd['OwnerSid'].formatCanonical()
        except Exception:
            owner_sid = None

    entries: List[Dict[str, Any]] = []
    dacl = sd['Dacl']
    if dacl is None:
        return entries, owner_sid

    for ace in dacl.aces:
        try:
            ace_core = ace['Ace']
            sid = ace_core['Sid'].formatCanonical()
            mask_val = int(ace_core['Mask']['Mask'])
            perms = _mask_to_names(mask_val)

            object_type = None
            try:
                ot = ace_core['ObjectType']
                if ot:
                    object_type = str(ot)
            except Exception:
                object_type = None

            entries.append({
                "sid": sid,
                "permisos": perms,
                "object_type": object_type,
            })
        except Exception:
            continue

    return entries, owner_sid
