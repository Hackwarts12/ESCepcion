import json, sys, base64
from pathlib import Path
from utils.descriptor_parser import parse_security_descriptor

def main(json_path, template_cn=None):
    p = Path(json_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    entries = data if isinstance(data, list) else data.get("templates", data if isinstance(data, dict) else [])
    if template_cn:
        entries = [t for t in entries if (t.get("cn") or "").lower() == template_cn.lower()]
    if not entries:
        print("Plantilla no encontrada.")
        return
    tpl = entries[0]
    print("== Plantilla seleccionada:", tpl.get("cn"))
    print("EKUs:", tpl.get("ekus"))
    print("Flags:", tpl.get("flags"))
    print("Schema version:", tpl.get("schema_version"))

    b64 = tpl.get("nTSecurityDescriptor_b64") or tpl.get("nTSecurityDescriptor")
    if not b64:
        print("No hay nTSecurityDescriptor en esta plantilla.")
        return
    raw = base64.b64decode(b64) if isinstance(b64, str) else bytes(b64)
    print("Descriptor bytes len:", len(raw))

    acl_entries, owner_sid = parse_security_descriptor(raw)
    print("\n== Owner SID:", owner_sid)
    print("== ACE count:", len(acl_entries))
    for i, e in enumerate(acl_entries, 1):
        sid = e.get("sid")
        name = e.get("nombre") or e.get("name")
        perms = e.get("permisos") or e.get("permissions") or e.get("rights") or e.get("access")
        if isinstance(perms, str):
            perms = [x.strip() for x in perms.replace("|", ",").split(",") if x.strip()]
        elif isinstance(perms, (list, tuple, set)):
            perms = list(perms)
        else:
            perms = []
        print(f"ACE #{i}")
        print("  SID   :", sid)
        print("  Name  :", name)
        print("  Perms :", perms)

if __name__ == "__main__":
    json_path = sys.argv[1]
    cn = sys.argv[2] if len(sys.argv) > 2 else None
    main(json_path, cn)
