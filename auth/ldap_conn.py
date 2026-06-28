from ldap3 import Server, Connection, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

WELL_KNOWN_SIDS = {
    'S-1-1-0': 'Everyone',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'Local System',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
}


def connect_ldap(username, password, domain, dc_ip, use_sspi=False, hash_ntlm=None):
    try:
        server = Server(dc_ip, get_info=ALL)
        
        if use_sspi:
            # En Windows esto usará el contexto actual
            conn = Connection(server, authentication=NTLM, auto_bind=True)
        else:
            if hash_ntlm:
                if ":" not in hash_ntlm:
                    # LM dummy + NT hash
                    password = f"aad3b435b51404eeaad3b435b51404ee:{hash_ntlm}"
                else:
                    password = hash_ntlm
                    
            user_dn = f"{domain}\\{username}" if username and "\\" not in username else username
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

        conn.request_security_descriptor = True
        return conn
    except Exception as e:
        print(f"[X] Error conectando LDAP: {e}")
        return None


def resolve_acl_bulk(conn, sid_list, search_base):
    resolved = {}
    unique_sids = [s for s in {s for s in sid_list if s}]
    if not unique_sids:
        return resolved

    chunk_size = 50
    for i in range(0, len(unique_sids), chunk_size):
        chunk = unique_sids[i:i + chunk_size]
        or_filter = "(|" + "".join([f"(objectSid={sid})" for sid in chunk]) + ")"
        try:
            conn.search(
                search_base=search_base,
                search_filter=or_filter,
                attributes=["objectSid", "sAMAccountName", "cn"],
            )
            for entry in conn.entries:
                try:
                    sid_val = str(entry["objectSid"].value)
                except Exception:
                    continue
                name = None
                try:
                    name = entry["sAMAccountName"].value
                except Exception:
                    name = None
                if not name:
                    try:
                        name = entry["cn"].value
                    except Exception:
                        name = None
                if sid_val and name:
                    resolved[sid_val] = name
        except Exception:
            pass

    for sid in unique_sids:
        if sid not in resolved:
            name = WELL_KNOWN_SIDS.get(sid, sid)
            trust = resolve_group_membership(sid, conn, search_base)
            resolved[sid] = f"{name} | {trust}"
        else:
            name = resolved[sid]
            trust = resolve_group_membership(sid, conn, search_base)
            resolved[sid] = f"{name} | {trust}"
            
    return resolved


_ADMIN_GROUPS = {
    "domain admins", "enterprise admins", "schema admins", 
    "administrators", "builtin\\administrators", "account operators",
    "backup operators", "server operators", "print operators"
}

_GROUP_CACHE = {}

def resolve_group_membership(sid, conn, search_base, max_depth=5):
    """
    Busca recursivamente si un SID pertenece a un grupo administrativo.
    Retorna "TRUSTED" si pertenece a un grupo admin, "LOW_TRUST" si no,
    o "UNKNOWN_SID" si no existe.
    """
    if not sid:
        return "UNKNOWN_SID"

    if sid in _GROUP_CACHE:
        return _GROUP_CACHE[sid]

    # Resolución inicial
    try:
        conn.search(search_base, f"(objectSid={sid})", attributes=["sAMAccountName", "memberOf"])
        if not conn.entries:
            _GROUP_CACHE[sid] = "UNKNOWN_SID"
            return "UNKNOWN_SID"
        
        entry = conn.entries[0]
        name = getattr(entry, "sAMAccountName", None)
        if name and name.value.lower() in _ADMIN_GROUPS:
            _GROUP_CACHE[sid] = "TRUSTED"
            return "TRUSTED"

        # Check membership
        visited = set()
        queue = []
        if "memberOf" in entry and entry.memberOf:
            queue.extend([(dn, 1) for dn in entry.memberOf.values])

        while queue:
            current_dn, depth = queue.pop(0)
            if current_dn in visited or depth > max_depth:
                continue
            visited.add(current_dn)
            
            # Buscar el grupo por DN
            conn.search(current_dn, "(objectClass=group)", attributes=["sAMAccountName", "memberOf"], search_scope="BASE")
            if conn.entries:
                g_entry = conn.entries[0]
                g_name = getattr(g_entry, "sAMAccountName", None)
                if g_name and g_name.value.lower() in _ADMIN_GROUPS:
                    _GROUP_CACHE[sid] = "TRUSTED"
                    return "TRUSTED"
                
                if "memberOf" in g_entry and g_entry.memberOf and depth < max_depth:
                    queue.extend([(dn, depth + 1) for dn in g_entry.memberOf.values])

        _GROUP_CACHE[sid] = "LOW_TRUST"
        return "LOW_TRUST"
    except Exception as e:
        # En caso de error, no podemos determinar si es admin. Lo marcamos UNKNOWN.
        _GROUP_CACHE[sid] = "UNKNOWN_SID"
        return "UNKNOWN_SID"


def enumerar_pki_objects(conn, base_dn):
    base_pki = f"CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    filt = "(|(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority)(cn=NTAuthCertificates)(objectClass=msPKI-Enterprise-Oid))"
    attrs = ["cn", "distinguishedName", "nTSecurityDescriptor", "msDS-OIDToGroupLink", "msPKI-CA-Flag", "msPKI-CA-Policy", "flags"]
    conn.request_security_descriptor = True
    sdctl = security_descriptor_control(sdflags=0x07)
    try:
        conn.search(base_pki, filt, attributes=attrs, controls=sdctl)
    except Exception as e:
        if "invalid attribute type" in str(e).lower():
            if "msPKI-CA-Flag" in attrs: attrs.remove("msPKI-CA-Flag")
            if "msPKI-CA-Policy" in attrs: attrs.remove("msPKI-CA-Policy")
            conn.search(base_pki, filt, attributes=attrs, controls=sdctl)
        else:
            raise
    resultados = []
    for entry in conn.entries:
        raw_acl = None
        if "nTSecurityDescriptor" in entry and entry["nTSecurityDescriptor"].raw_values:
            raw_acl = entry["nTSecurityDescriptor"].raw_values[0]
            
        ca_flag = 0
        if "msPKI-CA-Flag" in entry:
            try: ca_flag = int(entry["msPKI-CA-Flag"].value)
            except: pass
            
        ca_policy = ""
        if "msPKI-CA-Policy" in entry:
            try: ca_policy = entry["msPKI-CA-Policy"].value
            except: pass
            
        oid_to_group = ""
        if "msDS-OIDToGroupLink" in entry:
            try: oid_to_group = entry["msDS-OIDToGroupLink"].value
            except: pass
            
        flags = 0
        if "flags" in entry:
            try: flags = int(entry["flags"].value)
            except: pass

        resultados.append({
            "cn": entry.cn.value,
            "dn": entry.entry_dn,
            "objectClass": getattr(entry, "objectClass", []),
            "nTSecurityDescriptor": raw_acl,
            "msPKI-CA-Flag": ca_flag,
            "msPKI-CA-Policy": ca_policy,
            "msDS-OIDToGroupLink": oid_to_group,
            "flags": flags
        })
    return resultados

def enumerate_pki_objects_for_esc6(conn, base_dn, debug_flags: bool = False):
    objetos = []
    bases = [
        f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}",
        f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    ]
    attrs = [
        "cn",
        "displayName",
        "nTSecurityDescriptor",
        "msPKI-Enrollment-Flag",
        "serviceBindingInformation",
        "dNSHostName",
        "msPKI-CA-Flag",
        "msPKI-CA-Policy",
        "certificateTemplates"
    ]
    sdctl = security_descriptor_control(sdflags=0x07)

    for search_base in bases:
        try:
            conn.search(search_base, "(objectClass=*)", attributes=attrs, controls=sdctl)
        except Exception as e:
            if "invalid attribute type" in str(e).lower():
                print("️ msPKI-CA-Flag no disponible — ESC5/ESC11/ESC16 pueden tener cobertura reducida. ESC7 y ESC8 no afectados. Usar --deep-scan para confirmación via MS-RRP.")
                if "msPKI-CA-Flag" in attrs: attrs.remove("msPKI-CA-Flag")
                if "msPKI-CA-Policy" in attrs: attrs.remove("msPKI-CA-Policy")
                conn.search(search_base, "(objectClass=*)", attributes=attrs, controls=sdctl)
            else:
                raise
        try:
            for e in conn.entries:
                cn = e.cn.value
                display = e.displayName.value if "displayName" in e else cn
                raw_acl = None
                enroll_flags = 0
                service_bindings = []
                dns_host = None
                ca_flag = 0
                ca_policy = ""

                if "nTSecurityDescriptor" in e and getattr(e["nTSecurityDescriptor"], "raw_values", None):
                    raw_acl = e["nTSecurityDescriptor"].raw_values[0]
                elif getattr(e, "raw_attributes", None) and e.raw_attributes.get("nTSecurityDescriptor"):
                    raw_acl = e.raw_attributes["nTSecurityDescriptor"][0]

                if "msPKI-Enrollment-Flag" in e:
                    try:
                        enroll_flags = int(e["msPKI-Enrollment-Flag"].value)
                    except Exception:
                        enroll_flags = 0

                if "serviceBindingInformation" in e:
                    try:
                        service_bindings = list(getattr(e["serviceBindingInformation"], "values", []) or [])
                    except Exception:
                        service_bindings = []

                if "dNSHostName" in e:
                    try:
                        dns_host = e["dNSHostName"].value
                    except Exception:
                        dns_host = None
                        
                if "msPKI-CA-Flag" in e:
                    try: ca_flag = int(e["msPKI-CA-Flag"].value)
                    except: pass
                    
                if "msPKI-CA-Policy" in e:
                    try: ca_policy = e["msPKI-CA-Policy"].value
                    except: pass
                    
                certificate_templates = []
                if hasattr(e, "certificateTemplates") and e.certificateTemplates.values:
                    certificate_templates = [t.strip().lower() for t in e.certificateTemplates.values]

                if raw_acl:
                    objetos.append({
                        "name": cn,
                        "display": display,
                        "descriptor": raw_acl,
                        "enroll_flags": enroll_flags,
                        "service_bindings": service_bindings,
                        "dns_host": dns_host,
                        "certificate_templates": certificate_templates,
                    })
        except Exception as ex:
            print(f"️ Error enumerando en {search_base}: {ex}")

    if debug_flags and objetos:
        print("\n CHECKPOINT 6A — Validación de msPKI-Enrollment-Flag:")
        for o in objetos:
            if o.get("enroll_flags"):
                print(f"  • {o['name']:<30} → Flags: {o['enroll_flags']} (bin: {bin(o['enroll_flags'])})")
        print("--------------------------------------------------------\n")

    return objetos
