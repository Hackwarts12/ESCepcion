from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap3 import ALL_ATTRIBUTES
import struct

COMMON_ENROLL_SIDS = {
    "S-1-5-11": "Authenticated Users",
    "S-1-5-21": "Domain Users",
    "S-1-5-32-545": "Users"
}

ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
ADS_RIGHT_DS_WRITE_PROP = 0x20
ADS_RIGHT_DS_READ_PROP = 0x10
ADS_RIGHT_DS_CREATE_CHILD = 0x1
ADS_RIGHT_DS_ENROLL = 0x00000010
ADS_RIGHT_DS_AUTOENROLL = 0x00000020


def verificar_publicacion_y_permiso(conn, base_dn, template_name):
    try:
        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
        conn.search(search_base, "(objectClass=pKIEnrollmentService)", attributes=["certificateTemplates", "cn"])

        is_published = False
        for ca in conn.entries:
            templates = [t.lower() for t in ca["certificateTemplates"].values] if "certificateTemplates" in ca else []
            if template_name.lower() in templates:
                is_published = True
                break

        is_accessible = False

        if is_published:
            template_dn = f"CN={escape_filter_chars(template_name)},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
            sdctl = security_descriptor_control(sdflags=0x04)
            conn.search(template_dn, "(objectClass=pKICertificateTemplate)", attributes=["nTSecurityDescriptor"], controls=sdctl)

            if conn.entries:
                raw_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
                is_accessible = analizar_permisos_enroll(raw_sd)

        return (is_published, is_accessible)

    except Exception as e:
        print(f"[!] Error verificando publicación/permisos de '{template_name}': {e}")
        return (False, False)


def analizar_permisos_enroll(raw_sd):
    try:
        data = memoryview(raw_sd)
        offset_dacl = struct.unpack_from("<H", data[2:4])[0]
        if not offset_dacl:
            return False

        acl_size = struct.unpack_from("<H", data[offset_dacl + 2:offset_dacl + 4])[0]
        ace_count = struct.unpack_from("<H", data[offset_dacl + 4:offset_dacl + 6])[0]
        pos = offset_dacl + 8

        for _ in range(ace_count):
            ace_type = data[pos]
            ace_flags = data[pos + 1]
            ace_size = struct.unpack_from("<H", data[pos + 2:pos + 4])[0]
            access_mask = struct.unpack_from("<I", data[pos + 4:pos + 8])[0]

            if access_mask & (ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_ENROLL | ADS_RIGHT_DS_AUTOENROLL):
                sid_start = pos + 12
                sid_revision = data[sid_start]
                sid_subcount = data[sid_start + 1]
                sid_auth = struct.unpack(">Q", b"\x00\x00" + data[sid_start + 2:sid_start + 8])[0]
                sid_parts = [struct.unpack_from("<I", data[sid_start + 8 + i * 4:sid_start + 12 + i * 4])[0] for i in range(sid_subcount)]
                sid = "S-1-" + str(sid_revision) + "-" + "-".join([str(sid_auth)] + [str(x) for x in sid_parts])

                if sid.startswith("S-1-5-21"):
                    return True
                if sid in COMMON_ENROLL_SIDS:
                    return True

            pos += ace_size

        return False
    except Exception:
        return False


def extraer_principales_enroll(raw_sd, resolved_acl=None):
    resolved_acl = resolved_acl or {}
    principals = []
    try:
        data = memoryview(raw_sd)
        offset_dacl = struct.unpack_from("<H", data[2:4])[0]
        if not offset_dacl:
            return principals

        ace_count = struct.unpack_from("<H", data[offset_dacl + 4:offset_dacl + 6])[0]
        pos = offset_dacl + 8

        for _ in range(ace_count):
            ace_type = data[pos]
            ace_size = struct.unpack_from("<H", data[pos + 2:pos + 4])[0]

            # BUG FIX: Skip DENY ACEs (ace_type != 0). Only ACCESS_ALLOWED_ACE_TYPE (0x00)
            # should contribute effective enroll principals. Previously DENY ACEs for
            # Authenticated Users/Domain Users were being included, giving false positives.
            if ace_type != 0:
                pos += ace_size
                continue

            access_mask = struct.unpack_from("<I", data[pos + 4:pos + 8])[0]

            rights = []
            if access_mask & ADS_RIGHT_DS_ENROLL:
                rights.append("Enroll")
            if access_mask & ADS_RIGHT_DS_AUTOENROLL:
                rights.append("Autoenroll")
            if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
                rights.append("ControlAccess")

            if rights:
                sid_start = pos + 12
                sid_revision = data[sid_start]
                sid_subcount = data[sid_start + 1]
                sid_auth = struct.unpack(">Q", b"\x00\x00" + data[sid_start + 2:sid_start + 8])[0]
                sid_parts = [struct.unpack_from("<I", data[sid_start + 8 + i * 4:sid_start + 12 + i * 4])[0] for i in range(sid_subcount)]
                sid = "S-1-" + str(sid_revision) + "-" + "-".join([str(sid_auth)] + [str(x) for x in sid_parts])

                principals.append({
                    "sid": sid,
                    "name": resolved_acl.get(sid) or COMMON_ENROLL_SIDS.get(sid) or sid,
                    "rights": rights,
                    "ace_type": int(ace_type),
                })

            pos += ace_size

        dedup = {}
        for p in principals:
            key = (p.get("sid"), ",".join(sorted(p.get("rights") or [])))
            dedup[key] = p
        return list(dedup.values())
    except Exception:
        return principals
