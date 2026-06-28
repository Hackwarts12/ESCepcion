from base64 import b64encode
from ldap3 import SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from modules.esc_validator import detectar_escs
from modules.esc4_checker import check_ESC4
from modules.publish_validator import extraer_principales_enroll
from colorama import Fore, Style
from modules.analysis.ddcc import LOW_TRUST_PRINCIPALS
from modules.esc_validator import ENROLL_PEND_ALL_REQUESTS


def obtener_plantillas_publicadas(conn, base_dn):
    search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    search_filter = "(objectClass=pKIEnrollmentService)"
    attributes = ["certificateTemplates"]

    try:
        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes=attributes)
    except Exception as e:
        print(f"{Fore.YELLOW}️ Error al obtener plantillas publicadas: {e}{Style.RESET_ALL}")
        return []

    publicadas = set()
    for entry in conn.entries:
        if hasattr(entry, "certificateTemplates") and entry.certificateTemplates.values:
            for tpl in entry.certificateTemplates.values:
                publicadas.add(tpl.strip().lower())
    return list(publicadas)


def analizar_plantillas(conn, base_dn, resolved_acl, pki_objects=None, plantillas_publicadas=None):
    if not plantillas_publicadas:
        plantillas_publicadas = obtener_plantillas_publicadas(conn, base_dn)

    search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    search_filter = "(objectClass=pKICertificateTemplate)"
    attributes = [
        "cn", "displayName",
        "pKIExtendedKeyUsage",
        "msPKI-Certificate-Policy",
        "msPKI-Enrollment-Flag",
        "msPKI-Template-Schema-Version",
        "msPKI-Certificate-Name-Flag",
        "flags",
        "nTSecurityDescriptor"
    ]

    conn.request_security_descriptor = True
    sdctl = security_descriptor_control(sdflags=0x07)
    
    from utils.ldap_paginator import paginated_search
    all_entries = paginated_search(conn, search_base, search_filter, attributes, controls=sdctl)

    if not all_entries:
        print(f"{Fore.YELLOW}️ No se encontraron plantillas.{Style.RESET_ALL}")
        return []

    todos_los_resultados = []
    print(f"\n───────────────────────────────────────────────")
    print(f" Analizando {len(all_entries)} plantillas encontradas...\n")

    published_set = set([p.strip().lower() for p in (plantillas_publicadas or [])])

    default_template_names = {
        "user", "machine", "webserver", "domaincontroller", "domain controller",
        "kerberosauthentication", "smartcardlogon", "smartcard logon",
        "enrollmentagent", "enrollment agent",
        "subca", "ca", "ipsec", "efs", "administrator",
        "workstationauthentication", "computer", "router", "offline router",
    }

    for entry in all_entries:
        try:
            cn = entry.cn.value
            display = entry.displayName.value if "displayName" in entry else "N/A"
            ekus = entry["pKIExtendedKeyUsage"].values if "pKIExtendedKeyUsage" in entry else []
            policies = entry["msPKI-Certificate-Policy"].values if "msPKI-Certificate-Policy" in entry else []
            enroll_flag = entry["msPKI-Enrollment-Flag"].value if "msPKI-Enrollment-Flag" in entry else 0
            schema_version = entry["msPKI-Template-Schema-Version"].value if "msPKI-Template-Schema-Version" in entry else 0
            name_flag = entry["msPKI-Certificate-Name-Flag"].value if "msPKI-Certificate-Name-Flag" in entry else 0
            flags = entry["flags"].value if "flags" in entry else 0

            raw_acl = None
            if "nTSecurityDescriptor" in entry and entry["nTSecurityDescriptor"].raw_values:
                raw_acl = entry["nTSecurityDescriptor"].raw_values[0]
            elif hasattr(entry, "raw_attributes") and entry.raw_attributes.get("nTSecurityDescriptor"):
                raw_acl = entry.raw_attributes["nTSecurityDescriptor"][0]

            acl_b64 = b64encode(raw_acl).decode() if raw_acl else None

            enroll_principals = []
            if raw_acl:
                try:
                    enroll_principals = extraer_principales_enroll(raw_acl, resolved_acl=resolved_acl or {})
                except Exception:
                    enroll_principals = []

            data = {
                "cn": cn,
                "displayName": display,
                "ekus": ekus,
                "policies": policies,
                "enroll_flag": int(enroll_flag) if enroll_flag else 0,
                "schema_version": int(schema_version) if schema_version else 0,
                "flags": int(flags) if flags else 0,
                "cert_name_flag": int(name_flag) if name_flag else 0,
                "nTSecurityDescriptor_b64": acl_b64,
                "enroll_principals": enroll_principals,
            }

            cn_norm = (cn or "").strip().lower()
            display_norm = (display or "").strip().lower()
            is_published = cn_norm in published_set
            low_trust_reachable = False
            if enroll_principals:
                for p in enroll_principals:
                    p_name = (p.get("name") or "").strip()
                    if p_name in LOW_TRUST_PRINCIPALS:
                        low_trust_reachable = True
                        break

            friction = False
            friction_reasons = []
            if data["enroll_flag"] & ENROLL_PEND_ALL_REQUESTS:
                friction = True
                friction_reasons.append("Requires manager approval (PEND_ALL_REQUESTS)")
            if data.get("requires_manager_approval"):
                friction = True
                friction_reasons.append("Requires manager approval")
            if data.get("requires_agent_signature"):
                friction = True
                friction_reasons.append("Requires authorized signatures")

            exploitability_status = "EXPLOITABLE_NOW"
            exploitability_reasons = []
            if not is_published:
                exploitability_status = "NOT_EXPLOITABLE_NOT_PUBLISHED"
                exploitability_reasons.append("Template is not published on any Enrollment Service")
            elif not enroll_principals:
                exploitability_status = "NOT_EXPLOITABLE_NO_EFFECTIVE_ENROLL"
                exploitability_reasons.append("No effective Enroll/Autoenroll principals found")
            elif friction:
                exploitability_status = "NOT_EXPLOITABLE_FRICTION"
                exploitability_reasons.extend(friction_reasons)

            is_default_template = "unknown"
            if cn_norm in default_template_names or display_norm in default_template_names:
                is_default_template = True

            risk_score = 0
            if is_published:
                risk_score += 40
            if enroll_principals:
                risk_score += 10
            if low_trust_reachable:
                risk_score += 30
            if friction:
                risk_score -= 25
            else:
                risk_score += 20

            data["is_published"] = is_published
            data["low_trust_reachable"] = low_trust_reachable
            data["exploitability_status"] = exploitability_status
            data["exploitability_reasons"] = exploitability_reasons
            data["risk_score"] = int(risk_score)
            data["is_default_template"] = is_default_template

            escs = detectar_escs(data, resolved_acl or {}, pki_objects or [], plantillas_publicadas)
            data.update(escs)

            if raw_acl and not data.get("ESC4"):
                esc4_result, reason = check_ESC4(cn, raw_acl, resolved_acl or {})
                data["ESC4"] = esc4_result
                data["ESC4_Reason"] = reason

            riesgos = []
            for esc in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC9", "ESC13", "ESC15"]:
                if escs.get(esc) and escs.get(f"{esc}_Severidad"):
                    riesgos.append({
                        "esc": esc,
                        "nivel": escs.get(f"{esc}_Severidad")
                    })
            data["riesgos"] = riesgos

            vulns = []
            for esc in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC9", "ESC13", "ESC15"]:
                if escs.get(esc):
                    nivel = escs.get(f"{esc}_Severidad", "Info")
                    detalle = escs.get(f"{esc}_Reason", "")

                    if ("no publicada" in detalle.lower() or "sin permisos de inscripción efectivos" in detalle.lower()):
                        if cn.strip().lower() not in published_set:
                            nivel = "Info"

                    vulns.append({"esc": esc, "detalle": detalle, "nivel": nivel})

            if vulns:
                print(f"[{Fore.CYAN}{cn}{Style.RESET_ALL}] — ({display})")
                for v in vulns:
                    icon = (
                        "" if v["nivel"] == "High"
                        else "" if v["nivel"] == "Medium"
                        else "" if v["nivel"] == "Low"
                        else "ℹ"
                    )
                    color = (
                        Fore.RED if v["nivel"] == "High"
                        else Fore.YELLOW if v["nivel"] == "Medium"
                        else Fore.GREEN if v["nivel"] == "Low"
                        else Fore.CYAN
                    )
                    print(f"  {icon} {v['esc']} → {v['detalle']} → {color}{v['nivel']}{Style.RESET_ALL}")

                if enroll_principals:
                    max_show = 12
                    shown = 0
                    print(f"   Principals con Enroll/Autoenroll (preview):")
                    for p in enroll_principals:
                        if shown >= max_show:
                            break
                        try:
                            namep = p.get("name") or p.get("sid") or "N/A"
                            rights = ",".join(p.get("rights") or [])
                            print(f"     - {namep} ({rights})")
                            shown += 1
                        except Exception:
                            continue
                    if len(enroll_principals) > max_show:
                        print(f"     - ... +{len(enroll_principals) - max_show}")
                niveles = list(set([v['nivel'] for v in vulns]))
                print(f"   Riesgos globales: {', '.join(niveles)}\n")

            todos_los_resultados.append(data)

        except Exception as e:
            print(f"{Fore.YELLOW}️ Error procesando {entry.cn.value}: {e}{Style.RESET_ALL}")
            print("───────────────────────────────────────────────")

    print(f"{Fore.MAGENTA}───────────────────────────────────────────────{Style.RESET_ALL}")
    return todos_los_resultados
