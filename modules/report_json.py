import json
import os
from datetime import datetime
from modules.reporting_metrics import compute_report_meta_global


# ─── Severity → L1-L5 taxonomy ───────────────────────────────────────────────

_SEVERITY_TO_LEVEL = {
    "Critical": "L5_AUTH_AUTHORITY",
    "High":     "L4_IDENTITY_MINTING",
    "Medium":   "L2_ARBITRARY_USER",
    "Low":      "L1_WEAK_AUTH",
    "Info":     "L1_WEAK_AUTH",
}

_EXPLOITABILITY_LEVEL_OVERRIDE = {
    # If exploitable now AND High → promote to L3
    ("EXPLOITABLE_NOW", "High"):     "L3_PRIVILEGED_AUTH",
    ("EXPLOITABLE_NOW", "Critical"): "L5_AUTH_AUTHORITY",
}

def _severity_to_level(severidad: str, exploitability_status: str = "") -> str:
    """Map finding severity + exploitability context → L1–L5 taxonomy level."""
    key = (exploitability_status or "", severidad or "")
    if key in _EXPLOITABILITY_LEVEL_OVERRIDE:
        return _EXPLOITABILITY_LEVEL_OVERRIDE[key]
    return _SEVERITY_TO_LEVEL.get(severidad or "", "L1_WEAK_AUTH")


# ─── DDCC block builder ───────────────────────────────────────────────────────

def _ddcc_resultado(ddcc_report) -> str:
    """Distinguish SAFE_ANALYZED / SAFE_NO_DATA / NEAR_MISS / COMPROMISED."""
    if ddcc_report is None:
        return "SAFE_NO_DATA"

    is_comp = bool(getattr(ddcc_report, "is_compromisable", False))
    if is_comp:
        return "COMPROMISED"

    det_paths = getattr(ddcc_report, "deterministic_critical_paths", []) or []
    risk_paths = getattr(ddcc_report, "non_deterministic_risk_paths", []) or []

    if risk_paths:
        return "NEAR_MISS"

    # SAFE — but did we actually have data?
    summary = getattr(ddcc_report, "evaluation_summary", None)
    eff_enroll = int(getattr(summary, "templates_with_effective_enroll_count", 0) or 0) if summary else 0
    if eff_enroll == 0:
        return "SAFE_NO_DATA"

    return "SAFE_ANALYZED"


def _build_ddcc_block(ddcc_report) -> dict:
    """Serialize DomainCompromiseReport into the compact DDCC block for the main JSON."""
    resultado = _ddcc_resultado(ddcc_report)

    if ddcc_report is None:
        return {
            "resultado": "SAFE_NO_DATA",
            "is_compromisable": False,
            "razon": "DDCC engine did not run or returned no data.",
            "confidence_level": "LOW",
            "evaluation_summary": {},
            "paths_encontrados": [],
            "near_misses": [],
            "root_cause_analysis": ["No DDCC data available — enroll_principals may be empty or engine was not called."],
            "condicion_faltante": "ddcc_report is None",
        }

    det_paths = getattr(ddcc_report, "deterministic_critical_paths", []) or []
    risk_paths = getattr(ddcc_report, "non_deterministic_risk_paths", []) or []
    near_misses = getattr(ddcc_report, "near_misses", None)
    if near_misses is None:
        near_misses = getattr(ddcc_report, "near_miss_paths", []) or []

    summary_obj = getattr(ddcc_report, "evaluation_summary", None)
    eval_summary = {}
    if summary_obj:
        eval_summary = {
            "sources_used": list(getattr(summary_obj, "sources_used", []) or []),
            "total_templates_evaluated": int(getattr(summary_obj, "total_templates_evaluated", 0) or 0),
            "published_templates_count": int(getattr(summary_obj, "published_templates_count", 0) or 0),
            "templates_with_effective_enroll_count": int(getattr(summary_obj, "templates_with_effective_enroll_count", 0) or 0),
            "templates_with_low_trust_intersection_count": int(getattr(summary_obj, "templates_with_low_trust_intersection_count", 0) or 0),
            "discarded_not_published": int(getattr(summary_obj, "discarded_not_published", 0) or 0),
            "discarded_no_enroll_principals": int(getattr(summary_obj, "discarded_no_enroll_principals", 0) or 0),
            "discarded_no_low_trust_intersection": int(getattr(summary_obj, "discarded_no_low_trust_intersection", 0) or 0),
            "discarded_manager_approval": int(getattr(summary_obj, "discarded_manager_approval", 0) or 0),
            "discarded_authorized_signatures": int(getattr(summary_obj, "discarded_authorized_signatures", 0) or 0),
            "total_edges_generated": int(getattr(summary_obj, "total_edges_generated", 0) or 0),
            "deterministic_edges_created": int(getattr(summary_obj, "deterministic_edges_created", 0) or 0),
            "risk_edges_created": int(getattr(summary_obj, "risk_edges_created", 0) or 0),
        }

    def _serialize_path(path) -> dict:
        edges_out = []
        for edge in (getattr(path, "edges", []) or []):
            outcome = getattr(edge, "outcome", None)
            edges_out.append({
                "source": getattr(edge, "source_principal", ""),
                "edge_type": getattr(edge.edge_type, "name", str(edge.edge_type)) if hasattr(edge, "edge_type") else "ENROLL",
                "template": getattr(edge, "template_name", ""),
                "capability": getattr(edge.capability, "name", str(edge.capability)) if hasattr(edge, "capability") else "",
                "target": getattr(outcome, "target_identity", None) if outcome else None,
                "severity": getattr(outcome.severity, "name", str(outcome.severity)) if (outcome and hasattr(outcome, "severity")) else None,
                "level_l1_l5": getattr(outcome.severity, "name", None) if (outcome and hasattr(outcome, "severity")) else None,
            })
        return {
            "description": getattr(path, "description", ""),
            "length": len(edges_out),
            "is_deterministic": bool(getattr(path, "is_deterministic", True)),
            "confidence": getattr(path, "confidence", "unknown"),
            "edges": edges_out,
        }

    def _serialize_near_miss(nm) -> dict:
        return {
            "template_name": getattr(nm, "template_name", ""),
            "published": bool(getattr(nm, "published", False)),
            "effective_enroll_principals": list(getattr(nm, "effective_enroll_principals", []) or []),
            "low_trust_intersection": bool(getattr(nm, "low_trust_intersection", False)),
            "friction_factors": list(getattr(nm, "friction_factors", []) or []),
            "severity": str(getattr(nm, "severity", "")),
        }

    # Condition que falta para que sea SAFE
    condicion_faltante = ""
    if resultado in ("SAFE_NO_DATA", "SAFE_ANALYZED"):
        eff_enroll = eval_summary.get("templates_with_effective_enroll_count", 0)
        low_trust_intersect = eval_summary.get("templates_with_low_trust_intersection_count", 0)
        if eff_enroll == 0:
            condicion_faltante = "templates_with_effective_enroll_count=0 (no publishe templates with enroll principals reachable)"
        elif low_trust_intersect == 0:
            condicion_faltante = "templates_with_low_trust_intersection_count=0 (no low-trust groups have Enroll/Autoenroll on published templates)"
        else:
            condicion_faltante = "No L3+ severity capability found on templates reachable by low-trust principals"

    return {
        "resultado": resultado,
        "is_compromisable": bool(getattr(ddcc_report, "is_compromisable", False)),
        "razon": (getattr(ddcc_report, "evidence", []) or ["(no evidence)"])[0],
        "confidence_level": str(getattr(ddcc_report, "confidence_level", "UNKNOWN") or "UNKNOWN"),
        "evaluation_summary": eval_summary,
        "paths_encontrados": [_serialize_path(p) for p in det_paths],
        "near_misses": [_serialize_near_miss(nm) for nm in near_misses],
        "root_cause_analysis": list(getattr(ddcc_report, "root_cause_analysis", []) or []),
        "condicion_faltante": condicion_faltante,
    }


# ─── PKI Graph serializer ─────────────────────────────────────────────────────

def _serialize_graph(graph) -> dict:
    """Serialize an IdentityAttackGraph into {nodes, edges} for JSON output."""
    if graph is None:
        return {"nodes": [], "edges": []}
    try:
        nodes = [{"id": n} for n in sorted(graph.nodes)]
        edges = []
        for src, edge_list in graph._adj_list.items():
            for edge in edge_list:
                outcome = getattr(edge, "outcome", None)
                edges.append({
                    "source": getattr(edge, "source_principal", src),
                    "edge_type": getattr(edge.edge_type, "name", str(edge.edge_type)) if hasattr(edge, "edge_type") else "ENROLL",
                    "template": getattr(edge, "template_name", ""),
                    "capability": getattr(edge.capability, "name", str(edge.capability)) if hasattr(edge, "capability") else "",
                    "target": getattr(outcome, "target_identity", None) if outcome else None,
                    "severity": getattr(outcome.severity, "name", str(outcome.severity)) if (outcome and hasattr(outcome, "severity")) else None,
                    "level_l1_l5": getattr(outcome.severity, "name", None) if (outcome and hasattr(outcome, "severity")) else None,
                    "is_deterministic": True,
                })
        return {"nodes": nodes, "edges": edges}
    except Exception:
        return {"nodes": [], "edges": []}


def _build_pki_graph_block(ddcc_report) -> dict:
    """Merge deterministic + risk graphs into a single pki_graph block."""
    if ddcc_report is None:
        return {"nodes": [], "edges": [], "deterministic_nodes": [], "risk_nodes": []}

    det_graph = getattr(ddcc_report, "deterministic_graph", None)
    risk_graph = getattr(ddcc_report, "risk_graph", None)

    det_data = _serialize_graph(det_graph)
    risk_data = _serialize_graph(risk_graph)

    # Mark risk edges
    for e in risk_data["edges"]:
        e["is_deterministic"] = False

    all_nodes_ids = set(n["id"] for n in det_data["nodes"]) | set(n["id"] for n in risk_data["nodes"])
    all_edges = det_data["edges"] + risk_data["edges"]

    return {
        "nodes": [{"id": n} for n in sorted(all_nodes_ids)],
        "edges": all_edges,
        "deterministic_nodes": det_data["nodes"],
        "risk_nodes": risk_data["nodes"],
    }

# ─── Remediation Playbook ─────────────────────────────────────────────────────

def _get_remediation_playbook(esc_name: str, target_name: str) -> dict:
    """Returns the remediation playbook for a given ESC and target."""
    playbooks = {
        "ESC1": {
            "commands": [
                f"certutil -dstemplate {target_name} msPKI-Certificate-Name-Flag -0x1",
                f"$t = [ADSI]\"LDAP://CN={target_name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...\"",
                "$t.Put(\"msPKI-Certificate-Name-Flag\", <valor_sin_flag>)",
                "$t.SetInfo()"
            ],
            "time_estimate": "10 minutos",
            "risk": "Bajo (Cambio a nivel de ADDS)",
            "refs": ["https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/c4c77c61-0b5c-4235-9856-11b0e513a968"]
        },
        "ESC3": {
            "commands": [
                "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                "Configurar 'Enrollment Agent Restrictions' en certsrv.msc"
            ],
            "time_estimate": "30 minutos",
            "risk": "Medio (Requiere reinicio de servicio CA)",
            "refs": ["https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-cert-trust-prereqs"]
        },
        "ESC4": {
            "commands": [
                f"$acl = Get-Acl \"AD:CN={target_name},CN=Certificate Templates,...\"",
                "$acl.RemoveAccessRule(<ACE_problemática>)",
                f"Set-Acl -AclObject $acl \"AD:CN={target_name},...\""
            ],
            "time_estimate": "15 minutos",
            "risk": "Bajo (Cambio de ACL en AD)",
            "refs": []
        },
        "ESC6": {
            "commands": [
                "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                "net stop certsvc && net start certsvc"
            ],
            "time_estimate": "10 minutos",
            "risk": "Medio (Reinicio de servicio CA)",
            "refs": ["https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"]
        },
        "ESC7": {
            "commands": [
                "Remover privilegios ManageCA/ManageCertificates desde certsrv.msc -> Properties -> Security"
            ],
            "time_estimate": "10 minutos",
            "risk": "Bajo",
            "refs": []
        },
        "ESC8": {
            "commands": [
                "certutil -setreg -f auth\\provider\\PassportAuth+RequireSSL 1",
                "Set-WebConfigurationProperty -filter /system.webServer/security/authentication/windowsAuthentication -name enabled -value false (para /certsrv)"
            ],
            "time_estimate": "30 minutos",
            "risk": "Medio (Cambios en IIS / Web Enrollment)",
            "refs": ["https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429"]
        },
        "ESC9": {
            "commands": [
                f"certutil -dstemplate {target_name} msPKI-Enrollment-Flag -0x80000"
            ],
            "time_estimate": "10 minutos",
            "risk": "Bajo",
            "refs": []
        },
        "ESC11": {
            "commands": [
                "certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
                "net stop certsvc && net start certsvc"
            ],
            "time_estimate": "15 minutos",
            "risk": "Medio",
            "refs": []
        },
        "ESC13": {
            "commands": [
                "Remover el atributo msDS-OIDToGroupLink del objeto OID afectado"
            ],
            "time_estimate": "10 minutos",
            "risk": "Bajo",
            "refs": []
        },
        "ESC15": {
            "commands": [
                "Aplicar parche CVE-2024-49019 (Noviembre 2024)",
                "Restringir permisos de Enrollment en plantillas versión 1"
            ],
            "time_estimate": "Variable",
            "risk": "Alto (Aplicación de parches en DCs/CAs)",
            "refs": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019"]
        },
        "ESC16": {
            "commands": [
                "certutil -setreg CA\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\\DisableExtensionList \"\"",
                "net stop certsvc && net start certsvc"
            ],
            "time_estimate": "10 minutos",
            "risk": "Medio",
            "refs": []
        },
        "CERTIFRIED": {
            "commands": [
                "Set-ADObject -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}",
                "Aplicar parche KB5014754 en todos los DCs"
            ],
            "time_estimate": "Variable",
            "risk": "Alto",
            "refs": ["https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"]
        },
        "SHADOW_CREDENTIALS": {
            "commands": [
                "Auditar y limpiar msDS-KeyCredentialLink en cuentas privilegiadas",
                "Restringir GenericWrite sobre cuentas sensibles"
            ],
            "time_estimate": "Alto",
            "risk": "Bajo",
            "refs": []
        }
    }
    return playbooks.get(esc_name)

# ─── Main export function ─────────────────────────────────────────────────────

def exportar_resultado(
    resultados,
    output_dir: str | None = None,
    ddcc_report=None,
    evidence_level: str = "summary",
    emit_meta_file: bool = True,
    json_wrapper: bool = False,
):
    if not resultados:
        print("️ No hay resultados para exportar.")
        return

    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    archivo_salida = f"ESCepcion_Reporte_{fecha}.json"

    export_data = []

    report_meta = compute_report_meta_global(resultados=resultados, ddcc_report=ddcc_report, evidence_level=evidence_level)
    for r in resultados:
        exploitability_status = r.get("exploitability_status")
        exploitability_reasons = r.get("exploitability_reasons", [])
        risk_score = int(r.get("risk_score") or 0)

        item = {
            "plantilla": r.get("cn"),
            "displayName": r.get("displayName"),
            "ekus": r.get("ekus", []),
            "enroll_principals": r.get("enroll_principals", []),
            "is_published": r.get("is_published"),
            "low_trust_reachable": r.get("low_trust_reachable"),
            "exploitability_status": exploitability_status,
            "exploitability_reasons": exploitability_reasons,
            "risk_score": risk_score,
            "is_default_template": r.get("is_default_template", "unknown"),
            "report_meta": report_meta,
            "schema_version": r.get("schema_version"),
            "flags": r.get("flags"),
        }
        
        for esc_k in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6_Template", "ESC9", "ESC13", "ESC15"]:
            base_key = esc_k.replace("_Template", "")
            val = r.get(base_key)
            if not val or val == "SAFE" or val is False:
                item[esc_k] = None
            elif hasattr(val, "to_dict"):
                item[esc_k] = val.to_dict()
            elif isinstance(val, dict):
                item[esc_k] = val
            else:
                item[esc_k] = {
                    "estado": r.get(base_key),
                    "razon": r.get(f"{base_key}_Reason"),
                    "severidad": r.get(f"{base_key}_Severidad"),
                    "level_l1_l5": _severity_to_level(r.get(f"{base_key}_Severidad"), exploitability_status)
                }
                if base_key == "ESC5":
                    item[esc_k]["detalles"] = r.get("ESC5_Details", [])
                    item[esc_k]["matriz_riesgo"] = r.get("ESC5_RiskMatrix", {})

        esc6_ca = r.get("ESC6_CA")
        if not esc6_ca or esc6_ca == "SAFE" or esc6_ca is False:
            item["ESC6_CA"] = None
        elif hasattr(esc6_ca, "to_dict"):
            item["ESC6_CA"] = esc6_ca.to_dict()
        elif isinstance(esc6_ca, dict):
            item["ESC6_CA"] = esc6_ca
        else:
            item["ESC6_CA"] = {
                "estado": r.get("ESC6_CA"),
                "razon": r.get("ESC6_CA_Reason"),
                "severidad": r.get("ESC6_CA_Severidad"),
                "level_l1_l5": _severity_to_level(r.get("ESC6_CA_Severidad"), ""),
                "detalles": r.get("ESC6_CA_Details", []),
                "matriz_riesgo": r.get("ESC6_CA_RiskMatrix", {})
            }

        sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        findings = []
        for esc_name in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC9", "ESC13", "ESC15"]:
            val = r.get(esc_name)
            if not val or val == "SAFE" or val is False:
                continue
            
            if hasattr(val, "to_dict"):
                val = val.to_dict()

            if isinstance(val, dict):
                if val.get("status") in ["SAFE", "NOT_SCANNED", False]:
                    continue
                estado = val.get("status")
                sev = val.get("severity", "Info")
                razon = val.get("reason", "")
            else:
                estado = val
                sev = r.get(f"{esc_name}_Severidad") or "Info"
                razon = r.get(f"{esc_name}_Reason") or ""

            finding_obj = {
                "esc": esc_name,
                "estado": estado,
                "severidad": sev,
                "level_l1_l5": _severity_to_level(sev, exploitability_status),
                "razon": razon,
                "exploitability_status": exploitability_status,
                "exploitability_reasons": exploitability_reasons,
                "risk_score": risk_score,
            }

            if esc_name == "ESC6":
                finding_obj["confirmation_gap"] = {
                    "type": "REGISTRY_REQUIRED",
                    "description": "ESC6 requiere lectura del registro del servidor CA para confirmación absoluta del flag EDITF_ATTRIBUTESUBJECTALTNAME2. Esta herramienta detecta la condición via LDAP (plantilla con SAN habilitado + Client Auth EKU + publicada). Para confirmar manualmente ejecutar en el servidor CA: certutil -getreg policy\\EditFlags",
                    "manual_command": "certutil -getreg policy\\EditFlags",
                    "status_without_confirmation": "POTENTIAL",
                    "status_if_confirmed": "EXPLOITABLE"
                }

            if esc_name == "ESC3":
                finding_obj["template_a"] = r.get("ESC3_TemplateA") or r.get("cn")
                finding_obj["template_b"] = r.get("ESC3_TemplateB") or "<Template_B_Opcional>"
                finding_obj["missing_prereq"] = razon if estado == "POTENTIAL" else ""
                finding_obj["attack_chain"] = [
                    f"1. certipy req -u user -p pass -ca CA -template {finding_obj['template_a']}",
                    f"2. certipy req -u user -p pass -ca CA -template {finding_obj['template_b']} -on-behalf-of domain\\admin -pfx agent.pfx"
                ]

            if r.get(esc_name) in ["EXPLOITABLE", "NEAR_MISS"]:
                playbook = _get_remediation_playbook(esc_name, r.get("cn") or r.get("displayName") or "TemplateName")
                if playbook:
                    finding_obj["remediation_playbook"] = playbook

            findings.append(finding_obj)

        findings_sorted = sorted(
            findings,
            key=lambda f: (-int(f.get("risk_score") or 0), -sev_order.get(f.get("severidad") or "Info", 0), f.get("esc") or ""),
        )
        item["findings"] = findings_sorted

        esc6_list = r.get("ESC6_CA_Level", [])
        esc7_list = r.get("ESC7_CA_Level", [])
        esc8_list = r.get("ESC8_CA_Level", [])

        item["ESC6_CA_List"] = []
        for ca in esc6_list:
            item["ESC6_CA_List"].append({
                "nombre_objeto": ca.get("nombre_objeto"),
                "estado": ca.get("ESC6"),
                "razon": ca.get("ESC6_Reason"),
                "severidad": ca.get("ESC6_Severidad"),
                "detalles": ca.get("ESC6_Details", []),
                "matriz_riesgo": ca.get("ESC6_RiskMatrix", {}),
                "notas": ca.get("ESC6_ValidationNotes", []),
            })

        item["ESC7_CA"] = []
        for ca in esc7_list:
            item["ESC7_CA"].append({
                "ca_name": ca.get("ca_name"),
                "estado": ca.get("ESC7_CA"),
                "razon": ca.get("ESC7_CA_Reason"),
                "severidad": ca.get("ESC7_CA_Severidad"),
                "detalles": ca.get("ESC7_CA_Details", []),
                "matriz_riesgo": ca.get("ESC7_CA_RiskMatrix", {}),
            })

        item["ESC8_CA"] = []
        for svc in esc8_list:
            item["ESC8_CA"].append({
                "service_name": svc.get("service_name"),
                "estado": svc.get("ESC8_CA"),
                "razon": svc.get("ESC8_CA_Reason"),
                "severidad": svc.get("ESC8_CA_Severidad"),
                "detalles": svc.get("ESC8_CA_Details", []),
                "probe": svc.get("ESC8_CA_Probe", {}),
                "matriz_riesgo": svc.get("ESC8_CA_RiskMatrix", {}),
                "ESC11_CA": svc.get("ESC11_CA"),
                "ESC11_CA_Reason": svc.get("ESC11_CA_Reason"),
                "ESC11_CA_Severidad": svc.get("ESC11_CA_Severidad"),
                "ESC16_CA": svc.get("ESC16_CA"),
                "ESC16_CA_Reason": svc.get("ESC16_CA_Reason"),
                "ESC16_CA_Severidad": svc.get("ESC16_CA_Severidad"),
            })

        item["riesgos"] = r.get("riesgos", [])
        export_data.append(item)

    # Always build DDCC block and PKI graph — regardless of json_wrapper flag
    ddcc_block = _build_ddcc_block(ddcc_report)
    pki_graph_block = _build_pki_graph_block(ddcc_report)

    base_out = output_dir or os.getcwd()
    ruta_salida = os.path.join(base_out, archivo_salida)

    # Always emit as wrapper object (breaking from old flat array).
    # json_wrapper flag kept for backward-compat signaling but wrapper is now default.
    esc5_global = resultados[0].get("ESC5_Global", []) if resultados else []
    esc14_global = resultados[0].get("ESC14_Global", []) if resultados else []
    esc10_global = resultados[0].get("ESC10_Global", {}) if resultados else {}
    esc12_global = resultados[0].get("ESC12_Global", []) if resultados else []
    certifried_global = resultados[0].get("CERTIFRIED_Global", {}) if resultados else {}
    shadow_global = resultados[0].get("SHADOW_CREDENTIALS_Global", []) if resultados else []
    hybrid_global = resultados[0].get("HYBRID_Global", {}) if resultados else {}
    combo_chains_global = resultados[0].get("Combo_Chains_Global", []) if resultados else []
    bloodhound_path_global = resultados[0].get("BloodHound_Path", "") if resultados else ""

    payload = {
        "report_meta_global": report_meta,
        "ddcc": ddcc_block,
        "pki_graph": pki_graph_block,
        "global_escs": {
            "ESC5": esc5_global,
            "ESC10": esc10_global,
            "ESC12": esc12_global,
            "ESC14": esc14_global,
            "CERTIFRIED": certifried_global,
            "SHADOW_CREDENTIALS": shadow_global,
            "HYBRID_ENVIRONMENT": hybrid_global
        },
        "attack_chains": combo_chains_global,
        "bloodhound_path": bloodhound_path_global,
        "templates": export_data,
    }

    with open(ruta_salida, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)

    if emit_meta_file:
        meta_path = os.path.join(base_out, "ESCepcion_Reporte_meta.json")
        try:
            with open(meta_path, "w", encoding="utf-8") as mf:
                json.dump({"report_meta_global": report_meta, "ddcc_summary": {
                    "resultado": ddcc_block.get("resultado"),
                    "is_compromisable": ddcc_block.get("is_compromisable"),
                    "confidence_level": ddcc_block.get("confidence_level"),
                }}, mf, indent=4, ensure_ascii=False)
        except Exception:
            pass

    print(f"\n[OK] Reporte exportado exitosamente: {ruta_salida}")
