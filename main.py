from getpass import getpass
import argparse
import os
from auth.ldap_conn import connect_ldap, resolve_acl_bulk, enumerar_pki_objects, enumerate_pki_objects_for_esc6
from modules.template_analyzer import analizar_plantillas, obtener_plantillas_publicadas
from modules.esc6_checker import analyze_ca_for_esc6
from modules.esc7_checker import analyze_ca_for_esc7
from modules.esc8_checker import analyze_enrollment_service_for_esc8
from utils.descriptor_parser import parse_security_descriptor
from utils.banner import print_banner
from ldap3.protocol.microsoft import security_descriptor_control
from modules.report_json import exportar_resultado
from colorama import Fore, Style
from modules.report_html import exportar_reporte_html
from modules.analysis.ddcc import is_domain_deterministically_compromisable
from modules.inference.consequence_engine import infer_template_capabilities
from modules.analysis.ddcc_report import generate_ddcc_json, generate_ddcc_html
from data.report_strings import SUSCEPTIBILITY_EXPLANATIONS
from modules.reporting_metrics import compute_report_meta_global


def run_scan(

    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    show_banner: bool = True,
    export_json: bool = True,
    export_html: bool = True,
    output_dir: str | None = None,
    use_sspi: bool = False,

    hash_ntlm: str = None,
    ddcc_sources: str = None,
    top_paths: int = 3,
    include_non_deterministic: bool = True,
    evidence_level: str = "summary",
    emit_meta_file: bool = True,
    json_wrapper: bool = False,
    deep_scan: bool = False,
    bloodhound: bool = False,
    diff_report: str = None,
):
    if show_banner:
        print_banner()

    base_dn = ",".join([f"DC={p}" for p in domain.split(".")])

    conn = connect_ldap(username, password, domain, dc_ip, use_sspi=use_sspi, hash_ntlm=hash_ntlm)
    if not conn:
        print(f"{Fore.RED}[X] Falló la conexión LDAP{Style.RESET_ALL}")
        return None

    print(f"{Fore.GREEN}[+] Conexión LDAP exitosa{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}────────────────────────────────────────────────────────────────")
    print(f" Dominio:       {Fore.WHITE}{domain}{Style.RESET_ALL}")
    print(f" Controlador:   {Fore.WHITE}{dc_ip}{Style.RESET_ALL}")
    if use_sspi:
        print(f" Usuario:       {Fore.WHITE}[Autenticación Integrada SSPI]{Style.RESET_ALL}")
    else:
        print(f" Usuario:       {Fore.WHITE}{username}{Style.RESET_ALL}")
        if hash_ntlm:
            print(f" Tipo de Auth:  {Fore.WHITE}Pass-the-Hash (NTLM){Style.RESET_ALL}")
        else:
            print(f" Tipo de Auth:  {Fore.WHITE}Contraseña{Style.RESET_ALL}")
    print(f" Base DN:       {Fore.WHITE}{base_dn}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}────────────────────────────────────────────────────────────────{Style.RESET_ALL}\n")

    print(" Construyendo mapa de CA a Templates...")
    from utils.ca_template_map import build_ca_template_map
    ca_template_map, template_ca_map = build_ca_template_map(conn, base_dn)

    print(" Resolviendo nombres de SIDs desde las plantillas...")
    search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    sdctl = security_descriptor_control(sdflags=0x07)
    try:
        conn.search(search_base, "(objectClass=pKICertificateTemplate)", attributes=['nTSecurityDescriptor'], controls=sdctl)
    except Exception as e:
        print(f"{Fore.RED} Error al listar plantillas para resolver SIDs: {e}{Style.RESET_ALL}")
        return None

    sids_total = []
    for e in conn.entries:
        raw_acl = None
        if "nTSecurityDescriptor" in e and getattr(e["nTSecurityDescriptor"], "raw_values", None):
            raw_acl = e["nTSecurityDescriptor"].raw_values[0]
        elif getattr(e, "raw_attributes", None) and e.raw_attributes.get("nTSecurityDescriptor"):
            raw_acl = e.raw_attributes["nTSecurityDescriptor"][0]
        if raw_acl:
            try:
                acl_entries, owner_sid = parse_security_descriptor(raw_acl)
                for ace in acl_entries:
                    sids_total.append(ace.get("sid"))
                if owner_sid:
                    sids_total.append(owner_sid)
            except Exception:
                continue

    resolved_acl = resolve_acl_bulk(conn, sids_total, base_dn)
    print(f"{Fore.GREEN} {len(resolved_acl)} SIDs resueltos a nombres de cuenta o grupo.{Style.RESET_ALL}\n")

    print(" Enumerando objetos PKI/CA para análisis ESC5...")
    try:
        pki_objects = enumerar_pki_objects(conn, base_dn)
        print(f"{Fore.GREEN} {len(pki_objects)} objetos PKI encontrados.{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.YELLOW}️ No se pudieron enumerar objetos PKI: {e}{Style.RESET_ALL}")
        pki_objects = []

    esc5_global_findings = []
    if pki_objects:
        from modules.esc5_checker import analyze_descriptor_for_esc5
        for obj in pki_objects:
            dn = obj.get("dn") or obj.get("distinguishedName") or obj.get("cn")
            raw = obj.get("nTSecurityDescriptor") or obj.get("raw_descriptor")
            if not raw:
                continue
            res = analyze_descriptor_for_esc5(dn, raw, resolved_sids=resolved_acl or {})
            if res.get("ESC5"):
                res["dn"] = dn
                esc5_global_findings.append(res)
        
        if esc5_global_findings:
            print(f"{Fore.RED} ESC5 → {len(esc5_global_findings)} objetos PKI con ACLs inseguras → High{Style.RESET_ALL}")
            for finding in esc5_global_findings:
                print(f"   → {finding.get('dn')}:")
                for d in finding.get("ESC5_Details", []):
                    rights = ", ".join(d.get("rights", []))
                    print(f"      {d.get('principal')} -> {rights}")

    print("\n Obteniendo lista de plantillas publicadas en la CA...\n")
    try:
        plantillas_publicadas = obtener_plantillas_publicadas(conn, base_dn)
        print(f"{Fore.GREEN} {len(plantillas_publicadas)} plantillas publicadas detectadas en la configuración de la CA.{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.YELLOW}️ No se pudieron obtener plantillas publicadas: {e}{Style.RESET_ALL}")
        plantillas_publicadas = []

    try:
        resultados = analizar_plantillas(conn, base_dn, resolved_acl, pki_objects, plantillas_publicadas)
    except Exception as e:
        print(f"{Fore.RED} Error al analizar plantillas: {e}{Style.RESET_ALL}")
        return None

    if resultados and esc5_global_findings:
        resultados[0]["ESC5_Global"] = esc5_global_findings

    esc6_results, esc7_results, esc8_results = [], [], []
    try:
        ca_objects = enumerate_pki_objects_for_esc6(conn, base_dn, debug_flags=False)

        for obj in ca_objects:
            try:
                try:
                    from modules.esc6_checker import analyze_ca_for_esc6, confirm_via_winreg
                    esc6_data = analyze_ca_for_esc6(obj["name"], obj["descriptor"], resolved_acl, enroll_flags=int(obj.get("enroll_flags") or 0))
                    if deep_scan:
                        ca_host = obj.get("dNSHostName") or obj["name"]
                        lmhash = hash_ntlm.split(":")[0] if hash_ntlm and ":" in hash_ntlm else ""
                        nthash = hash_ntlm.split(":")[1] if hash_ntlm and ":" in hash_ntlm else (hash_ntlm or "")
                        conf = confirm_via_winreg(ca_host, obj["name"], username, password, domain, lmhash, nthash)
                        if conf.get("status") in ["EXPLOITABLE", "NEAR_MISS"]:
                            esc6_data["ESC6"] = conf["status"]
                            esc6_data["ESC6_Reason"] = conf.get("reason", "")
                    esc6_results.append(esc6_data)
                except Exception:
                    pass

                esc7_data = analyze_ca_for_esc7(obj["name"], obj["descriptor"], resolved_acl, enroll_flags=int(obj.get("enroll_flags") or 0))
                esc8_data = analyze_enrollment_service_for_esc8(obj["name"], obj)
                esc7_results.append(esc7_data)
                esc8_results.append(esc8_data)
            except Exception:
                continue

        for r in resultados:
            r["ESC6_CA_Level"] = esc6_results
            r["ESC7_CA_Level"] = esc7_results
            r["ESC8_CA_Level"] = esc8_results
            r["Total_Published_In_CA"] = len(plantillas_publicadas)

    except Exception as e:
        print(f"{Fore.YELLOW}️ Error analizando CAs y servicios de inscripción: {e}{Style.RESET_ALL}")

    print(" Ejecutando ESC14 (Explicit Mapping)...")
    from modules.esc14_checker import ESC14Checker
    domain_sid_str = None
    if sids_total:
        for s in sids_total:
            if str(s).startswith("S-1-5-21-") and len(str(s).split("-")) >= 7:
                domain_sid_str = "-".join(str(s).split("-")[:7])
                break
    esc14_checker = ESC14Checker(conn, domain_sid_str, base_dn, resolved_acl)
    esc14_results = esc14_checker.check()

    print(" Ejecutando Análisis de Entorno Híbrido...")
    from modules.hybrid_detector import HybridDetector
    hybrid_detector = HybridDetector(conn, base_dn)
    hybrid_results = hybrid_detector.check()
    if hybrid_results.get("hybrid_detected"):
        print(f"    {Fore.CYAN}ENTORNO HÍBRIDO DETECTADO ({hybrid_results.get('tenant')}){Style.RESET_ALL}")
        accts = hybrid_results.get('sync_accounts', [])
        if accts:
            risky = [a for a in accts if a.get('risks')]
            print(f"      Cuentas sync encontradas: {len(accts)} (️ {len(risky)} con riesgos)")

    print(" Ejecutando Shadow Credentials...")
    from modules.shadow_credentials_checker import ShadowCredentialsChecker
    shadow_checker = ShadowCredentialsChecker(conn, domain_sid_str, base_dn, resolved_acl)
    shadow_results = shadow_checker.check(hybrid_results=hybrid_results)
    if shadow_results:
        print(f"   {Fore.YELLOW}️ {len(shadow_results)} cuentas vulnerables a Shadow Credentials:{Style.RESET_ALL}")
        for sr in shadow_results:
            print(f"        - {sr.get('target_account')}: {sr.get('mapping_type')} sobre {sr.get('attacker_account')}")

    print(" Ejecutando Certifried (CVE-2022-26923)...")
    from modules.certifried_checker import CertifriedChecker
    certifried_checker = CertifriedChecker(conn, base_dn)
    certifried_results = certifried_checker.check([{"dNSHostName": dc_ip}] if dc_ip else [], resultados, ca_objects)

    from modules.esc10_checker import ESC10Checker
    from modules.esc12_checker import ESC12Checker
    esc10_checker = ESC10Checker(conn, base_dn)
    esc12_checker = ESC12Checker(conn, base_dn)
    
    lmhash = hash_ntlm.split(":")[0] if hash_ntlm and ":" in hash_ntlm else ""
    nthash = hash_ntlm.split(":")[1] if hash_ntlm and ":" in hash_ntlm else (hash_ntlm or "")
    
    if deep_scan:
        print(" Ejecutando escaneos profundos via MS-RRP (ESC10, ESC12)...")
        esc10_result = esc10_checker.check_via_winreg(dc_ip, username, password, domain, lmhash, nthash)
    else:
        esc10_result = esc10_checker.check_via_ldap([dc_ip])
        
    esc12_results = []
    ca_objects_to_check = ca_objects if 'ca_objects' in locals() else []
    for obj in ca_objects_to_check:
        ca_host = obj.get("dNSHostName") or obj["name"]
        if deep_scan:
            esc12_res = esc12_checker.check_via_winreg(ca_host, username, password, domain, lmhash, nthash)
        else:
            esc12_res = esc12_checker.check_via_ldap(ca_host)
        esc12_results.append(esc12_res)

    for r in resultados:
        r["ESC14_Global"] = esc14_results
        r["ESC10_Global"] = esc10_result
        r["ESC12_Global"] = esc12_results
        r["CERTIFRIED_Global"] = certifried_results
        r["SHADOW_CREDENTIALS_Global"] = shadow_results
        r["HYBRID_Global"] = hybrid_results

    print(" Correlacionando Combo Chains...")
    from modules.analysis.combo_chains import analyze_combo_chains
    combo_chains_results = analyze_combo_chains(
        resultados, esc7_results, esc8_results, certifried_results, hybrid_results, shadow_results,
        username=username, domain=domain, dc_ip=dc_ip, ca_template_map=ca_template_map
    )
    for r in resultados:
        r["Combo_Chains_Global"] = combo_chains_results

    print(" Ejecutando validaciones ESC9 (GenericWrite dependiente)...")
    from modules.esc9_checker import ESC9Checker
    esc9_checker = ESC9Checker(resultados, shadow_results, esc10_result)
    resultados = esc9_checker.check()

    print(" Ejecutando validaciones ESC13 (OID Group Link)...")
    from modules.esc13_checker import ESC13Checker
    esc13_checker = ESC13Checker(conn, base_dn, resultados, pki_objects)
    resultados = esc13_checker.check()

    print(" Ejecutando validaciones ESC15 (Schema V1 EnrolleeSuppliesSubject)...")
    from modules.esc15_checker import ESC15Checker
    esc15_checker = ESC15Checker(resultados)
    resultados = esc15_checker.check()

    # Apply ESC11 / ESC16 results to template level as informative globally
    for r in resultados:
        r["ESC11_CA_Level"] = esc8_results
        r["ESC16_CA_Level"] = esc8_results

    total_templates = len(resultados)
    high = sum(1 for r in resultados if any(ri.get('nivel') == 'High' for ri in r.get('riesgos', [])))
    medium = sum(1 for r in resultados if any(ri.get('nivel') == 'Medium' for ri in r.get('riesgos', [])))
    low = sum(1 for r in resultados if any(ri.get('nivel') == 'Low' for ri in r.get('riesgos', [])))
    esc7_vuln = sum(1 for r in esc7_results if r.get("ESC7_CA"))
    esc8_vuln = sum(1 for r in esc8_results if r.get("ESC8_CA"))

    # Integración del motor de consecuencias e identidades (DDCC)
    print("\n️‍️ Ejecutando Identity Severity Model y Deterministic Domain Compromise Check (DDCC)...")
    ddcc_json_path = None
    ddcc_html_path = None
    try:
        ddcc_templates = []
        for r in resultados:
            # BUG FIX: previously read r.get('misconfigurations',[]) which never existed.
            # enroll_principals is a flat list of {sid, name, rights, ace_type} dicts
            # DDCC engine expects principal names as plain strings.
            raw_enroll = r.get('enroll_principals', [])
            eff_principals = []
            for p in raw_enroll:
                name = p.get('name') or p.get('sid') or ''
                if name:
                    eff_principals.append(name)

            ddcc_tpl = {
                "name": r.get('cn', 'Unknown'),
                "ekus": r.get('ekus', []),
                "name_flags": r.get('cert_name_flag', 0),
                "enroll_flags": r.get('enroll_flag', 0),
                "schema_version": r.get('schema_version', 1),
                "is_published": r.get('is_published', False),
                "effective_enroll_principals": eff_principals,
                "issuance_policies": [],
                "requires_manager_approval": bool(r.get('enroll_flag', 0) & 0x02),
                "requires_agent_signature": bool(r.get('enroll_flag', 0) & 0x01),
                "is_ca": False,
            }
            ddcc_templates.append(ddcc_tpl)
            
        custom_sources = set(ddcc_sources.split(",")) if ddcc_sources else None
        reporte_ddcc = is_domain_deterministically_compromisable(ddcc_templates, target_principals_override=custom_sources)
        
        if certifried_results.get("status") in ["EXPLOITABLE", "NEAR_MISS"] and certifried_results.get("machine_account_quota", 0) > 0 and certifried_results.get("machine_template_published"):
            from modules.graph.models import AttackPath
            reporte_ddcc.deterministic_critical_paths.append(
                AttackPath(
                    start_principal="LowTrustUser",
                    description=f"[CERTIFRIED PATH] LowTrustUser → [CAN_CREATE_MACHINE] → MachineAccount → [CAN_IMPERSONATE_DC via dNSHostName] → DC → [CERTIFICATE_AUTH via {certifried_results.get('machine_template_name', 'Machine')}] → DomainAdmin"
                )
            )
            reporte_ddcc.is_compromisable = True

        if reporte_ddcc.is_compromisable:
            print(f"{Fore.RED}️ ¡ADVERTENCIA CRÍTICA DDCC! (Determinístico){Style.RESET_ALL}")
            for path in reporte_ddcc.deterministic_critical_paths:
                print(f"   {Fore.RED}️ Attack Path:{Style.RESET_ALL} {path.description}")
        else:
            print(f"{Fore.GREEN} DDCC: Seguro. No hay paths determinísticos directos.{Style.RESET_ALL}")
            
        if reporte_ddcc.non_deterministic_risk_paths:
            print(f"\n{Fore.YELLOW}️ ¡RIESGO LATENTE! (Human-in-the-Loop){Style.RESET_ALL}")
            print("Estos caminos requieren aprobación de administrador o firmas autorizadas pero son válidos lógicamente:")
            for path in reporte_ddcc.non_deterministic_risk_paths:
                print(f"   {Fore.YELLOW}️ Risk Path:{Style.RESET_ALL} {path.description}")

        if bloodhound:
            print(f"\n{Fore.CYAN} Exportando datos a formato BloodHound v5...{Style.RESET_ALL}")
            from modules.output.bloodhound_export import export_bloodhound
            bh_out = output_dir if output_dir else "."
            bh_path = export_bloodhound(reporte_ddcc, domain, bh_out)
            if bh_path:
                for r in resultados:
                    r["BloodHound_Path"] = bh_path
                
        if diff_report:
            print(f"\n{Fore.CYAN} Calculando Diff con reporte anterior: {diff_report}{Style.RESET_ALL}")
            from modules.analysis.diff_engine import generate_diff
            diff_summary = generate_diff(diff_report, resultados)
            if diff_summary:
                resultados[0]["Diff_Summary"] = diff_summary
                print(f"   {Fore.GREEN} Diff calculado. {diff_summary.get('nuevas_vulns', 0)} nuevas, {diff_summary.get('resueltas', 0)} resueltas.{Style.RESET_ALL}")
                
        # Export DDCC Files
        if output_dir:
            try:
                ddcc_json_path = generate_ddcc_json(reporte_ddcc, domain, dc_ip, output_dir, top_paths, include_non_deterministic, evidence_level)
                ddcc_html_path = generate_ddcc_html(reporte_ddcc, domain, dc_ip, output_dir, top_paths, include_non_deterministic, evidence_level)
                print(f"\n{Fore.GREEN} Reportes DDCC Generados Exitosamente:{Style.RESET_ALL}")
                print(f"   JSON: {ddcc_json_path}")
                print(f"   HTML: {ddcc_html_path}")
            except Exception as e:
                print(f"{Fore.RED} Error al generar reportes DDCC: {e}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.YELLOW}️ Error en el motor DDCC: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.MAGENTA}═══════════════════════════════════════════════════════════════")
    print(f"  RESUMEN GLOBAL DEL ANÁLISIS — ESCecpcion v1.0")
    print(f"───────────────────────────────────────────────────────────────{Style.RESET_ALL}")
    print(f" • Plantillas analizadas:   {Fore.CYAN}{total_templates}{Style.RESET_ALL}")
    print(f" • Vulnerabilidades High:   {Fore.RED}{high}{Style.RESET_ALL}")
    print(f" • Vulnerabilidades Medium: {Fore.YELLOW}{medium}{Style.RESET_ALL}")
    print(f" • Vulnerabilidades Low:    {Fore.GREEN}{low}{Style.RESET_ALL}")
    print(f" • CAs vulnerables (ESC7):  {Fore.RED}{esc7_vuln}{Style.RESET_ALL}")
    print(f" • Enrollment (ESC8):       {Fore.YELLOW}{esc8_vuln}{Style.RESET_ALL}")
    
    if 'reporte_ddcc' in locals():
        det_paths = len(reporte_ddcc.deterministic_critical_paths)
        risk_paths = len(reporte_ddcc.non_deterministic_risk_paths)
        if det_paths > 0:
            print(f" • Estado DDCC:             {Fore.RED}COMPROMISIBLE ({det_paths} Attack Paths){Style.RESET_ALL}")
        elif risk_paths > 0:
            print(f" • Estado DDCC:             {Fore.YELLOW}RIESGO LATENTE ({risk_paths} Risk Paths){Style.RESET_ALL}")
        else:
            print(f" • Estado DDCC:             {Fore.GREEN}SEGURO (Sin Paths Low-Trust){Style.RESET_ALL}")

        report_meta = compute_report_meta_global(resultados=resultados, ddcc_report=reporte_ddcc, evidence_level=evidence_level, published_count=len(plantillas_publicadas))
        posture_score = int(report_meta.get("posture_score") or 0)
        posture_label = str(report_meta.get("posture_label") or "UNKNOWN")
        susceptibility = str(report_meta.get("attack_susceptibility") or "LOW")
        expl = SUSCEPTIBILITY_EXPLANATIONS.get(susceptibility, "")
        print(f" • Posture Score:           {Fore.CYAN}{posture_score}/100{Style.RESET_ALL} ({posture_label})")
        print(f" • Attack Susceptibility:   {Fore.CYAN}{susceptibility}{Style.RESET_ALL} — {expl}")
        if det_paths == 0 and risk_paths == 0:
            try:
                eff_enroll = int(getattr(reporte_ddcc.evaluation_summary, "templates_with_effective_enroll_count", 0) or 0)
            except Exception:
                eff_enroll = 0
            if eff_enroll == 0:
                print(f"   Nota: No se generaron paths porque las plantillas publicadas no tienen permisos efectivos de inscripción para los entrypoints low-trust (effective_enroll=0).")
        
    print(f"═══════════════════════════════════════════════════════════════{Style.RESET_ALL}\n")

    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception:
            pass

    if export_json:
        try:
            exportar_resultado(
                resultados,
                output_dir=output_dir,
                ddcc_report=locals().get('reporte_ddcc'),
                evidence_level=evidence_level,
                emit_meta_file=emit_meta_file,
                json_wrapper=json_wrapper,
            )
            print(f"{Fore.GREEN} Reporte JSON exportado exitosamente.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}️ Error al exportar JSON: {e}{Style.RESET_ALL}")

    if export_html:
        try:
            exportar_reporte_html(
                resultados,
                dominio=domain,
                output_dir=output_dir,
                ddcc_report=locals().get('reporte_ddcc'),
                evidence_level=evidence_level,
                ddcc_html_path=ddcc_html_path,
                ddcc_json_path=ddcc_json_path,
            )
            print(f"{Fore.GREEN} Reporte HTML generado correctamente.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}️ Error al generar el reporte HTML: {e}{Style.RESET_ALL}")

    return resultados


def interactive_menu():
    print_banner()
    while True:
        print("\nSeleccione una opción:")
        print(" 1) Analizar AD — Escaneo con Usuario/Contraseña")
        print(" 2) Analizar AD — Escaneo con Usuario/Hash NTLM")
        print(" 3) Analizar AD — Escaneo con Autenticación Integrada (SSPI)")
        print(" 0) Salir")
        choice = input("\nOpción: ").strip()
        if choice == "1":
            username = input("Usuario (ej: Administrator): ").strip()
            password = getpass("Contraseña: ")
            domain = input("Dominio (ej: level.corp): ").strip()
            dc_ip = input("IP del Domain Controller (ej: 192.168.56.10): ").strip()
            run_scan(username, password, domain, dc_ip, show_banner=True)
        elif choice == "2":
            username = input("Usuario (ej: Administrator): ").strip()
            hash_ntlm = input("Hash NTLM (ej: LM:NT o solo NT): ").strip()
            domain = input("Dominio (ej: level.corp): ").strip()
            dc_ip = input("IP del Domain Controller (ej: 192.168.56.10): ").strip()
            run_scan(username, None, domain, dc_ip, show_banner=True, hash_ntlm=hash_ntlm)
        elif choice == "3":
            domain = input("Dominio (ej: level.corp): ").strip()
            dc_ip = input("IP del Domain Controller (ej: 192.168.56.10): ").strip()
            run_scan(None, None, domain, dc_ip, show_banner=True, use_sspi=True)
        elif choice == "0":
            print("Saliendo.")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")


def _parse_args(argv=None):
    epilog = """Ejemplos:
  python main.py --interactive

  python main.py --user usuario --domain corp.local --dc-ip 192.168.1.10
  (sin --password/--password-env: pedirá la contraseña por prompt)

  python main.py --user usuario --domain corp.local --dc-ip 192.168.1.10 --password TuPasswordAqui
  (solo lab)

  CMD:
    set ESCEPCION_PASS=TuPasswordAqui
    python main.py --user usuario --domain corp.local --dc-ip 192.168.1.10 --password-env ESCEPCION_PASS

  PowerShell:
    $env:ESCEPCION_PASS='TuPasswordAqui'
    python main.py --user usuario --domain corp.local --dc-ip 192.168.1.10 --password-env ESCEPCION_PASS

  python main.py --user usuario --domain corp.local --dc-ip 192.168.1.10 --output-dir output
"""
    parser = argparse.ArgumentParser(
        prog="ESCepcion",
        description="Auditoría de AD CS (ESC1-ESC8) por LDAP con reportes JSON/HTML.",
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--user", dest="username")
    parser.add_argument("--domain")
    parser.add_argument("--dc-ip", dest="dc_ip")
    parser.add_argument("--password")
    parser.add_argument("--password-env")
    parser.add_argument("--hashes", help="Hash NTLM (formato LM:NT) para Pass-the-Hash")
    parser.add_argument("--sspi", action="store_true", help="Usar autenticación integrada en Windows (usuario actual)")
    parser.add_argument("--ddcc-sources", help="Grupos separados por coma para iniciar el grafo DDCC (ej: 'Domain Users,Everyone')")
    parser.add_argument("--no-json", action="store_true")
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--top-paths", type=int, default=3, help="Top paths to include in the report")
    parser.add_argument("--disable-non-deterministic", action="store_true", help="Exclude human-in-the-loop paths")
    parser.add_argument("--evidence-level", choices=["summary", "full"], default="summary")
    parser.add_argument("--json-wrapper", action="store_true", help="Emit JSON wrapper: {report_meta_global, templates} (default OFF for compatibility)")
    parser.add_argument("--no-meta-file", action="store_true", help="Disable writing ESCepcion_Reporte_meta.json")
    parser.add_argument("--deep-scan", action="store_true", help="Habilita lectura de registro via MS-RRP para confirmar ESC10, ESC12 y ESC6.")
    parser.add_argument("--bloodhound", action="store_true", help="Exportar el grafo de relaciones a BloodHound v5 (JSON).")
    parser.add_argument("--diff", dest="diff_report", help="Ruta a un reporte JSON previo para comparar y mostrar diferencias.")
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    if args.interactive:
        interactive_menu()
    elif (args.username or args.sspi) and args.domain and args.dc_ip:
        password = args.password
        hash_ntlm = args.hashes
        if not password and not hash_ntlm and not args.sspi and args.password_env:
            password = os.environ.get(args.password_env)
        if not password and not hash_ntlm and not args.sspi:
            password = getpass("Contraseña: ")
        run_scan(
            args.username,
            password,
            args.domain,
            args.dc_ip,
            show_banner=True,
            export_json=not args.no_json,
            export_html=not args.no_html,
            output_dir=args.output_dir,
            use_sspi=args.sspi,
            hash_ntlm=hash_ntlm,
            ddcc_sources=args.ddcc_sources,
            top_paths=args.top_paths,
            include_non_deterministic=not args.disable_non_deterministic,
            evidence_level=args.evidence_level,
            emit_meta_file=not args.no_meta_file,
            json_wrapper=args.json_wrapper,
            deep_scan=args.deep_scan,
            bloodhound=args.bloodhound,
            diff_report=args.diff_report
        )
    else:
        interactive_menu()
