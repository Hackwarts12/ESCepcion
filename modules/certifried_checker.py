from typing import Dict, Any, List

class CertifriedChecker:
    def __init__(self, ldap_conn, base_dn):
        self.conn = ldap_conn
        self.base_dn = base_dn

    def check(self, dc_hosts: List[Dict[str, str]], resultados: List[Dict[str, Any]], ca_objects: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        CVE-2022-26923 (Certifried) Detector
        """
        ca_objects = ca_objects or []
        
        # 1. MachineAccountQuota
        maq = 10
        maq_readable = False
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, self.base_dn, "(objectClass=domain)", attributes=["ms-DS-MachineAccountQuota"])
            for e in entries:
                if "ms-DS-MachineAccountQuota" in e:
                    maq = int(e["ms-DS-MachineAccountQuota"].value)
                    maq_readable = True
        except Exception as e:
            import sys
            print(f"  [DEBUG] certifried_checker: {e}", file=sys.stderr)

        # 2 & 3. Plantilla Machine publicada y con Client Auth
        machine_template_published = False
        machine_template_name = ""
        is_esc4_vulnerable = False
        
        for tpl in resultados:
            if not tpl.get("is_published", False):
                continue
                
            ekus = tpl.get("ekus", [])
            client_auth = "1.3.6.1.5.5.7.3.2" in ekus or "Any Purpose" in ekus or len(ekus) == 0
            
            principals = tpl.get("enroll_principals", [])
            has_low_trust = any(
                "Domain Computers" in (p.get("name") or "") or
                "Authenticated Users" in (p.get("name") or "") or
                "Domain Users" in (p.get("name") or "") or
                "| LOW_TRUST" in (p.get("name") or "")
                for p in principals
            )
            
            cert_name_flag = tpl.get("cert_name_flag", 0)
            enrollee_supplies = (cert_name_flag & 0x00000001) or (cert_name_flag & 0x00010000)
            
            if client_auth and has_low_trust and not enrollee_supplies:
                machine_template_published = True
                machine_template_name = tpl.get("displayName") or tpl.get("cn", "Machine")
                if tpl.get("ESC4") in ["EXPLOITABLE", "NEAR_MISS"]:
                    is_esc4_vulnerable = True
                break

        # Check which CAs publish this template
        cas_publishing_machine = []
        for ca in ca_objects:
            if machine_template_name.lower() in ca.get("certificate_templates", []):
                cas_publishing_machine.append(ca.get("name", "Unknown CA"))
                
        # 4. Patch de mayo 2022 (KB5014754) heuristics
        patch_confirmed = None
        patch_heuristic_notes = []
        os_versions = []
        for dc in dc_hosts:
            host = dc.get("dNSHostName", "DC")
            os_val = dc.get("operatingSystem", "")
            os_ver = dc.get("operatingSystemVersion", "")
            os_versions.append({"dc": host, "os": os_val, "version": os_ver})
            
            # Simple heuristic based on build numbers (Server 2022 build 20348.707+, Server 2019 build 17763.2931+)
            if "20348." in os_ver:
                build_minor = int(os_ver.split(".")[-1]) if "." in os_ver else 0
                if build_minor >= 707: patch_heuristic_notes.append(f"{host} (Server 2022) parece parcheado por build {os_ver}")
            elif "17763." in os_ver:
                build_minor = int(os_ver.split(".")[-1]) if "." in os_ver else 0
                if build_minor >= 2931: patch_heuristic_notes.append(f"{host} (Server 2019) parece parcheado por build {os_ver}")

        notes = []
        if maq_readable:
            if maq == 0:
                status = "SAFE"
                severity = "Info"
            elif not machine_template_published:
                status = "POTENTIAL"
                severity = "Low"
            else:
                status = "EXPLOITABLE" if not patch_heuristic_notes else "NEAR_MISS"
                severity = "Critical"
        else:
            notes.append("ms-DS-MachineAccountQuota no legible con las credenciales actuales. Valor asumido: 10 (default de Windows). Para confirmar: Set-ADDomain -Identity domain -Replace @{'ms-DS-MachineAccountQuota'='0'}")
            if not machine_template_published:
                status = "POTENTIAL"
                severity = "Low"
            else:
                status = "NEAR_MISS"
                severity = "Critical"

        if len(cas_publishing_machine) > 1:
            notes.append(f"Machine template publicada en {len(cas_publishing_machine)} CAs: {', '.join(cas_publishing_machine)}. Superficie de ataque ampliada — cualquier CA puede emitir el certificado de impersonación.")
            
        if is_esc4_vulnerable:
            notes.append(f"CORRELACIÓN DETECTADA: La CA tiene ESC4 activo Y tiene Machine template publicada. Un atacante que explote ESC4 obtiene control sobre la misma CA que emitiría el certificado Certifried.")
            
        if patch_heuristic_notes:
            notes.append("Heurística de parcheo: " + "; ".join(patch_heuristic_notes))

        return {
            "check": "CERTIFRIED",
            "cve": "CVE-2022-26923",
            "status": status,
            "severity": severity,
            "machine_account_quota": maq,
            "machine_template_published": machine_template_published,
            "machine_template_name": machine_template_name,
            "dc_os_versions": os_versions,
            "patch_confirmed": patch_confirmed,
            "notes": notes,
            "attack_summary": "Un usuario de dominio puede crear una machine account, setear su dNSHostName al del DC, solicitar certificado Machine y autenticarse como el DC → DCSync → Domain Takeover.",
            "attack_chain": [
                f"1. Verificar MachineAccountQuota: ldapsearch ... ms-DS-MachineAccountQuota (Actual: {maq})",
                "2. certipy account create domain/user:pass@dc -user attacker$ -dns dc.domain.local",
                f"3. certipy req -u attacker$ -p pass -ca CA -template {machine_template_name or 'Machine'}",
                "4. certipy auth -pfx dc.pfx -dc-ip DC_IP → NT hash del DC",
                "5. secretsdump.py domain/dc$@dc -hashes :NTHASH → DCSync"
            ],
            "remediation": [
                "Setear ms-DS-MachineAccountQuota = 0 en la raíz del dominio.",
                "Aplicar KB5014754 en todos los DCs.",
                "Revisar permisos GenericWrite sobre machine accounts existentes."
            ],
            "taxonomy_level": "L5",
            "ddcc_impact": "DOMAIN_TAKEOVER"
        }
