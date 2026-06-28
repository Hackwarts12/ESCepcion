from typing import Dict, Any, List
from utils.descriptor_parser import parse_security_descriptor

class ShadowCredentialsChecker:
    def __init__(self, ldap_conn, domain_sid, base_dn, resolved_acl=None):
        self.conn = ldap_conn
        self.domain_sid = domain_sid
        self.base_dn = base_dn
        self.resolved_acl = resolved_acl or {}
        
        domain_parts = [p.split("=")[1] for p in base_dn.split(",") if p.startswith("DC=")]
        self.domain_str = ".".join(domain_parts) if domain_parts else ""
        
        self.privileged_sids = []
        if self.domain_sid:
            self.privileged_sids = [
                f"{self.domain_sid}-512",  # Domain Admins
                f"{self.domain_sid}-519",  # Enterprise Admins
                f"{self.domain_sid}-516",  # Domain Controllers
            ]

    def check(self, hybrid_results: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        results = []
        hybrid_results = hybrid_results or {}
        sync_accounts_map = {a["samAccountName"].lower(): a for a in hybrid_results.get("sync_accounts", [])}
        
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, self.base_dn, "(|(objectClass=user)(objectClass=computer))", attributes=["sAMAccountName", "objectSid", "nTSecurityDescriptor", "msDS-KeyCredentialLink", "adminCount", "description"])
            for entry in entries:
                try:
                    obj_sid = entry.objectSid.value if 'objectSid' in entry else None
                    if not obj_sid:
                        continue
                        
                    sam_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else "Unknown"
                    sam_lower = sam_name.lower()
                    
                    is_sync_account = sam_lower in sync_accounts_map
                    admin_count = int(entry.adminCount.value) if "adminCount" in entry else 0
                    is_privileged = obj_sid in self.privileged_sids or admin_count == 1
                    
                    desc = entry.description.value if "description" in entry else ""
                    desc_lower = desc.lower()
                    
                    # Compute Tier
                    if is_privileged or is_sync_account or "cloud" in desc_lower or "azure" in desc_lower or "sync" in desc_lower:
                        tier = 1
                    elif "svc_" in sam_lower or "service" in desc_lower or "admin" in sam_lower:
                        tier = 2
                    else:
                        tier = 3
                    
                    # Chequeo 1: Atributo msDS-KeyCredentialLink ya poblado
                    if 'msDS-KeyCredentialLink' in entry and entry['msDS-KeyCredentialLink']:
                        count = len(entry['msDS-KeyCredentialLink']) if isinstance(entry['msDS-KeyCredentialLink'], list) else 1
                        sev = "High" if is_sync_account else ("Medium" if is_privileged else "Info")
                        
                        notes = ["El atributo msDS-KeyCredentialLink contiene datos. Esto frecuentemente es legítimo (Windows Hello for Business, FIDO2, Entra Hybrid Join)."]
                        if is_sync_account:
                            notes.insert(0, " Cuenta de sincronización con Key Credentials. Requiere verificación si Entra ID tiene CBA habilitado.")
                            
                        results.append({
                            "esc": "SHADOW_CREDENTIALS",
                            "status": "INFORMATIVE",
                            "severity": sev,
                            "confidence": "LOW",
                            "tier": tier,
                            "scenario": "KEYCREDENTIAL_PRESENT",
                            "target_account": f"{sam_name} ({obj_sid})",
                            "attacker_account": "N/A",
                            "mapping_type": "msDS-KeyCredentialLink Populated",
                            "existing_mapping_value": "KEY_CREDENTIAL_LINK_DATA_PRESENT",
                            "attack_chain": [f"La cuenta {sam_name} tiene {count} valor(es) en msDS-KeyCredentialLink."] + notes,
                            "cross_module_alert": is_sync_account,
                            "keycredential_present": True,
                            "keycredential_count": count,
                            "false_positive_note": "Altamente probable que sea legítimo (WHfB, FIDO2). Solo se confirma como ataque con correlación de Event ID 5136/4662 o analizando la estructura binaria del BLOB.",
                            "recommendation": "Verificar si la cuenta realmente utiliza Windows Hello for Business o FIDO2. En caso negativo, investigar quién pobló el atributo en los logs (Event ID 5136)."
                        })

                    # Chequeo 2: Permisos débiles
                    raw_acl = None
                    if "nTSecurityDescriptor" in entry and getattr(entry["nTSecurityDescriptor"], "raw_values", None):
                        raw_acl = entry["nTSecurityDescriptor"].raw_values[0]
                    if not raw_acl:
                        continue
                        
                    entries_acl, owner = parse_security_descriptor(raw_acl)
                    for e in entries_acl:
                        sid = e.get("sid")
                        name = self.resolved_acl.get(sid, "")
                        perms = set(e.get("permisos", []))
                        
                        if self._is_low_trust(sid, name):
                            if "WRITE_PROPERTY" in perms or "GENERIC_WRITE" in perms or "GENERIC_ALL" in perms or "WRITE_DACL" in perms or "WRITE_OWNER" in perms:
                                sev = "Critical" if is_privileged or is_sync_account else "High"
                                
                                attack_chain = [
                                    f"1. El principal {name} puede modificar msDS-KeyCredentialLink (o tomar ownership/modificar DACL) de {sam_name}",
                                    "2. Inyecta una clave pública (Shadow Credential).",
                                    "3. Solicita un TGT como esa cuenta usando el certificado inyectado (PKINIT)."
                                ]
                                
                                if is_sync_account:
                                    tenant = sync_accounts_map[sam_lower].get("tenant", "Entra ID")
                                    attack_chain.append(f" CROSS-MODULE ALERT: cuenta sync {sam_name} tiene Shadow Credentials expuestas. Comprometer esta cuenta permite DCSync + impacto en tenant {tenant}.")
                                
                                results.append({
                                    "esc": "SHADOW_CREDENTIALS",
                                    "status": "POTENTIAL",
                                    "severity": sev,
                                    "confidence": "HIGH",
                                    "tier": tier,
                                    "scenario": "WEAK_ACL",
                                    "target_account": f"{sam_name} ({obj_sid})",
                                    "attacker_account": f"{name} ({sid})",
                                    "mapping_type": "WriteProperty / GenericWrite / WriteDacl / WriteOwner",
                                    "existing_mapping_value": "N/A",
                                    "attack_chain": attack_chain,
                                    "cross_module_alert": is_sync_account,
                                    "keycredential_present": ('msDS-KeyCredentialLink' in entry and bool(entry['msDS-KeyCredentialLink'])),
                                    "false_positive_note": "Bajo riesgo de falso positivo. La delegación de permisos a cuentas de baja confianza suele ser una misconfiguración explotable determinística.",
                                    "recommendation": f"Auditar y revocar los permisos peligrosos sobre {sam_name} otorgados al principal {name}."
                                })
                except Exception:
                    continue
        except Exception as e:
            print(f"️ Error al escanear Shadow Credentials: {e}")
            
        # Sort results by tier
        results.sort(key=lambda x: x.get("tier", 3))
        return results

    def _is_low_trust(self, sid: str, name: str) -> bool:
        sid_lower = sid.lower() if sid else ""
        if sid_lower in {"s-1-5-10", "s-1-3-0", "s-1-5-18"}: # SELF, Creator Owner, System
            return False
        if name:
            if "| TRUSTED" in name:
                return False
            if "| LOW_TRUST" in name or "| UNKNOWN_SID" in name:
                return True
        if not sid and not name:
            return False
        
        name_lower = name.split(" | ")[0].lower() if name else ""
        non_priv_names = {"everyone", "authenticated users", "domain users", "users", "domain computers"}
        if name_lower in non_priv_names:
            return True
        if sid_lower.endswith("-513") or sid_lower.endswith("-515"):
            return True
        if sid_lower in {"s-1-1-0", "s-1-5-11", "s-1-5-32-545"}:
            return True
        return False
