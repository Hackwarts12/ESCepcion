from typing import Dict, Any, List
import datetime

class HybridDetector:
    def __init__(self, ldap_conn, base_dn):
        self.conn = ldap_conn
        self.base_dn = base_dn
        
    def check(self) -> Dict[str, Any]:
        """
        Detects if the environment has Entra ID / Azure AD Connect sync
        """
        hybrid_detected = False
        tenant = None
        adconnect_servers = []
        adfs_detected = False
        sync_accounts = []
        hybrid_joined_devices = 0
        
        # 1. Objeto AD Connect en Configuration
        config_base = f"CN=Services,CN=Configuration,{self.base_dn}"
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, config_base, "(name=Microsoft Azure AD Connect)", attributes=["name"])
            if len(entries) > 0:
                hybrid_detected = True
        except Exception:
            pass
            
        # 2. ADFS presente
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, self.base_dn, "(|(objectClass=msDS-FederationServiceAccount)(samAccountName=*ADFS*))", attributes=["samAccountName"])
            if len(entries) > 0:
                adfs_detected = True
                hybrid_detected = True
        except Exception:
            pass

        # 3. Dispositivos Hybrid Joined
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, self.base_dn, "(&(objectClass=computer)(userCertificate=*))", attributes=["samAccountName"])
            hybrid_joined_devices = len(entries)
            if hybrid_joined_devices > 0:
                hybrid_detected = True
        except Exception:
            pass

        # 4. Cuentas de sincronización
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(self.conn, self.base_dn, "(|(samAccountName=MSOL_*)(samAccountName=AAD_*)(samAccountName=Sync_*))", attributes=[
                "sAMAccountName", "description", "pwdLastSet", "userAccountControl", "adminCount", "distinguishedName", "msDS-KeyCredentialLink"
            ])
            for entry in entries:
                sam = entry.sAMAccountName.value if "sAMAccountName" in entry else "Unknown"
                desc = entry.description.value if "description" in entry else ""
                
                # Try to extract tenant and server from description
                acct_tenant = None
                acct_server = None
                if desc:
                    import re
                    if "to tenant " in desc:
                        tenant_match = re.search(r'to tenant\s+(\S+\.onmicrosoft\.com)', desc, re.IGNORECASE)
                        if tenant_match:
                            acct_tenant = tenant_match.group(1)
                        else:
                            tenant_match2 = re.search(r'(\S+\.onmicrosoft\.com)', desc)
                            acct_tenant = tenant_match2.group(1) if tenant_match2 else "tenant_no_detectado"
                    elif "Account created by" in desc:
                        parts = desc.split(" ")
                        for p in parts:
                            if p.endswith(".onmicrosoft.com"):
                                acct_tenant = p
                        
                if acct_tenant and not tenant:
                    tenant = acct_tenant
                    
                pwd_last_set = None
                pwd_age_days = 0
                if "pwdLastSet" in entry:
                    try:
                        # pwdLastSet is a datetime object in ldap3
                        pwd_last_set = entry.pwdLastSet.value
                        if pwd_last_set and pwd_last_set.year > 1601:
                            # calculate age in days
                            now = datetime.datetime.now(datetime.timezone.utc)
                            diff = now - pwd_last_set
                            pwd_age_days = diff.days
                    except Exception:
                        pass
                        
                uac = int(entry.userAccountControl.value or 0) if "userAccountControl" in entry else 0
                dont_expire = bool(uac & 0x10000)
                
                admin_count = int(entry.adminCount.value or 0) if "adminCount" in entry else 0
                dcsync_inferred = "directory replication" in desc.lower() or "replicación de directorios" in desc.lower()
                shadow_creds_present = "msDS-KeyCredentialLink" in entry and bool(entry["msDS-KeyCredentialLink"].value)
                
                risks = []
                if pwd_age_days > 730:
                    risks.append("STATIC_PASSWORD_CRITICAL")
                elif pwd_age_days > 365:
                    risks.append("STATIC_PASSWORD_HIGH")
                    
                if dcsync_inferred:
                    risks.append("DCSYNC_INFERRED")
                    
                if admin_count == 0 and dcsync_inferred:
                    risks.append("NO_ADMINSD_PROTECTION")
                    
                sync_accounts.append({
                    "samAccountName": sam,
                    "tenant": acct_tenant,
                    "server": acct_server,
                    "pwd_last_set": str(pwd_last_set) if pwd_last_set else "Unknown",
                    "pwd_age_days": pwd_age_days,
                    "dont_expire_pwd": dont_expire,
                    "admin_count": admin_count,
                    "dcsync_inferred": dcsync_inferred,
                    "shadow_creds_present": shadow_creds_present,
                    "risks": risks,
                    "dn": entry.entry_dn
                })
                hybrid_detected = True
        except Exception as e:
            print(f"️ Error al detectar cuentas de sincronización: {e}")
            
        severity = "Info"
        if sync_accounts:
            for acct in sync_accounts:
                if "STATIC_PASSWORD_CRITICAL" in acct["risks"] or "DCSYNC_INFERRED" in acct["risks"]:
                    severity = "Critical"
                    break
                elif "STATIC_PASSWORD_HIGH" in acct["risks"]:
                    if severity == "Info": severity = "High"

        if hybrid_detected and not tenant:
            tenant = "detectado"
            
        return {
            "check": "HYBRID_ENVIRONMENT",
            "hybrid_detected": hybrid_detected,
            "tenant": tenant,
            "adconnect_servers": adconnect_servers,
            "adfs_detected": adfs_detected,
            "sync_accounts": sync_accounts,
            "hybrid_joined_devices": hybrid_joined_devices,
            "impact_statement": f"Este dominio sincroniza identidades con {tenant or 'Entra ID'}. Las misconfiguraciones ADCS on-prem (ESC1-ESC16, Certifried) pueden tener impacto en recursos cloud si Certificate-Based Authentication está habilitado en Entra ID.",
            "cloud_verification_required": [
                "Verificar si CA on-prem está registrada como trusted en Entra ID: portal.azure.com → Entra ID → Security → Authentication methods → Certificate-based auth",
                "Verificar Conditional Access policies que acepten certificados on-prem"
            ],
            "taxonomy_level": "L5",
            "severity": severity
        }
