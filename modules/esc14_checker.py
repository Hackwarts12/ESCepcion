import re
from typing import Dict, Any, List
from utils.descriptor_parser import parse_security_descriptor

class ESC14Checker:
    def __init__(self, ldap_conn, domain_sid, base_dn, resolved_acl=None):
        self.conn = ldap_conn
        self.domain_sid = domain_sid
        self.base_dn = base_dn
        self.resolved_acl = resolved_acl or {}
        
        # Determine domain string from base_dn for privileged SIDs
        domain_parts = [p.split("=")[1] for p in base_dn.split(",") if p.startswith("DC=")]
        self.domain_str = ".".join(domain_parts) if domain_parts else ""
        
        self.privileged_sids = []
        if self.domain_sid:
            self.privileged_sids = [
                f"{self.domain_sid}-512",  # Domain Admins
                f"{self.domain_sid}-519",  # Enterprise Admins
                f"{self.domain_sid}-516",  # Domain Controllers
            ]

    def check(self) -> List[Dict[str, Any]]:
        results = []
        # Escenario A: buscar WritePropery sobre altSecurityIdentities
        results += self._check_write_perms()
        # Escenario B/C/D: buscar mapeos débiles existentes
        results += self._check_weak_mappings()
        return results

    def _is_low_trust(self, sid: str, name: str) -> bool:
        if name:
            if "| TRUSTED" in name:
                return False
            if "| LOW_TRUST" in name or "| UNKNOWN_SID" in name:
                return True
        if not sid and not name:
            return False
        sid_lower = sid.lower() if sid else ""
        name_lower = name.split(" | ")[0].lower() if name else ""
        non_priv_names = {"everyone", "authenticated users", "domain users", "users", "domain computers"}
        if name_lower in non_priv_names:
            return True
        if sid_lower.endswith("-513") or sid_lower.endswith("-515"):
            return True
        if sid_lower in {"s-1-1-0", "s-1-5-11", "s-1-5-32-545"}:
            return True
        return False

    def _check_write_perms(self) -> List[Dict[str, Any]]:
        results = []
        # GUID for altSecurityIdentities: bf967950-0de6-11d0-a285-00aa003049e2
        search_filter = "(|(objectClass=user)(objectClass=computer))"
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(
                self.conn,
                self.base_dn,
                search_filter,
                attributes=['nTSecurityDescriptor', 'sAMAccountName', 'objectSid']
            )
            for entry in entries:
                try:
                    obj_sid = entry.objectSid.value if 'objectSid' in entry else None
                    if not obj_sid:
                        continue
                    sam_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else "Unknown"
                    is_privileged = False
                    if obj_sid in self.privileged_sids:
                        is_privileged = True
                        
                    raw_acl = None
                    if "nTSecurityDescriptor" in entry and getattr(entry["nTSecurityDescriptor"], "raw_values", None):
                        raw_acl = entry["nTSecurityDescriptor"].raw_values[0]
                    if not raw_acl:
                        continue
                        
                    entries, owner = parse_security_descriptor(raw_acl)
                    for e in entries:
                        sid = e.get("sid")
                        name = self.resolved_acl.get(sid, "")
                        perms = set(e.get("permisos", []))
                        if self._is_low_trust(sid, name):
                            applies = False
                            if "GENERIC_WRITE" in perms or "GENERIC_ALL" in perms or "WRITE_DACL" in perms:
                                applies = True
                            elif "WRITE_PROPERTY" in perms:
                                obj_type = str(e.get("object_type", "")).lower()
                                applies = (obj_type == "bf967950-0de6-11d0-a285-00aa003049e2" or not obj_type or obj_type == "none")

                            if applies:
                                sev = "Critical" if is_privileged else "High"
                                res = {
                                    "esc": "ESC14",
                                    "status": "EXPLOITABLE",
                                    "severity": sev,
                                    "scenario": "A",
                                    "target_account": f"{sam_name} ({obj_sid})",
                                    "attacker_account": f"{name} ({sid})",
                                    "mapping_type": "WriteAltSecId",
                                    "existing_mapping_value": "N/A",
                                    "attack_chain": [
                                        f"1. Modificar atributo altSecurityIdentities de {sam_name}",
                                        f"2. Inyectar un mapeo débil (ej. X509:<S>CN=Fake)",
                                        f"3. certipy auth -pfx fake.pfx -domain {self.domain_str}"
                                    ],
                                    "manual_verification": f"ldapsearch -x -H ldap://DC -D user -w pass -b '{self.base_dn}' '(sAMAccountName={sam_name})' nTSecurityDescriptor"
                                }
                                results.append(res)
                                break # One hit per target is enough
                except Exception:
                    continue
        except Exception as e:
            pass
        return results

    def _check_weak_mappings(self) -> List[Dict[str, Any]]:
        results = []
        search_filter = "(altSecurityIdentities=X509*)"
        try:
            from utils.ldap_paginator import paginated_search
            entries = paginated_search(
                self.conn,
                self.base_dn,
                search_filter,
                attributes=['sAMAccountName', 'objectSid', 'altSecurityIdentities']
            )
            for entry in entries:
                try:
                    obj_sid = entry.objectSid.value if 'objectSid' in entry else None
                    sam_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else "Unknown"
                    is_privileged = (obj_sid in self.privileged_sids)
                    
                    alt_ids = entry.altSecurityIdentities.values if 'altSecurityIdentities' in entry else []
                    if not isinstance(alt_ids, list):
                        alt_ids = [alt_ids]
                        
                    for alt_id in alt_ids:
                        alt_str = str(alt_id)
                        scenario = None
                        mapping_type = None
                        sev = "Low"
                        
                        if "X509:<S>" in alt_str and "<I>" not in alt_str:
                            scenario = "D"
                            mapping_type = "X509SubjectOnly"
                            sev = "Critical" if is_privileged else "High"
                        elif "X509:<I>" in alt_str and "<S>" in alt_str:
                            scenario = "C"
                            mapping_type = "X509IssuerSubject"
                            sev = "High" if is_privileged else "Medium"
                        elif "X509:<RFC822>" in alt_str:
                            scenario = "B"
                            mapping_type = "X509RFC822"
                            sev = "High" if is_privileged else "Medium"
                            
                        if scenario:
                            res = {
                                "esc": "ESC14",
                                "status": "EXPLOITABLE" if scenario == "D" else "POTENTIAL",
                                "severity": sev,
                                "scenario": scenario,
                                "target_account": f"{sam_name} ({obj_sid})",
                                "attacker_account": "Cualquier atacante con un certificado coincidente",
                                "mapping_type": mapping_type,
                                "existing_mapping_value": alt_str,
                                "attack_chain": [
                                    "1. Modificar atributo [mail/cn/dNSHostName] de cuenta controlada",
                                    "2. certipy req -u victim -p pass -ca CA -template User",
                                    f"3. certipy auth -pfx victim.pfx -domain {self.domain_str}"
                                ],
                                "manual_verification": f"ldapsearch -x -H ldap://DC -D user -w pass -b '{self.base_dn}' '(altSecurityIdentities={alt_str})' altSecurityIdentities"
                            }
                            results.append(res)
                except Exception:
                    continue
        except Exception:
            pass
        return results
