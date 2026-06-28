from typing import List, Dict, Any
from utils.result_model import ESCResult

class ESC13Checker:
    def __init__(self, ldap_conn, base_dn: str, resultados: List[Dict[str, Any]], pki_objects: List[Dict[str, Any]]):
        self.conn = ldap_conn
        self.base_dn = base_dn
        self.resultados = resultados
        self.pki_objects = pki_objects

    def _validate_oid_group(self, group_dn: str) -> Dict[str, Any]:
        try:
            self.conn.search(group_dn, '(objectClass=group)', attributes=['groupType', 'member', 'memberOf', 'adminCount', 'samAccountName'], search_scope='BASE')
            if not self.conn.entries: return None
            entry = self.conn.entries[0]
            return {
                'is_universal': bool(int(str(entry.groupType)) & 0x8),
                'has_members': bool(str(entry.member) != '[]' and str(entry.member) != 'None' and entry.member),
                'admin_count': str(entry.adminCount) if 'adminCount' in entry else "0",
                'member_of': [str(m) for m in entry.memberOf] if 'memberOf' in entry else [],
                'sam': str(entry.samAccountName) if 'samAccountName' in entry else "Unknown"
            }
        except Exception: return None

    def _is_privileged_group(self, group_info: Dict[str, Any]) -> str:
        if str(group_info.get("admin_count", "0")) == "1": return "HIGH"
        critical_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins"]
        high_groups = ["Administrators", "Account Operators", "Backup Operators", "Print Operators", "Server Operators", "Group Policy Creator Owners"]
        for mo in group_info.get("member_of", []):
            for cg in critical_groups:
                if f"CN={cg}," in mo: return "CRITICAL"
            for hg in high_groups:
                if f"CN={hg}," in mo: return "HIGH"
        return "NONE"

    def check(self) -> List[Dict[str, Any]]:
        oid_to_group_dn = {}
        try:
            self.conn.search(self.base_dn, '(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))', attributes=['msDS-OIDToGroupLink', 'msPKI-Cert-Template-OID'])
            for entry in self.conn.entries:
                if 'msDS-OIDToGroupLink' in entry and 'msPKI-Cert-Template-OID' in entry:
                    oid_to_group_dn[str(entry['msPKI-Cert-Template-OID'].value)] = str(entry['msDS-OIDToGroupLink'].value)
        except Exception: pass

        for tpl in self.resultados:
            all_template_oids = tpl.get("ekus", []) + tpl.get("issuance_policies", [])
            linked_group_dn = next((oid_to_group_dn[oid] for oid in all_template_oids if oid in oid_to_group_dn), None)
            if not linked_group_dn: continue
            group_info = self._validate_oid_group(linked_group_dn)
            if not group_info: continue

            ekus = tpl.get("ekus", [])
            client_auth = "1.3.6.1.5.5.7.3.2" in ekus or "Any Purpose" in ekus or len(ekus) == 0
            if not tpl.get("is_published", False):
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="INFORMATIVE", reason="Template NO publicada.").to_dict()
                continue
            if not group_info['is_universal']:
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="INFORMATIVE", reason="msDS-OIDToGroupLink presente pero grupo no es universal.").to_dict()
                continue
            if group_info['has_members']:
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="INFORMATIVE", reason="Grupo tiene miembros, comportamiento inesperado.").to_dict()
                continue
            privilege_level = self._is_privileged_group(group_info)
            if privilege_level == "NONE":
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="INFORMATIVE", reason=f"OID link presente hacia grupo ({group_info['sam']}) sin privilegios conocidos.").to_dict()
                continue

            principals = tpl.get("enroll_principals", [])
            low_trust_enroll = any("Domain Computers" in (p.get("name") or "") or "Authenticated Users" in (p.get("name") or "") or "Domain Users" in (p.get("name") or "") or "| LOW_TRUST" in (p.get("name") or "") for p in principals)
            if not client_auth or not low_trust_enroll: continue
            
            has_manager_approval = bool(tpl.get("enroll_flag", 0) & 0x00000002) or (tpl.get("ra_signatures", 0) > 0)
            if has_manager_approval:
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="NEAR_MISS", severity="High", reason="Requiere Manager Approval o Firmas.", blocking_controls=['MANAGER_APPROVAL_OR_SIGNATURE']).to_dict()
            else:
                tpl["ESC13"] = ESCResult(esc_id="ESC13", status="EXPLOITABLE", severity="Critical" if privilege_level == "CRITICAL" else "High", reason=f"Grupo OID ({group_info['sam']}) es universal, vacío y con privilegios ({privilege_level}).").to_dict()
        return self.resultados
