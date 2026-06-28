from typing import List, Dict, Any
from utils.result_model import ESCResult

class ESC15Checker:
    def __init__(self, resultados: List[Dict[str, Any]]):
        self.resultados = resultados
        self.skip_templates = ["CrossCA", "CAExchange", "MachineEnrollmentAgent", "KeyRecoveryAgent"]

    def check(self) -> List[Dict[str, Any]]:
        for tpl in self.resultados:
            tpl_name = tpl.get("cn", "")
            if tpl_name in self.skip_templates: continue
            if tpl.get("schema_version", 1) != 1: continue

            cert_name_flag = tpl.get("cert_name_flag", 0)
            if not (bool(cert_name_flag & 0x00000001) or bool(cert_name_flag & 0x00010000)): continue

            ekus = tpl.get("ekus", [])
            client_auth = "1.3.6.1.5.5.7.3.2" in ekus or "Any Purpose" in ekus or len(ekus) == 0
            if not client_auth and tpl_name.lower() != "subca":
                tpl["ESC15"] = ESCResult(esc_id="ESC15", status="INFORMATIVE", reason="Schema V1 con EnrolleeSuppliesSubject, pero sin EKU de ClientAuth ni es SubCA conocida.").to_dict()
                continue
            if not tpl.get("is_published", False):
                tpl["ESC15"] = ESCResult(esc_id="ESC15", status="INFORMATIVE", reason="Template NO publicada.").to_dict()
                continue

            principals = tpl.get("enroll_principals", [])
            low_trust_enroll = any("Domain Computers" in (p.get("name") or "") or "Authenticated Users" in (p.get("name") or "") or "Domain Users" in (p.get("name") or "") or "| LOW_TRUST" in (p.get("name") or "") for p in principals)
            if not low_trust_enroll or bool(tpl.get("enroll_flag", 0) & 0x00000002) or (tpl.get("ra_signatures", 0) > 0): continue
            
            tpl["ESC15"] = ESCResult(esc_id="ESC15", status="NEAR_MISS", severity="Medium", reason="Schema V1, EnrolleeSuppliesSubject habilitado. Vulnerable a ESC15 (CVE-2024-43496) si la CA no tiene el parche de Octubre 2024. Estado del parche de la CA es DESCONOCIDO.").to_dict()
        return self.resultados
