from typing import List, Dict, Any
from utils.result_model import ESCResult

class ESC9Checker:
    def __init__(self, resultados: List[Dict[str, Any]], shadow_results: List[Dict[str, Any]], esc10_result: Dict[str, Any]):
        self.resultados = resultados
        self.shadow_results = shadow_results
        self.esc10_result = esc10_result

    def check(self) -> List[Dict[str, Any]]:
        accounts_with_write = []
        genericwrite_source = None
        esc4_vuln = any(t.get("ESC4") in ["EXPLOITABLE", "NEAR_MISS"] for t in self.resultados)
        if esc4_vuln:
            genericwrite_source = "ESC4"
            accounts_with_write.append("Templates vulnerables a ESC4")

        if self.shadow_results:
            if not genericwrite_source:
                genericwrite_source = "ShadowCreds"
            else:
                genericwrite_source += " + ShadowCreds"
            for sr in self.shadow_results:
                accounts_with_write.append(sr.get("target_account", "Unknown Account"))

        strong_binding = None
        if self.esc10_result and "strong_binding_value" in self.esc10_result:
            strong_binding = self.esc10_result.get("strong_binding_value")

        esc6_active = any(ca.get("ESC6") in ["EXPLOITABLE", "NEAR_MISS"] for t in self.resultados for ca in t.get("ESC6_CA_Level", []))

        for tpl in self.resultados:
            enroll_flag = tpl.get("enroll_flag", 0)
            if not bool(enroll_flag & 0x80000):
                continue
            ekus = tpl.get("ekus", [])
            if not ("1.3.6.1.5.5.7.3.2" in ekus or "Any Purpose" in ekus or len(ekus) == 0):
                continue
            if not tpl.get("is_published", False):
                tpl["ESC9"] = ESCResult(esc_id="ESC9", status="INFORMATIVE", severity="Info", reason="Template NO publicada.").to_dict()
                continue
            principals = tpl.get("enroll_principals", [])
            low_trust_enroll = any(
                "Domain Computers" in (p.get("name") or "") or "Authenticated Users" in (p.get("name") or "") or
                "Domain Users" in (p.get("name") or "") or "| LOW_TRUST" in (p.get("name") or "")
                for p in principals
            )
            if bool(enroll_flag & 0x00000002) or tpl.get("ra_signatures", 0) > 0:
                low_trust_enroll = False
            if not low_trust_enroll:
                 continue

            if not accounts_with_write:
                res = ESCResult(esc_id="ESC9", status="POTENTIAL", severity="Low",
                                reason="Condición de template detectada pero se requiere GenericWrite sobre alguna cuenta para explotar.",
                                blocking_controls=['NO_GENERICWRITE_DETECTED'])
            else:
                if strong_binding is None:
                    res = ESCResult(esc_id="ESC9", status="NEAR_MISS", severity="High",
                                    reason="GenericWrite detectado, pero StrongCertificateBindingEnforcement no es legible como low-priv. Usar --deep-scan para confirmar.",
                                    requires_deep_scan=True)
                elif strong_binding == 2:
                    if esc6_active:
                        res = ESCResult(esc_id="ESC9", status="NEAR_MISS", severity="High",
                                        reason="GenericWrite confirmado y StrongBinding=2, pero ESC6 está activo (bypass de SAN SID URL injection).")
                    else:
                        res = ESCResult(esc_id="ESC9", status="POTENTIAL", severity="Medium",
                                        reason="GenericWrite confirmado, pero StrongBinding=2 previene el ataque.",
                                        blocking_controls=['STRONG_BINDING_ENFORCED'])
                else:
                    res = ESCResult(esc_id="ESC9", status="EXPLOITABLE", severity="Critical",
                                    reason=f"GenericWrite confirmado (via {genericwrite_source}) y StrongBinding={strong_binding} permite el ataque.")
            tpl["ESC9"] = res.to_dict()

        return self.resultados
