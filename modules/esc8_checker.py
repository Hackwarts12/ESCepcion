from typing import Dict, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


def _probe_url(url: str, timeout: float) -> Dict[str, Any]:
    try:
        req = Request(url, method="GET", headers={"User-Agent": "ESCepcion"})
        with urlopen(req, timeout=timeout) as resp:
            return {
                "url": url,
                "ok": True,
                "status": int(getattr(resp, "status", 200) or 200),
                "final_url": str(getattr(resp, "url", url) or url),
                "server": str(resp.headers.get("Server", "")),
                "www_authenticate": str(resp.headers.get("WWW-Authenticate", "")),
            }
    except HTTPError as e:
        return {
            "url": url,
            "ok": False,
            "status": int(getattr(e, "code", 0) or 0),
            "error": str(e),
            "www_authenticate": str(getattr(e, "headers", {}).get("WWW-Authenticate", "")) if getattr(e, "headers", None) else "",
        }
    except URLError as e:
        return {"url": url, "ok": False, "status": 0, "error": str(e)}
    except Exception as e:
        return {"url": url, "ok": False, "status": 0, "error": str(e)}


def analyze_enrollment_service_for_esc8(service_name: str, service_obj: Dict[str, Any], verify: bool = False, timeout: float = 3.0) -> Dict[str, Any]:
    vulnerable = False
    severidad = "Low"
    razon = "Servicio de inscripción seguro y autenticado"
    detalles = []

    name = (service_name or "").lower()
    service_bindings = service_obj.get("service_bindings") or []
    dns_host = service_obj.get("dns_host")

    indicators = []
    for s in service_bindings:
        try:
            indicators.append(str(s).lower())
        except Exception:
            continue
    if dns_host:
        indicators.append(str(dns_host).lower())
    indicators.append(name)

    joined = "\n".join(indicators)

    probe = {"enabled": bool(verify), "results": []}
    if verify:
        hosts = []
        if dns_host:
            hosts.append(str(dns_host))
        for s in service_bindings:
            try:
                val = str(s)
            except Exception:
                continue
            low = val.lower()
            if low.startswith("http://") or low.startswith("https://"):
                probe["results"].append(_probe_url(val.rstrip("/") + "/certsrv/", timeout))
            else:
                if "/" not in val and ":" not in val:
                    hosts.append(val)

        dedup_hosts = []
        seen = set()
        for h in hosts:
            key = h.lower().strip()
            if not key or key in seen:
                continue
            seen.add(key)
            dedup_hosts.append(h)

        for h in dedup_hosts:
            probe["results"].append(_probe_url(f"http://{h}/certsrv/", timeout))
            probe["results"].append(_probe_url(f"https://{h}/certsrv/", timeout))

    if "certsrv" in joined or "certfnsh.asp" in joined or "certcarc.asp" in joined:
        detalles.append("Posible Web Enrollment (certsrv) detectado por indicadores LDAP")

    estado = "SAFE"
    if "http://" in joined:
        estado = "EXPLOITABLE"
        severidad = "High"
        razon = "Servicio Web Enrollment/Inscripción expuesto por HTTP sin TLS"
        detalles.append("Indicador HTTP encontrado en service bindings o nombre")

    if verify and probe.get("results"):
        http_ok = any(r.get("ok") and str(r.get("url", "")).lower().startswith("http://") for r in probe["results"])
        https_ok = any(r.get("ok") and str(r.get("url", "")).lower().startswith("https://") for r in probe["results"])
        if http_ok and not https_ok:
            estado = "EXPLOITABLE"
            severidad = "High"
            razon = "Verificación: endpoint /certsrv accesible por HTTP pero no por HTTPS"
            detalles.append("Probe confirmó exposición HTTP sin HTTPS")
        elif http_ok and https_ok:
            if severidad == "Low":
                severidad = "Medium"
            detalles.append("Probe: /certsrv accesible por HTTP y HTTPS")
        elif https_ok:
            if severidad == "Low":
                severidad = "Low"
            detalles.append("Probe: /certsrv accesible por HTTPS")

    if ("https://" in joined) and ("auth=none" in joined or "anonymous" in joined):
        if estado == "SAFE":
            estado = "POTENTIAL"
        if severidad != "High":
            severidad = "Medium"
        razon = "Servicio Web Enrollment accesible sin autenticación (indicadores de Anonymous)"
        detalles.append("Indicador de autenticación anónima encontrado")

    if "ntlm" in joined and ("relay" in joined or "relaying" in joined):
        if estado == "SAFE":
            estado = "POTENTIAL"
        if severidad != "High":
            severidad = "Medium"
        razon = "Servicio de inscripción con indicadores de NTLM relayable"
        detalles.append("Indicador NTLM/relay encontrado")

    # --- ESC11: RPC Request Encryption ---
    ca_flag = service_obj.get("msPKI-CA-Flag", 0)
    # IF_ENFORCEENCRYPTICERTREQUEST (0x00000200)
    esc11_estado = "SAFE"
    esc11_sev = "Info"
    esc11_reason = "CA enforces RPC encryption"
    if not (ca_flag & 0x00000200):
        esc11_estado = "EXPLOITABLE"
        esc11_sev = "High"
        esc11_reason = "CA does not enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST is missing), vulnerable to NTLM relay to RPC (ESC11)"

    # --- ESC16: Security Extension Deshabilitada Globalmente ---
    ca_policy = service_obj.get("msPKI-CA-Policy", "")
    esc16_estado = "SAFE"
    esc16_sev = "Info"
    esc16_reason = "Security extension is enabled globally"
    if "DisableExtensionList" in ca_policy and "1.3.6.1.4.1.311.25.2" in ca_policy:
        esc16_estado = "EXPLOITABLE"
        esc16_sev = "Critical"
        esc16_reason = "CA has SID extension disabled globally (1.3.6.1.4.1.311.25.2 in DisableExtensionList). All templates vulnerable to ESC16."

    return {
        "service_name": service_name,
        "ESC8_CA": estado,
        "ESC8_CA_Reason": razon,
        "ESC8_CA_Severidad": severidad,
        "ESC8_CA_Details": detalles,
        "ESC8_CA_Probe": probe,
        "ESC8_CA_RiskMatrix": {
            "tls_disabled": "High" if "http://" in name else "Low",
            "auth_anonymous": "Medium" if "auth=none" in name else "Low",
            "ntlm_relayable": "Medium" if "ntlm" in name else "Low"
        },
        "ESC11_CA": esc11_estado,
        "ESC11_CA_Reason": esc11_reason,
        "ESC11_CA_Severidad": esc11_sev,
        "ESC16_CA": esc16_estado,
        "ESC16_CA_Reason": esc16_reason,
        "ESC16_CA_Severidad": esc16_sev
    }
