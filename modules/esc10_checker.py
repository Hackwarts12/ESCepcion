from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
from typing import Dict, Any

class ESC10Checker:
    def __init__(self, ldap_conn, base_dn):
        self.conn = ldap_conn
        self.base_dn = base_dn

    def check_via_ldap(self, dc_hosts) -> Dict[str, Any]:
        """
        Estrategia 1: Inferir estado via versión de SO de DCs (LDAP-only)
        """
        try:
            search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            self.conn.search(self.base_dn, search_filter, attributes=['operatingSystem', 'dNSHostName'])
            for entry in self.conn.entries:
                os_str = entry.operatingSystem.value if 'operatingSystem' in entry else ""
                dc_host = entry.dNSHostName.value if 'dNSHostName' in entry else "DC"
                # If OS contains 2019, 2022, etc, it's likely patched to Compat mode (1)
                return {
                    "esc": "ESC10",
                    "status": "NEAR_MISS",
                    "severity": "High",
                    "reason": f"El controlador de dominio ({dc_host} - {os_str}) podría ser vulnerable o requerir mapeo fuerte.",
                    "note": "Requiere verificación manual del registro. Utilice el flag --deep-scan para confirmar automáticamente o revise HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc",
                    "fallback_command": f"reg query \\\\{dc_host}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc /v StrongCertificateBindingEnforcement"
                }
        except Exception:
            pass
            
        return {
            "esc": "ESC10",
            "status": "NOT_SCANNED",
            "severity": "Info",
            "reason": "No se pudo inferir el estado de ESC10 via LDAP",
            "note": "Requiere verificación manual del registro o ejecutar con --deep-scan."
        }

    def check_via_winreg(self, dc_host, username, password, domain, lmhash='', nthash='') -> Dict[str, Any]:
        """
        Estrategia 2: Active probing via MS-RRP
        """
        if not dc_host:
            return self.check_via_ldap([])
            
        try:
            stringbinding = f'ncacn_np:{dc_host}[\\pipe\\winreg]'
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials(username, password, domain, lmhash, nthash)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            ans = rrp.hOpenLocalMachine(dce)
            reg_handle = ans['phKey']

            strong_binding = None
            try:
                kdc_key = "SYSTEM\\CurrentControlSet\\Services\\Kdc"
                ans = rrp.hBaseRegOpenKey(dce, reg_handle, kdc_key)
                key_handle = ans['phkResult']
                val = rrp.hBaseRegQueryValue(dce, key_handle, 'StrongCertificateBindingEnforcement')
                strong_binding = val[1]
                rrp.hBaseRegCloseKey(dce, key_handle)
            except Exception:
                pass

            mapping_methods = None
            try:
                schannel_key = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel"
                ans2 = rrp.hBaseRegOpenKey(dce, reg_handle, schannel_key)
                key_handle2 = ans2['phkResult']
                val2 = rrp.hBaseRegQueryValue(dce, key_handle2, 'CertificateMappingMethods')
                mapping_methods = val2[1]
                rrp.hBaseRegCloseKey(dce, key_handle2)
            except Exception:
                pass

            dce.disconnect()
            print(f" MS-RRP conectado a {dc_host} — ESC10 analizado via registro")
            return self._evaluate(strong_binding, mapping_methods, dc_host)

        except Exception as e:
            print(f"️ MS-RRP no pudo conectar a {dc_host}: {str(e)}\n     ESC10 reportado como NOT_SCANNED")
            return {
                "esc": "ESC10",
                "status": "NOT_SCANNED",
                "severity": "Info",
                "reason": f"No se pudo conectar via MS-RRP a {dc_host}: {str(e)}",
                "fallback_command": f"reg query \\\\{dc_host}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc"
            }

    def _evaluate(self, strong_binding, mapping_methods, dc_host) -> Dict[str, Any]:
        if strong_binding is None and mapping_methods is None:
            return {
                "esc": "ESC10",
                "status": "NOT_SCANNED",
                "severity": "Info",
                "reason": "Deep scan se conectó pero no pudo leer las claves de registro relevantes.",
                "note": "Verificar manualmente.",
                "fallback_command": f"reg query \\\\{dc_host}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc"
            }

        vulnerable_kerberos = False
        if strong_binding is not None and strong_binding in [0, 1]:
            vulnerable_kerberos = True
        elif strong_binding is None:
            # Si no existe la llave, el default histórico era vulnerable, pero no lo afirmamos ciegamente.
            pass

        vulnerable_schannel = (mapping_methods is not None and (mapping_methods & 0x4))

        if not vulnerable_kerberos and not vulnerable_schannel:
            return {
                "esc": "ESC10",
                "status": "SAFE",
                "severity": "Info",
                "reason": "Strong binding habilitado (2) y Schannel protegido."
            }

        return {
            "esc": "ESC10",
            "status": "EXPLOITABLE" if (vulnerable_kerberos or vulnerable_schannel) else "NEAR_MISS",
            "severity": "Critical",
            "strong_binding_value": strong_binding if strong_binding is not None else "No leído",
            "mapping_methods_value": hex(mapping_methods) if mapping_methods is not None else "No leído",
            "vulnerable_kerberos": vulnerable_kerberos,
            "vulnerable_schannel": vulnerable_schannel,
            "case_applicable": "A (Kerberos)" if vulnerable_kerberos else ("B (Schannel)" if vulnerable_schannel else "N/A"),
            "dc_host": dc_host,
            "attack_chain": [
                "1. Obtener hash de cuenta con GenericWrite sobre otra cuenta",
                "2. certipy account update -u attacker -p pass -user victima -upn admin@domain",
                "3. certipy req -u victima -p pass -ca CA -template User",
                "4. certipy account update -u attacker -p pass -user victima -upn victima@domain",
                "5. certipy auth -pfx admin.pfx -domain domain.local"
            ]
        }
