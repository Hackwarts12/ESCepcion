from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
from typing import Dict, Any

class ESC12Checker:
    def __init__(self, ldap_conn, base_dn):
        self.conn = ldap_conn
        self.base_dn = base_dn

    def check_via_ldap(self, ca_host) -> Dict[str, Any]:
        """
        Detector de Condición (sin deep-scan)
        """
        return {
            "esc": "ESC12",
            "status": "NOT_SCANNED",
            "ca_host": ca_host,
            "yubiHSM_detected": None,
            "auth_password_exposed": None,
            "severity": "Info",
            "note": "Requiere acceso local o shell al servidor CA para explotación. Si se confirma, permite forjar certificados para cualquier usuario sin límite de tiempo.",
            "manual_command": f"reg query \\\\{ca_host}\\HKLM\\SOFTWARE\\Yubico\\YubiHSM /v AuthPassword" if ca_host else "reg query HKLM\\SOFTWARE\\Yubico\\YubiHSM /v AuthPassword"
        }

    def check_via_winreg(self, ca_host, username, password, domain, lmhash='', nthash='') -> Dict[str, Any]:
        if not ca_host:
            return self.check_via_ldap(ca_host)

        try:
            stringbinding = f'ncacn_np:{ca_host}[\\pipe\\winreg]'
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials(username, password, domain, lmhash, nthash)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            ans = rrp.hOpenLocalMachine(dce)
            reg_handle = ans['phKey']

            yubiHSM_detected = False
            auth_password_exposed = False
            
            try:
                yubico_key = "SOFTWARE\\Yubico\\YubiHSM"
                ans = rrp.hBaseRegOpenKey(dce, reg_handle, yubico_key)
                key_handle = ans['phkResult']
                yubiHSM_detected = True
                
                try:
                    val = rrp.hBaseRegQueryValue(dce, key_handle, 'AuthPassword')
                    auth_password_exposed = True
                except Exception:
                    pass
                    
                rrp.hBaseRegCloseKey(dce, key_handle)
            except Exception:
                pass

            dce.disconnect()

            if auth_password_exposed:
                print(f" MS-RRP conectado a {ca_host} — YubiHSM detectado (AuthPassword expuesto)")
                return {
                    "esc": "ESC12",
                    "status": "EXPLOITABLE",
                    "ca_host": ca_host,
                    "yubiHSM_detected": True,
                    "auth_password_exposed": True,
                    "severity": "Critical",
                    "note": "AuthPassword expuesto en el registro. Permite forjar certificados ilimitadamente.",
                    "manual_command": f"reg query \\\\{ca_host}\\HKLM\\SOFTWARE\\Yubico\\YubiHSM /v AuthPassword"
                }
            elif yubiHSM_detected:
                print(f" MS-RRP conectado a {ca_host} — YubiHSM detectado (AuthPassword seguro)")
                return {
                    "esc": "ESC12",
                    "status": "NEAR_MISS",
                    "ca_host": ca_host,
                    "yubiHSM_detected": True,
                    "auth_password_exposed": False,
                    "severity": "High",
                    "note": "YubiHSM detectado pero AuthPassword no está en texto plano en el registro. Requiere extraerlo de otra manera (ej. dumping memoria).",
                    "manual_command": f"reg query \\\\{ca_host}\\HKLM\\SOFTWARE\\Yubico\\YubiHSM /v AuthPassword"
                }
            else:
                print(f" MS-RRP conectado a {ca_host} — YubiHSM no detectado")
                return {
                    "esc": "ESC12",
                    "status": "SAFE",
                    "ca_host": ca_host,
                    "yubiHSM_detected": False,
                    "auth_password_exposed": False,
                    "severity": "Info",
                    "note": "YubiHSM no detectado en el registro remoto.",
                }

        except Exception as e:
            print(f"️ MS-RRP no pudo conectar a CA ({ca_host}) — ESC12 NOT_SCANNED")
            return {
                "esc": "ESC12",
                "status": "NOT_SCANNED",
                "ca_host": ca_host,
                "yubiHSM_detected": None,
                "auth_password_exposed": None,
                "severity": "Info",
                "reason": f"No se pudo conectar via MS-RRP a {ca_host}: {str(e)}",
                "manual_command": f"reg query \\\\{ca_host}\\HKLM\\SOFTWARE\\Yubico\\YubiHSM /v AuthPassword"
            }
