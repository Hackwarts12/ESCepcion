# models/eku_registry.py
# Strict mappings to avoid inflating capabilities

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_CERT_REQ_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_SUBCA = "2.5.29.19"

KNOWN_IDENTITY_EKUS = {
    EKU_CLIENT_AUTH,
    EKU_SMARTCARD_LOGON,
    EKU_PKINIT_CLIENT,
    EKU_CERT_REQ_AGENT,
    EKU_SUBCA
}

def is_identity_eku(eku_oid: str) -> bool:
    return eku_oid in KNOWN_IDENTITY_EKUS
