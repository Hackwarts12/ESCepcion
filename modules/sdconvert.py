from impacket.dcerpc.v5 import dtypes
from impacket.dcerpc.v5 import samr, rrp, scmr
from impacket.dcerpc.v5.dtypes import NULL
from impacket import ntlm
from impacket.structure import Structure
from enum import IntFlag

class SDFlags(IntFlag):
    OWNER_PRESENT = 0x00000001
    GROUP_PRESENT = 0x00000002
    DACL_PRESENT = 0x00000004
    SACL_PRESENT = 0x00000008
    DACL_DEFAULTED = 0x00000010
    SACL_DEFAULTED = 0x00000020

def convertSecurityDescriptor(raw_descriptor, flags=SDFlags.DACL_PRESENT):
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1
    from impacket.dcerpc.v5.dtypes import SECURITY_DESCRIPTOR
    try:
        sd = SECURITY_DESCRIPTOR(raw_descriptor)
        sddl = sd.dumpSecurityDescriptor()
        return sddl
    except Exception as e:
        return f"Error al convertir descriptor: {e}"
