import functools
from dataclasses import dataclass
from enum import Enum, auto
from typing import List

from models.capabilities import PKICapability

@functools.total_ordering
class IdentitySeverity(Enum):
    L0_NONE = 0
    L1_SELF_AUTH = 1           # Puede autenticarse como sí mismo
    L2_ARBITRARY_USER = 2      # Puede autenticarse como otro usuario (no admin)
    L3_PRIVILEGED_AUTH = 3     # Puede autenticarse como Admin/DA 
    L4_IDENTITY_MINTING = 4    # Enrollment Agent (puede generar certs para otros)
    L5_AUTH_AUTHORITY = 5      # SubCA (control total sobre PKI)

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

@dataclass
class IdentityOutcome:
    severity: IdentitySeverity
    target_identity: str
    source_capability: PKICapability
    evidence: dict = None
