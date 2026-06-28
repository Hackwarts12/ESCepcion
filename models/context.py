from dataclasses import dataclass, field
from typing import List, Set, Dict

@dataclass
class DirectoryContext:
    domain_name: str = ""
    # Store SIDs or group names that are considered highly privileged
    privileged_groups: Set[str] = field(default_factory=lambda: {
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins"
    })
    
    # Are we sure we parsed all members or relying on generic names?
    privileged_targets_resolution: str = "partial" # "full", "partial", "unknown"
    
    def is_privileged(self, target_identity: str) -> bool:
        """Determines if a target name or SID maps to a known privileged group."""
        return target_identity in self.privileged_groups or \
               target_identity.lower() in [g.lower() for g in self.privileged_groups]
