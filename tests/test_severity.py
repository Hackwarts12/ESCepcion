import unittest
from models.capabilities import AuthenticationConsequence, PKICapability, EvidenceRecord
from models.severity import IdentitySeverity
from models.context import DirectoryContext
from modules.inference.severity_evaluator import evaluate_severity

class TestSeverityEvaluator(unittest.TestCase):
    
    def setUp(self):
        self.evidence_template = EvidenceRecord(
            source_principal="Domain Users",
            template="Test",
            published=True,
            effective_rights=["Enroll"],
            observed_ekus=[],
            observed_flags=[],
            issuance_reqs={},
            inferred_capabilities=[],
            confidence="high",
            notes=[]
        )

    def test_l5_subca_requires_no_friction(self):
        """SUBCA target should be L5 if unconstrained, L2 if constrained."""
        # Unconstrained
        cq_unconstrained = AuthenticationConsequence(
            capability=PKICapability.CanSubordinateCA,
            is_deterministic=True,
            subject_alt_name_enabled=False,
            can_target_arbitrary=True,
            can_target_privileged=True,
            explanations=[],
            raw_evidence=self.evidence_template.__dict__.copy()
        )
        
        outcome1 = evaluate_severity(cq_unconstrained, "Authority Target")
        self.assertEqual(outcome1.severity, IdentitySeverity.L5_AUTH_AUTHORITY)
        
        # Constrained (can_target_privileged = False due to friction)
        cq_constrained = AuthenticationConsequence(
            capability=PKICapability.CanSubordinateCA,
            is_deterministic=False,
            subject_alt_name_enabled=False,
            can_target_arbitrary=True,
            can_target_privileged=False,
            explanations=[],
            raw_evidence=self.evidence_template.__dict__.copy()
        )
        
        outcome2 = evaluate_severity(cq_constrained, "Authority Target")
        self.assertEqual(outcome2.severity, IdentitySeverity.L2_ARBITRARY_USER)

    def test_l3_requires_privileged_targeting(self):
        """L3 should only trigger if the target can actually be privileged."""
        cq_esc1 = AuthenticationConsequence(
            capability=PKICapability.CanPKINITUser,
            is_deterministic=True,
            subject_alt_name_enabled=True,
            can_target_arbitrary=True,
            can_target_privileged=True,
            explanations=[],
            raw_evidence=self.evidence_template.__dict__.copy()
        )
        
        context = DirectoryContext(privileged_groups={"Domain Admins"})
        
        # Targeting specific admin
        outcome_admin = evaluate_severity(cq_esc1, "Domain Admins", dir_context=context)
        self.assertEqual(outcome_admin.severity, IdentitySeverity.L3_PRIVILEGED_AUTH)
        
        # Targeting generic unknown means it cannot definitively hit an admin. Downgrade to L2.
        outcome_generic = evaluate_severity(cq_esc1, "Unknown/Arbitrary Target", dir_context=context)
        self.assertEqual(outcome_generic.severity, IdentitySeverity.L2_ARBITRARY_USER)

    def test_l1_self_auth_only(self):
        """Self Auth where SAN is not allowed stays L1."""
        cq_esc3_client = AuthenticationConsequence(
            capability=PKICapability.CanSmartcardLogon,
            is_deterministic=True,
            subject_alt_name_enabled=False,
            can_target_arbitrary=False,
            can_target_privileged=False,
            explanations=[],
            raw_evidence=self.evidence_template.__dict__.copy()
        )
        outcome = evaluate_severity(cq_esc3_client, "Domain Users")
        self.assertEqual(outcome.severity, IdentitySeverity.L1_SELF_AUTH)

if __name__ == '__main__':
    unittest.main()
