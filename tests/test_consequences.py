import unittest
from models.capabilities import PKICapability
from models.eku_registry import EKU_CLIENT_AUTH, EKU_ANY_PURPOSE
from modules.inference.consequence_engine import infer_template_capabilities, can_target_arbitrary_user, can_target_privileged_user

class TestConsequenceEngine(unittest.TestCase):
    
    def test_strict_eku_mapping(self):
        """Unknown EKUs must be flagged as RequiresLabValidation and not assume ClientAuth."""
        template_unknown = {
            "name": "WeirdTemplate",
            "ekus": ["1.2.3.4.5.6.7"], # Unknown EKU
            "name_flags": 0,
            "is_published": True
        }
        
        consequences = infer_template_capabilities(template_unknown)
        self.assertEqual(len(consequences), 1)
        self.assertEqual(consequences[0].capability, PKICapability.RequiresLabValidation)
        self.assertFalse(consequences[0].is_deterministic)
        self.assertEqual(consequences[0].raw_evidence['confidence'], 'requires_lab_validation')

    def test_arbitrary_but_protected_targeting(self):
        """If a template has SAN but also manager approval, it should NOT be privileged targetable."""
        template_protected = {
            "name": "ProtectedSAN",
            "ekus": [EKU_CLIENT_AUTH],
            "name_flags": 0x00000001, # ENROLLEE_SUPPLIES_SUBJECT
            "requires_manager_approval": True # Friction
        }
        
        # Should now be true because targeting is decoupled from determinism/friction
        self.assertTrue(can_target_arbitrary_user(template_protected))
        self.assertFalse(can_target_privileged_user(template_protected))
        
        consequences = infer_template_capabilities(template_protected)
        # Auth Capability is found...
        self.assertTrue(any(c.capability == PKICapability.CanPKINITUser for c in consequences))
        # ...but deterministic is False
        auth_c = [c for c in consequences if c.capability == PKICapability.CanPKINITUser][0]
        self.assertFalse(auth_c.is_deterministic)
        self.assertFalse(auth_c.can_target_privileged)

    def test_pure_esc1(self):
        """Testing a pure deterministic ESC1 scenario."""
        template_esc1 = {
            "name": "VulnESC1",
            "ekus": [EKU_CLIENT_AUTH],
            "name_flags": 0x00000001,
            "requires_manager_approval": False,
            "requires_agent_signature": False
        }
        
        self.assertTrue(can_target_arbitrary_user(template_esc1))
        self.assertTrue(can_target_privileged_user(template_esc1))
        
        consequences = infer_template_capabilities(template_esc1)
        auth_c = [c for c in consequences if c.capability == PKICapability.CanPKINITUser][0]
        
        self.assertTrue(auth_c.is_deterministic)
        self.assertTrue(auth_c.can_target_privileged)
        self.assertEqual(auth_c.raw_evidence['confidence'], 'high')


    def test_esc6_override(self):
        """Testing if CA-level EDITF_ATTRIBUTESUBJECTALTNAME2 grants Arbitrary Targeting."""
        template_no_san = {
            "name": "NoSanButAuth",
            "ekus": ["1.3.6.1.5.5.7.3.2"], # Client Auth
            "name_flags": 0, # No SAN flag
            "is_published": True
        }
        ca_override = {
            "editf_attributesubjectaltname2": True
        }
        
        # Testing explicitly with and without the override
        self.assertFalse(can_target_arbitrary_user(template_no_san))
        self.assertTrue(can_target_arbitrary_user(template_no_san, ca_dict=ca_override))
        
        consequences = infer_template_capabilities(template_no_san, ca_dict=ca_override)
        self.assertEqual(len(consequences), 1)
        self.assertTrue(consequences[0].can_target_arbitrary)
        self.assertTrue(consequences[0].can_target_privileged)
        
    def test_enrollment_agent_app_policy(self):
        """Enrollment Agents defined in Application Policies instead of EKUs must be detected."""
        template_app_pol = {
            "name": "HiddenEA",
            "application_policies": ["1.3.6.1.4.1.311.20.2.1"], # Cert Req Agent
            "ekus": [],
            "name_flags": 0,
            "is_published": True
        }
        consequences = infer_template_capabilities(template_app_pol)
        # Should detect CanIssueOtherCerts smoothly
        has_issue = any(c.capability.name == "CanIssueOtherCerts" for c in consequences)
        self.assertTrue(has_issue)
        
    def test_low_trust_signer_warning(self):
        """If a signer requires interaction but the signer is a generic user, raise warning flag in evidence notes."""
        template_sign = {
            "name": "WeaklySignedEA",
            "ekus": ["1.3.6.1.4.1.311.20.2.1"],
            "requires_agent_signature": True,
            "authorized_signers": ["Domain Users"]
        }
        
        # Mock Context where Domain Users is NOT privileged
        from models.context import DirectoryContext
        mock_context = DirectoryContext(privileged_groups=["Domain Admins"], privileged_targets_resolution="complete")
        
        consequences = infer_template_capabilities(template_sign, dir_context=mock_context)
        
        self.assertEqual(len(consequences), 1)
        # Must be non-deterministic (it still requires interaction)
        self.assertFalse(consequences[0].is_deterministic)
        
        # But evidence must contain the warning
        notes = consequences[0].raw_evidence.get("notes", [])
        warning_found = any("WARNING! Authorized Signers include Low-Trust subjects" in n for n in notes)
        self.assertTrue(warning_found)

if __name__ == '__main__':
    unittest.main()
