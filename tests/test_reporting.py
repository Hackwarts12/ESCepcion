import unittest
import os
import json
import tempfile
from modules.report_json import exportar_resultado
from modules.report_html import exportar_reporte_html
from modules.reporting_metrics import compute_report_meta_global
from models.capabilities import PKICapability, EvidenceRecord
from models.severity import IdentitySeverity, IdentityOutcome
from modules.graph.models import AttackEdge, AttackPath, AttackEdgeType
from modules.analysis.ddcc import DomainCompromiseReport, DDCCEvaluationSummary
from modules.analysis.ddcc_report import generate_ddcc_json, generate_ddcc_html

class TestReporting(unittest.TestCase):
    def make_edge(self, source: str, template: str, cap: PKICapability, sev: IdentitySeverity, target: str, evidence: dict):
        return AttackEdge(
            source_principal=source,
            edge_type=AttackEdgeType.ENROLL,
            template_name=template,
            capability=cap,
            outcome=IdentityOutcome(sev, target, cap, evidence),
            explanations=[],
        )

    def make_path(self, start: str, edges):
        p = AttackPath(start)
        for e in edges:
            p.add_edge(e)
        return p

    def make_report(self, *, ddcc: bool, det_paths=None, risk_paths=None, root_cause=None):
        return DomainCompromiseReport(
            is_compromisable=ddcc,
            deterministic_critical_paths=det_paths or [],
            non_deterministic_risk_paths=risk_paths or [],
            evidence=["Test Evidence"],
            evaluation_summary=DDCCEvaluationSummary(sources_used=["Domain Users"]),
            near_miss_paths=[],
            confidence_level="HIGH",
            root_cause_analysis=root_cause or [],
        )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.ev_high = EvidenceRecord(
            source_principal="Domain Users", template="A", published=True, effective_rights=[],
            observed_ekus=[], observed_flags=[], issuance_reqs={}, inferred_capabilities=[],
            confidence="high", notes=[]
        )
        self.ev_med = EvidenceRecord(
            source_principal="Domain Users", template="B", published=True, effective_rights=[],
            observed_ekus=[], observed_flags=[], issuance_reqs={}, inferred_capabilities=[],
            confidence="medium", notes=[]
        )

        ev_high = self.ev_high.__dict__.copy()
        ev_high["severity_reasons"] = ["Reason 1"]
        ev_med = self.ev_med.__dict__.copy()
        ev_med["severity_reasons"] = ["Reason Minter"]

        edge_l5_short = self.make_edge("Domain Users", "CaTakeover", PKICapability.CanWriteDACL, IdentitySeverity.L5_AUTH_AUTHORITY, "CA_OBJECT", ev_high)
        edge_l3_short = self.make_edge("Domain Users", "VulnWebSrv", PKICapability.CanPKINITUser, IdentitySeverity.L3_PRIVILEGED_AUTH, "Domain Admins", ev_high)
        edge_l3_long1 = self.make_edge("Domain Users", "Tpl1", PKICapability.CanWriteDACL, IdentitySeverity.L3_PRIVILEGED_AUTH, "Target1", ev_high)
        edge_l3_long2 = self.make_edge("Target1", "Tpl2", PKICapability.CanPKINITUser, IdentitySeverity.L3_PRIVILEGED_AUTH, "Domain Admins", ev_high)
        edge_risk_l2 = self.make_edge("Computers", "RestrictedEA", PKICapability.CanIssueOtherCerts, IdentitySeverity.L2_ARBITRARY_USER, "Minter", ev_med)

        self.path_l5 = self.make_path("Domain Users", [edge_l5_short])
        self.path_l3_short = self.make_path("Domain Users", [edge_l3_short])
        self.path_l3_long = self.make_path("Domain Users", [edge_l3_long1, edge_l3_long2])
        self.path_risk = self.make_path("Computers", [edge_risk_l2])

        self.report = self.make_report(
            ddcc=True,
            det_paths=[self.path_l3_long, self.path_l5, self.path_l3_short],
            risk_paths=[self.path_risk],
            root_cause=["Test Root Cause"],
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_schema_and_sorting(self):
        output_dir = self.temp_dir.name
        json_path = generate_ddcc_json(self.report, "test.local", "127.0.0.1", output_dir, top_paths=3)
        
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Structural requirements
        self.assertEqual(data["report_version"], "ddcc-report/1.0")
        self.assertIn("generated_at", data)
        self.assertEqual(data["domain"], "test.local")
        self.assertTrue(data["ddcc"])
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["deterministic_paths_count"], 3)
        self.assertIn("evaluation_summary", data)
        self.assertIn("near_misses", data)
        self.assertIn("confidence_level", data)
        
        # 2. Sorting validation for Deterministic (Desc Severity, Asc Length)
        p1 = data["deterministic_critical_paths"][0]
        p2 = data["deterministic_critical_paths"][1]
        p3 = data["deterministic_critical_paths"][2]

        # Highest Severity first (L5)
        self.assertEqual(p1["end_outcome"]["severity"], "L5_AUTH_AUTHORITY")
        # Then L3 short (Length 1)
        self.assertEqual(p2["end_outcome"]["severity"], "L3_PRIVILEGED_AUTH")
        self.assertEqual(p2["length"], 1)
        # Then L3 long (Length 2)
        self.assertEqual(p3["end_outcome"]["severity"], "L3_PRIVILEGED_AUTH")
        self.assertEqual(p3["length"], 2)

    def test_html_export(self):
        output_dir = self.temp_dir.name
        html_path = generate_ddcc_html(self.report, "test.local", "127.0.0.1", output_dir)
        
        self.assertTrue(os.path.exists(html_path))
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        self.assertIn("DDCC — Deterministic Domain Compromise Check", content)
        self.assertIn("L5_AUTH_AUTHORITY", content)
        self.assertIn("test.local", content)

    def test_ddcc_html_contains_model_telemetry_and_glossary(self):
        output_dir = self.temp_dir.name
        report = self.make_report(ddcc=False, det_paths=[], risk_paths=[], root_cause=["No deterministic paths from low-trust"])
        html_path = generate_ddcc_html(report, "test.local", "127.0.0.1", output_dir)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Model Telemetry", content)
        self.assertIn("published_templates_count", content)
        self.assertIn("deterministic_edges_created", content)
        self.assertIn("Glossary & Legends", content)

    def test_standard_report_exploitability_and_sorting(self):
        # Two templates, same ESC but different exploitability/risk_score
        resultados = [
            {
                "cn": "WebServer",
                "displayName": "WebServer",
                "ekus": ["1.3.6.1.5.5.7.3.1"],
                "enroll_principals": [{"name": "Domain Users", "rights": ["ENROLL"], "sid": "S-1-5-21-x"}],
                "is_published": True,
                "low_trust_reachable": True,
                "exploitability_status": "EXPLOITABLE_NOW",
                "exploitability_reasons": [],
                "risk_score": 95,
                "is_default_template": True,
                "ESC1": True,
                "ESC1_Reason": "demo",
                "ESC1_Severidad": "High",
                "riesgos": [{"esc": "ESC1", "nivel": "High"}],
            },
            {
                "cn": "EnrollmentAgent",
                "displayName": "Enrollment Agent",
                "ekus": ["1.3.6.1.4.1.311.20.2.1"],
                "enroll_principals": [],
                "is_published": False,
                "low_trust_reachable": False,
                "exploitability_status": "NOT_EXPLOITABLE_NOT_PUBLISHED",
                "exploitability_reasons": ["Template is not published on any Enrollment Service"],
                "risk_score": 0,
                "is_default_template": True,
                "ESC3": True,
                "ESC3_Reason": "demo",
                "ESC3_Severidad": "High",
                "riesgos": [{"esc": "ESC3", "nivel": "High"}],
            },
        ]

        out_dir = self.temp_dir.name
        exportar_resultado(resultados, output_dir=out_dir)
        exportar_reporte_html(resultados, dominio="test.local", output_dir=out_dir)

        # Find latest generated files
        json_files = [
            f for f in os.listdir(out_dir)
            if f.endswith(".json") and f.startswith("ESCepcion_Reporte_") and f != "ESCepcion_Reporte_meta.json"
        ]
        html_files = [f for f in os.listdir(out_dir) if f.endswith(".html") and f.startswith("ESCepcion_Reporte_")]
        self.assertTrue(json_files)
        self.assertTrue(html_files)

        json_path = os.path.join(out_dir, sorted(json_files)[-1])
        html_path = os.path.join(out_dir, sorted(html_files)[-1])

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # JSON is now a wrapper object: {report_meta_global, ddcc, pki_graph, templates}
        self.assertIn("templates", data, "JSON should have 'templates' key (new wrapper format)")
        self.assertIn("ddcc", data, "JSON should have 'ddcc' key (Tarea 2)")
        self.assertIn("pki_graph", data, "JSON should have 'pki_graph' key (Tarea 3)")
        templates = data["templates"]

        self.assertEqual(templates[0]["exploitability_status"], "EXPLOITABLE_NOW")
        self.assertEqual(templates[1]["exploitability_status"], "NOT_EXPLOITABLE_NOT_PUBLISHED")
        self.assertIn("findings", templates[0])
        self.assertTrue(len(templates[0]["findings"]) >= 1)
        self.assertEqual(templates[0]["findings"][0]["risk_score"], 95)
        # Tarea 4: each finding should have level_l1_l5
        self.assertIn("level_l1_l5", templates[0]["findings"][0], "finding should have level_l1_l5 (Tarea 4)")

        self.assertIn("report_meta", templates[0])
        self.assertIn("posture_score", templates[0]["report_meta"])
        self.assertIn("posture_label", templates[0]["report_meta"])
        self.assertIn("ddcc_status", templates[0]["report_meta"])
        self.assertIn("attack_susceptibility", templates[0]["report_meta"])
        self.assertIn("evidence_level", templates[0]["report_meta"])
        self.assertIn("score_breakdown", templates[0]["report_meta"])

        # DDCC block assertions (Tarea 2)
        ddcc = data["ddcc"]
        self.assertIn("resultado", ddcc)
        self.assertIn(ddcc["resultado"], ["SAFE_ANALYZED", "SAFE_NO_DATA", "NEAR_MISS", "COMPROMISED"])
        self.assertIn("is_compromisable", ddcc)
        self.assertIn("evaluation_summary", ddcc)


    def test_json_wrapper_and_meta_file(self):
        output_dir = self.temp_dir.name
        resultados = [
            {
                "cn": "Tpl",
                "displayName": "Tpl",
                "ekus": [],
                "enroll_principals": [],
                "is_published": False,
                "low_trust_reachable": False,
                "exploitability_status": "NOT_EXPLOITABLE_NOT_PUBLISHED",
                "exploitability_reasons": ["not published"],
                "risk_score": 10,
                "is_default_template": "unknown",
                "riesgos": [],
            }
        ]

        exportar_resultado(resultados, output_dir=output_dir, ddcc_report=self.report, evidence_level="summary", emit_meta_file=True, json_wrapper=True)

        meta_path = os.path.join(output_dir, "ESCepcion_Reporte_meta.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertIn("report_meta_global", meta)
        self.assertIn("posture_score", meta["report_meta_global"])

    def test_consistent_posture_score_across_meta_and_html(self):
        output_dir = self.temp_dir.name
        resultados = [
            {
                "cn": "WebServer",
                "displayName": "WebServer",
                "ekus": ["1.3.6.1.5.5.7.3.1"],
                "enroll_principals": [{"name": "Domain Users", "rights": ["ENROLL"], "sid": "S-1-5-21-x"}],
                "is_published": True,
                "low_trust_reachable": True,
                "exploitability_status": "EXPLOITABLE_NOW",
                "exploitability_reasons": [],
                "risk_score": 95,
                "is_default_template": False,
                "riesgos": [{"esc": "ESC1", "nivel": "High"}],
                "ESC7_CA_Level": [],
                "ESC8_CA_Level": [],
            }
        ]
        meta = compute_report_meta_global(resultados=resultados, ddcc_report=self.report, evidence_level="summary")
        posture_score = int(meta.get("posture_score") or 0)

        exportar_resultado(resultados, output_dir=output_dir, ddcc_report=self.report, evidence_level="summary", emit_meta_file=True, json_wrapper=True)
        json_files = [f for f in os.listdir(output_dir) if f.endswith(".json") and f.startswith("ESCepcion_Reporte_")]
        self.assertTrue(json_files)
        with open(os.path.join(output_dir, json_files[0]), "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIn("report_meta_global", payload)
        self.assertEqual(int(payload["report_meta_global"]["posture_score"]), posture_score)

        html_path = exportar_reporte_html(resultados, dominio="test.local", output_dir=output_dir, ddcc_report=self.report, evidence_level="summary")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn(f">{posture_score}/100<", html)

    def test_no_duplicate_ldap_success_print_in_connect_ldap(self):
        ldap_path = os.path.join(os.path.dirname(__file__), "..", "auth", "ldap_conn.py")
        ldap_path = os.path.abspath(ldap_path)
        with open(ldap_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn(" Conexión LDAP exitosa", content)

    def test_standard_visibility_uses_is_published(self):
        resultados = [
            {
                "cn": "TplNotPublished",
                "displayName": "TplNotPublished",
                "ekus": [],
                "enroll_principals": [{"name": "Domain Users", "rights": ["ENROLL"], "sid": "S-1-5-21-x"}],
                "is_published": False,
                "exploitability_status": "NOT_EXPLOITABLE_NOT_PUBLISHED",
                "risk_score": 0,
                "ESC1": True,
                "ESC1_Reason": "demo",
                "ESC1_Severidad": "High",
                "riesgos": [{"esc": "ESC1", "nivel": "High"}],
            },
            {
                "cn": "TplNoEnroll",
                "displayName": "TplNoEnroll",
                "ekus": [],
                "enroll_principals": [],
                "is_published": True,
                "exploitability_status": "NOT_EXPLOITABLE_NO_EFFECTIVE_ENROLL",
                "risk_score": 0,
                "ESC2": True,
                "ESC2_Reason": "demo",
                "ESC2_Severidad": "Low",
                "riesgos": [{"esc": "ESC2", "nivel": "Low"}],
            },
        ]

        out_dir = self.temp_dir.name
        exportar_reporte_html(resultados, dominio="test.local", output_dir=out_dir)
        html_files = [f for f in os.listdir(out_dir) if f.endswith(".html") and f.startswith("ESCepcion_Reporte_")]
        html_path = os.path.join(out_dir, sorted(html_files)[-1])

        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("[NOT PUBLISHED]", html)
        self.assertIn("[NO EFFECTIVE ENROLL]", html)

    def test_html_contains_why_ddcc_no_block(self):
        output_dir = self.temp_dir.name
        report = self.make_report(ddcc=False, det_paths=[], risk_paths=[], root_cause=["No deterministic paths from low-trust"]) 
        html_path = generate_ddcc_html(report, "test.local", "127.0.0.1", output_dir)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Why DDCC = NO", content)

if __name__ == '__main__':
    unittest.main()
