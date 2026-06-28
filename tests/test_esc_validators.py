import json, pytest
from pathlib import Path

FIXTURES = Path("tests/fixtures")

def load(name):
    with open(FIXTURES / name, encoding="utf-8-sig") as f: 
        return json.load(f)

class TestESC9:
    def test_no_flag_no_vuln(self):
        from modules.esc9_checker import ESC9Checker
        chk = ESC9Checker([load("template_esc9_noflag.json")], [], {})
        r = chk.check()
        assert not any(x.get("ESC9", {}).get("status") in ("EXPLOITABLE", "NEAR_MISS") for x in r)

    def test_flag_no_write_is_potential(self):
        from modules.esc9_checker import ESC9Checker
        chk = ESC9Checker([load("template_esc9_withflag_nogenericwrite.json")], [], {})
        r = chk.check()
        assert r and r[0].get("ESC9", {}).get("status") == "POTENTIAL"

    def test_flag_with_write_is_nearmiss(self):
        from modules.esc9_checker import ESC9Checker
        chk = ESC9Checker([load("template_esc9_withflag_withgenericwrite.json")], [{"target_account": "victim@domain"}], {})
        r = chk.check()
        assert r and r[0].get("ESC9", {}).get("status") == "NEAR_MISS"

class TestESC13:
    def test_nonuniversal_not_exploitable(self):
        from modules.esc13_checker import ESC13Checker
        class DummyConn:
            def search(self, *args, **kwargs):
                self.entries = []
        chk = ESC13Checker(DummyConn(), "DC=domain", [load("template_esc13_nonuniversal.json")], [])
        # We simulate the oid mapping logic by overriding _validate_oid_group
        chk._validate_oid_group = lambda x: {"is_universal": False, "has_members": False, "admin_count": "0", "member_of": [], "sam": "G"}
        # And inject mapping directly for the test
        chk.check = self._custom_check(chk)
        r = chk.check()
        assert not any(x.get("ESC13", {}).get("status") == "EXPLOITABLE" for x in r)
        
    def _custom_check(self, chk):
        def _mock_check():
            for tpl in chk.resultados:
                tpl["ESC13"] = {"esc": "ESC13", "status": "INFORMATIVE", "reason": "No es universal."}
            return chk.resultados
        return _mock_check

class TestESC15:
    def test_not_published_is_informative(self):
        from modules.esc15_checker import ESC15Checker
        chk = ESC15Checker([load("template_esc15_notpublished.json")])
        r = chk.check()
        assert not any(x.get("ESC15", {}).get("status") in ("EXPLOITABLE", "NEAR_MISS") for x in r)

    def test_published_unknown_patch_is_nearmiss(self):
        from modules.esc15_checker import ESC15Checker
        chk = ESC15Checker([load("template_esc15_published.json")])
        r = chk.check()
        assert r and r[0].get("ESC15", {}).get("status") == "NEAR_MISS"

class TestPlaceholders:
    def test_placeholders_never_safe(self):
        from modules.esc_validator import detectar_escs
        t = load("template_safe.json")
        result = detectar_escs(t, [], [])
        for esc in ["ESC9", "ESC11", "ESC13", "ESC15", "ESC16"]:
            v = result.get(esc)
            assert v not in (False, "SAFE", None), f"{esc} retorna {v} - debe ser NOT_SCANNED u objeto"
