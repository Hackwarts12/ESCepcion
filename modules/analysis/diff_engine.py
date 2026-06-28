import json
from typing import Dict, Any, List

def generate_diff(prev_json_path: str, current_resultados: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Comparisons logic between a previous JSON report and the current scan results.
    """
    try:
        with open(prev_json_path, 'r', encoding='utf-8') as f:
            prev_data = json.load(f)
    except Exception as e:
        print(f"️ No se pudo cargar el reporte previo para diff: {e}")
        return {}

    # Extract previous findings
    prev_templates = prev_data.get("templates", [])
    if not prev_templates and isinstance(prev_data, list):
        # Fallback to old format
        prev_templates = prev_data

    # We will key templates by their 'cn' or 'displayName'
    prev_map = {}
    for pt in prev_templates:
        name = pt.get("plantilla") or pt.get("displayName") or pt.get("cn")
        if name:
            prev_map[name.upper()] = pt

    curr_map = {}
    for ct in current_resultados:
        name = ct.get("cn") or ct.get("displayName")
        if name:
            curr_map[name.upper()] = ct

    nuevas = []
    resueltas = []
    cambios_risk = []

    # Check for resolved or changes
    for p_name, p_data in prev_map.items():
        if p_name not in curr_map:
            resueltas.append({
                "template": p_name,
                "reason": "La plantilla fue eliminada o dejó de ser vulnerable en todos los ESCs evaluados."
            })
        else:
            c_data = curr_map[p_name]
            p_risk = int(p_data.get("risk_score") or 0)
            c_risk = int(c_data.get("risk_score") or 0)
            if p_risk != c_risk:
                cambios_risk.append({
                    "template": p_name,
                    "old_risk": p_risk,
                    "new_risk": c_risk,
                    "delta": c_risk - p_risk
                })

    # Check for new findings
    for c_name, c_data in curr_map.items():
        if c_name not in prev_map:
            # We only care if it actually has vulnerabilities
            if any(ri.get('nivel') in ['High', 'Critical'] for ri in c_data.get('riesgos', [])):
                nuevas.append({
                    "template": c_name,
                    "risk_score": int(c_data.get("risk_score") or 0)
                })

    # You could also compare global states like ESC6_CA, CERTIFRIED, etc.
    # For now, we focus on templates as requested.
    
    return {
        "nuevas": nuevas,
        "resueltas": resueltas,
        "cambios_risk": cambios_risk,
        "nuevas_vulns": len(nuevas),
        "resueltas_count": len(resueltas),
        "prev_file": prev_json_path
    }
