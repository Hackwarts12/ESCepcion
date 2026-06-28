import json
import os
import html
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from modules.analysis.ddcc import LOW_TRUST_PRINCIPALS
from data.report_strings import POSTURE_INTERPRETATION, SUSCEPTIBILITY_EXPLANATIONS, CONFIDENCE_EXPLANATIONS
from modules.reporting_metrics import compute_report_meta_global

ESC_ORDER = ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8", "ESC9", "ESC11", "ESC13", "ESC15", "ESC16"]
SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def esc(x):
    return html.escape(str(x)) if x else ""


def _interpret_posture(score: int) -> str:
    for min_score, label in POSTURE_INTERPRETATION:
        if score >= min_score:
            return label
    return POSTURE_INTERPRETATION[-1][1] if POSTURE_INTERPRETATION else "UNKNOWN"


def _compute_posture_score(
    ddcc_yes: Optional[bool],
    exploitable_now_count: int,
    high_count: int,
    low_count: int,
    esc7_count: int,
    esc8_count: int,
) -> Tuple[int, List[Dict[str, Any]]]:
    score = 100
    breakdown: List[Dict[str, Any]] = []

    if ddcc_yes is True:
        score -= 60
        breakdown.append({"label": "DDCC YES (COMPROMISED)", "delta": -60})
    elif ddcc_yes is False:
        breakdown.append({"label": "DDCC NO (SAFE)", "delta": 0})
    else:
        breakdown.append({"label": "DDCC UNKNOWN", "delta": 0})

    if exploitable_now_count:
        d = -20 * exploitable_now_count
        score += d
        breakdown.append({"label": f"EXPLOITABLE_NOW findings ({exploitable_now_count})", "delta": d})

    if high_count:
        d = -6 * high_count
        score += d
        breakdown.append({"label": f"High findings ({high_count})", "delta": d})

    if low_count:
        d = -2 * low_count
        score += d
        breakdown.append({"label": f"Low findings ({low_count})", "delta": d})

    if esc7_count > 0:
        score -= 8
        breakdown.append({"label": "CA ESC7 present", "delta": -8})

    if esc8_count > 0:
        score -= 6
        breakdown.append({"label": "ESC8 present", "delta": -6})

    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return score, breakdown


def _compute_attack_susceptibility(
    ddcc_yes: Optional[bool],
    deterministic_paths: Optional[int],
    risk_paths: Optional[int],
    templates_with_effective_enroll: Optional[int],
) -> str:
    if ddcc_yes is True or (deterministic_paths is not None and deterministic_paths > 0):
        return "HIGH"
    if risk_paths is not None and risk_paths > 0:
        return "MEDIUM"
    if templates_with_effective_enroll is not None and templates_with_effective_enroll == 0:
        return "LOW"
    return "LOW"


def _load_esc_info(base_dir: str) -> Dict[str, Any]:
    desc_path = os.path.join(base_dir, "..", "data", "esc_descriptions.json")
    esc_info = {}
    try:
        with open(desc_path, "r", encoding="utf-8") as f:
            esc_info = json.load(f)
    except Exception as e:
        print(f"No se pudo cargar esc_descriptions.json: {e}")

    for escn in ESC_ORDER:
        esc_info.setdefault(escn, {
            "severity": "Low",
            "description": "Sin descripción.",
            "exploitation": "N/A",
            "mitigation": "N/A",
        })
    return esc_info


def _append_vuln(grouped: Dict[str, Any], esc_name: str, tpl: Dict[str, Any], nivel: str, reason: str):
    tpl_cn = tpl.get("cn") or "N/A"
    display = tpl.get("displayName") or tpl_cn
    ekus = tpl.get("ekus") or []
    enroll_flag = tpl.get("enroll_flag", 0)
    flags = tpl.get("flags", 0)
    cert_name_flag = tpl.get("cert_name_flag", 0)

    details_lines = []
    if reason:
        details_lines.append(f"Razón: {reason}")
    details_lines.append(f"EKUs: {', '.join(ekus) if ekus else 'N/A'}")
    details_lines.append(f"enroll_flag: {enroll_flag}")
    details_lines.append(f"flags: {flags}")
    details_lines.append(f"cert_name_flag: {cert_name_flag}")

    principals = tpl.get("enroll_principals") or []
    exploitability_status = tpl.get("exploitability_status") or "UNKNOWN"
    exploitability_reasons = tpl.get("exploitability_reasons") or []
    risk_score = int(tpl.get("risk_score") or 0)
    is_default_template = tpl.get("is_default_template", "unknown")
    
    # Analyze principals
    is_published = tpl.get("is_published")
    if is_published is None:
        is_published = True
    has_low_trust = False
    has_admin = False
    
    for p in principals:
        p_name = p.get("name") or p.get("sid", "")
        if p_name in LOW_TRUST_PRINCIPALS:
            has_low_trust = True
        if "Admin" in p_name:
            has_admin = True
                
    has_effective_enroll = bool(principals)
    if not is_published:
        visibility_tag = "<span style='color: #7f8c8d; font-weight: bold;'>[NOT PUBLISHED]</span>"
    elif not has_effective_enroll:
        visibility_tag = "<span style='color: #7f8c8d; font-weight: bold;'>[NO EFFECTIVE ENROLL]</span>"
    elif has_low_trust:
        visibility_tag = "<span style='color: #c0392b; font-weight: bold;'>[LOW-TRUST REACHABLE]</span>"
    elif has_admin and len(principals) <= 3:
        visibility_tag = "<span style='color: #27ae60; font-weight: bold;'>[ADMIN ONLY]</span>"
    else:
        visibility_tag = "<span style='color: #f39c12; font-weight: bold;'>[RESTRICTED]</span>"
            
    details_lines.insert(0, f"Visibility: {visibility_tag}")

    details_lines.insert(1, f"Exploitability: {exploitability_status}")
    details_lines.insert(2, f"risk_score: {risk_score}")
    details_lines.insert(3, f"is_default_template: {is_default_template}")
    if exploitability_reasons:
        for rr in exploitability_reasons[:6]:
            details_lines.append(f"exploitability_reason: {rr}")

    if principals:
        preview = []
        for p in principals[:12]:
            n = p.get("name") or p.get("sid")
            rights = ",".join(p.get("rights") or [])
            preview.append(f"{n} ({rights})")
        details_lines.append(f"enroll_principals: {len(principals)}")
        details_lines.append("enroll_principals_preview: " + "; ".join(preview))

    # Remediation Playbook
    remediation_playbook = None
    if exploitability_status in ["EXPLOITABLE", "NEAR_MISS"]:
        from modules.report_json import _get_remediation_playbook
        remediation_playbook = _get_remediation_playbook(esc_name, tpl_cn)

    grouped[esc_name]["vulnerabilities"].append({
        "template": display,
        "details": details_lines,
        "level": nivel or "Info",
        "exploitability_status": exploitability_status,
        "risk_score": risk_score,
        "is_default_template": is_default_template,
        "exploitability_reasons": exploitability_reasons,
        "remediation_playbook": remediation_playbook,
    })


def exportar_reporte_html(
    resultados: List[Dict[str, Any]],
    dominio: str = "N/A",
    version: str = "1.0",
    output_dir: str | None = None,
    ddcc_report: Any = None,
    ddcc_paths_hint: Dict[str, Any] | None = None,
    evidence_level: str = "summary",
    ddcc_html_path: str | None = None,
    ddcc_json_path: str | None = None,
):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    esc_info = _load_esc_info(base_dir)

    grouped: Dict[str, Dict[str, Any]] = {
        esc: {
            "description": esc_info[esc].get("description", ""),
            "exploitation": esc_info[esc].get("exploitation", ""),
            "mitigation": esc_info[esc].get("mitigation", ""),
            "vulnerabilities": [],
        } for esc in ESC_ORDER
    }

    for tpl in resultados:
        for r in tpl.get("riesgos", []):
            esc_name = r.get("esc")
            if esc_name not in grouped:
                continue
            nivel = r.get("nivel") or "Info"
            reason = tpl.get(f"{esc_name}_Reason", "")
            _append_vuln(grouped, esc_name, tpl, nivel, reason)

        bloodhound_path = tpl.get("BloodHound_Path")

        for esc_name in ESC_ORDER:
            exists = any(v["template"] == (tpl.get("displayName") or tpl.get("cn") or "N/A")
                         for v in grouped[esc_name]["vulnerabilities"])
            if exists:
                continue
            estado_val = tpl.get(esc_name)
            if estado_val and str(estado_val).upper() != "SAFE" and str(estado_val).upper() != "FALSE":
                reason = tpl.get(f"{esc_name}_Reason", "")
                level = tpl.get(f"{esc_name}_Severidad", "Info")
                _append_vuln(grouped, esc_name, tpl, level, reason)

    esc6_ca = []
    esc7_ca = []
    esc8_ca = []
    if resultados:
        esc6_ca = resultados[0].get("ESC6_CA_Level", []) or []
        esc7_ca = resultados[0].get("ESC7_CA_Level", []) or []
        esc8_ca = resultados[0].get("ESC8_CA_Level", []) or []

    for ca in esc6_ca:
        try:
            estado_val = ca.get("ESC6")
            if estado_val and str(estado_val).upper() != "SAFE" and str(estado_val).upper() != "FALSE":
                name = ca.get("nombre_objeto") or "CA"
                reason = ca.get("ESC6_Reason") or ""
                level = ca.get("ESC6_Severidad") or "Info"
                tpl = {"cn": name, "displayName": name, "ekus": [], "enroll_flag": 0, "flags": 0, "cert_name_flag": 0}
                _append_vuln(grouped, "ESC6", tpl, level, reason)
        except Exception:
            continue

    for ca in esc7_ca:
        try:
            estado_val = ca.get("ESC7_CA")
            if estado_val and str(estado_val).upper() != "SAFE" and str(estado_val).upper() != "FALSE":
                name = ca.get("ca_name") or "CA"
                reason = ca.get("ESC7_CA_Reason") or ""
                level = ca.get("ESC7_CA_Severidad") or "Info"
                tpl = {"cn": name, "displayName": name, "ekus": [], "enroll_flag": 0, "flags": 0, "cert_name_flag": 0}
                _append_vuln(grouped, "ESC7", tpl, level, reason)
        except Exception:
            continue

    for svc in esc8_ca:
        try:
            estado_val = svc.get("ESC8_CA")
            if estado_val and str(estado_val).upper() != "SAFE" and str(estado_val).upper() != "FALSE":
                name = svc.get("service_name") or "EnrollmentService"
                reason = svc.get("ESC8_CA_Reason") or ""
                level = svc.get("ESC8_CA_Severidad") or "Info"
                probe = svc.get("ESC8_CA_Probe") or {}
                if probe.get("enabled") and probe.get("results"):
                    ok = [r for r in (probe.get("results") or []) if r.get("ok")]
                    if ok:
                        reason = reason + " | probe_ok=" + str(len(ok))
                tpl = {"cn": name, "displayName": name, "ekus": [], "enroll_flag": 0, "flags": 0, "cert_name_flag": 0}
                _append_vuln(grouped, "ESC8", tpl, level, reason)
                
            estado11_val = svc.get("ESC11_CA")
            if estado11_val and str(estado11_val).upper() != "SAFE" and str(estado11_val).upper() != "FALSE":
                name = svc.get("service_name") or "EnrollmentService"
                reason = svc.get("ESC11_CA_Reason") or ""
                level = svc.get("ESC11_CA_Severidad") or "Info"
                tpl = {"cn": name, "displayName": name, "ekus": [], "enroll_flag": 0, "flags": 0, "cert_name_flag": 0}
                _append_vuln(grouped, "ESC11", tpl, level, reason)
                
            estado16_val = svc.get("ESC16_CA")
            if estado16_val and str(estado16_val).upper() != "SAFE" and str(estado16_val).upper() != "FALSE":
                name = svc.get("service_name") or "EnrollmentService"
                reason = svc.get("ESC16_CA_Reason") or ""
                level = svc.get("ESC16_CA_Severidad") or "Info"
                tpl = {"cn": name, "displayName": name, "ekus": [], "enroll_flag": 0, "flags": 0, "cert_name_flag": 0}
                _append_vuln(grouped, "ESC16", tpl, level, reason)
        except Exception:
            continue

    esc_present = [esc for esc in ESC_ORDER if grouped[esc]["vulnerabilities"]]

    all_flagged_templates = [r for r in resultados if r.get("riesgos") or any(r.get(e) and str(r.get(e)).upper() != "SAFE" and str(r.get(e)).upper() != "FALSE" for e in ESC_ORDER)]
    top_findings = sorted(
        all_flagged_templates,
        key=lambda t: (-int(t.get("risk_score") or 0), -SEV_ORDER.get((t.get("riesgos") or [{}])[0].get("nivel") if t.get("riesgos") else "Info", 0)),
    )[:15]

    report_meta_global = compute_report_meta_global(resultados=resultados, ddcc_report=ddcc_report, evidence_level=evidence_level)
    counts = report_meta_global.get("counts", {})

    bloodhound_path_global = None
    if resultados and "BloodHound_Path" in resultados[0]:
        bloodhound_path_global = resultados[0].get("BloodHound_Path")

    total_templates = int(counts.get("templates_analyzed") or 0)
    published_templates = int(counts.get("templates_published") or 0)
    templates_with_effective_enroll = int(counts.get("templates_with_effective_enroll") or 0)
    templates_vuln = sum(1 for r in resultados if r.get("riesgos"))
    critical = int(counts.get("findings_critical") or 0)
    high = int(counts.get("findings_high") or 0)
    medium = int(counts.get("findings_medium") or 0)
    low = int(counts.get("findings_low") or 0)

    esc7_vuln = 0
    esc8_vuln = 0
    esc11_vuln = 0
    esc16_vuln = 0
    if resultados:
        esc7_vuln = sum(1 for r in (resultados[0].get("ESC7_CA_Level", []) or []) if r.get("ESC7_CA"))
        esc8_vuln = sum(1 for r in (resultados[0].get("ESC8_CA_Level", []) or []) if r.get("ESC8_CA"))
        esc11_vuln = sum(1 for r in (resultados[0].get("ESC8_CA_Level", []) or []) if r.get("ESC11_CA"))
        esc16_vuln = sum(1 for r in (resultados[0].get("ESC8_CA_Level", []) or []) if r.get("ESC16_CA"))

    posture_score = int(report_meta_global.get("posture_score") or 0)
    posture_label = str(report_meta_global.get("posture_label") or "UNKNOWN")
    attack_susceptibility = str(report_meta_global.get("attack_susceptibility") or "LOW")
    score_breakdown = report_meta_global.get("score_breakdown", []) or []

    det_paths_count = counts.get("ddcc_deterministic_paths")
    risk_paths_count = counts.get("ddcc_risk_paths")
    ddcc_confidence = str(counts.get("ddcc_confidence") or "UNKNOWN")
    ddcc_yes: Optional[bool] = None
    if report_meta_global.get("ddcc_status") == "COMPROMISED":
        ddcc_yes = True
    elif report_meta_global.get("ddcc_status") == "SAFE":
        ddcc_yes = False

    ddcc_status = "UNKNOWN"
    if ddcc_yes is True:
        ddcc_status = "COMPROMETIDO"
    elif ddcc_yes is False:
        ddcc_status = "SIN RUTA DIRECTA"

    susceptibility_expl = SUSCEPTIBILITY_EXPLANATIONS.get(attack_susceptibility, "")
    confidence_expl = CONFIDENCE_EXPLANATIONS.get(ddcc_confidence, CONFIDENCE_EXPLANATIONS.get(ddcc_confidence.upper(), ""))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ddcc_yes is False:
        risk_posture_statement = (
            "DDCC (Sin Ruta Directa): No se observaron paths determinísticos desde grupos básicos de dominio hasta Domain Admin vía AD CS puro. "
            f"Sin embargo, los hallazgos representan riesgo real (susceptibilidad={attack_susceptibility}) "
            "y las 'Cadenas de Ataque' detectadas deben remediarse, ya que un atacante puede pivotar o forzar configuraciones vulnerables (ej. Template Takeover)."
        )
    elif ddcc_yes is True:
        risk_posture_statement = (
            "DDCC COMPROMISED: Se observaron paths determinísticos directos (Zero-Click) desde cuentas sin privilegios hasta Domain Admin. "
            "Se requiere mitigación INMEDIATA de las plantillas y/o CA involucradas."
        )
    else:
        risk_posture_statement = "DDCC UNKNOWN: el reporte estándar no cuenta con un objeto DDCC para concluir veredicto."

    if ddcc_html_path:
        ddcc_html_cta = f"<a class='tab-btn' href='{esc(ddcc_html_path)}' target='_blank' title='Abrir DDCC HTML'>Abrir reporte DDCC (HTML)</a>"
    else:
        ddcc_html_cta = "<span class='tab-btn' title='No se generó artefacto DDCC HTML' style='opacity:0.6; cursor:not-allowed;'>Abrir reporte DDCC (HTML)</span>"

    if ddcc_json_path:
        ddcc_json_cta = f"<a class='tab-btn' href='{esc(ddcc_json_path)}' target='_blank' title='Abrir DDCC JSON'>Abrir DDCC (JSON)</a>"
    else:
        ddcc_json_cta = "<span class='tab-btn' title='No se generó artefacto DDCC JSON' style='opacity:0.6; cursor:not-allowed;'>Abrir DDCC (JSON)</span>"

    stats = {
        "templates_total": total_templates,
        "templates_vulnerables": templates_vuln,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

    html_report = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte ESCepcion</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family:'Outfit', 'Inter', sans-serif; margin:30px; background:#f4f7f6; color:#333; }}
.header {{ background: #0d1b2a; color: #fff; padding: 25px; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
.header h1 {{ margin: 0 0 10px 0; font-size: 2.2rem; }}
.header p {{ margin: 0; opacity: 0.9; }}
.tabs {{ display:flex; gap:0.5rem; flex-wrap:wrap; margin: 1rem 0 1.5rem 0; }}
.tab-btn {{ border:1px solid #d0d7de; background:#fff; padding:0.6rem 1.2rem; border-radius:999px; cursor:pointer; font-weight:600; color: #0d1b2a; transition: all 0.2s; }}
.tab-btn:hover {{ background: #f0f4f8; }}
.tab-btn.active {{ background:#0d1b2a; color:#fff; border-color:#0d1b2a; }}
.tabcontent {{ display:none; }}
.tabcontent.active {{ display:block; animation: fadeIn 0.3s; }}
@keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
.scorecard {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin: 1rem 0; }}
.card {{ background:#fff; border-radius:8px; padding: 18px; box-shadow:0 2px 8px rgba(0,0,0,0.04); border:1px solid #e0e6ed; }}
.card-title {{ color:#5a6b7c; font-size:0.85rem; font-weight:700; text-transform: uppercase; letter-spacing: 0.5px; }}
.card-value {{ font-size:1.8rem; font-weight:800; margin-top: 8px; color: #0d1b2a; }}
.pill {{ display:inline-block; padding:4px 12px; border-radius:999px; font-weight:700; font-size:0.85rem; }}
.pill.ok {{ background:#e8f5e9; color:#1b5e20; }}
.pill.bad {{ background:#ffebee; color:#b71c1c; }}
.pill.warn {{ background:#fff8e1; color:#7a4f01; }}
.pill.info {{ background:#e3f2fd; color:#0d47a1; }}
.charts-container {{ display:flex; gap:2rem; flex-wrap:wrap; }}
.chart-box {{ flex:1 1 45%; min-width:320px; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); border: 1px solid #e0e6ed; }}
.chart-box canvas {{ height:260px !important; max-height:260px; width:100%; }}
.vulnerability {{ background:#fff; padding:1.5rem; margin:1.5rem 0; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.04); border: 1px solid #e0e6ed; }}
.info-block {{ background:#fff; padding:1.2rem; margin:1rem 0; border-left:4px solid #0d1b2a; border-radius:0 8px 8px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
.severity-badge {{ display:inline-block; padding:4px 12px; border-radius:999px; font-weight:700; color:#fff; font-size:0.85rem; text-transform: uppercase; }}
.badge-critical {{ background: linear-gradient(135deg, #d32f2f, #b71c1c); }}
.badge-high {{ background: linear-gradient(135deg, #f57c00, #e65100); }}
.badge-medium {{ background: linear-gradient(135deg, #fbc02d, #f57f17); color:#fff; }}
.badge-low {{ background: linear-gradient(135deg, #388e3c, #1b5e20); }}
.badge-secondary {{ background:#78909c; }}
table {{ width:100%; border-collapse:collapse; margin-top:1rem; background:#fff; border-radius:8px; overflow:hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
th {{ background: #0d1b2a; color: #fff; text-align:left; padding:1rem; font-weight: 600; }}
td {{ text-align:left; padding:1rem; border-bottom:1px solid #e0e6ed; vertical-align:top; }}
tbody tr:nth-child(even) {{ background-color: #f8f9fa; }}
tbody tr:hover {{ background-color: #f1f3f5; }}
footer {{ margin-top:40px; text-align:center; color:#888; padding: 20px 0; border-top: 1px solid #e0e6ed; }}

/* DDCC Hero (Tarea 5) */
.ddcc-hero {{ border-radius:14px; padding:2rem; margin:1.5rem 0; box-shadow:0 6px 24px rgba(0,0,0,0.10); }}
.ddcc-hero.compromised {{ background:linear-gradient(135deg,#b71c1c,#c62828); color:#fff; }}
.ddcc-hero.near-miss {{ background:linear-gradient(135deg,#e65100,#ef6c00); color:#fff; }}
.ddcc-hero.safe-analyzed {{ background:linear-gradient(135deg,#1b5e20,#2e7d32); color:#fff; }}
.ddcc-hero.safe-no-data {{ background:linear-gradient(135deg,#37474f,#546e7a); color:#fff; }}
.ddcc-verdict-label {{ font-size:2.6rem; font-weight:900; letter-spacing:1px; }}
.ddcc-verdict-sub {{ font-size:1rem; margin-top:4px; opacity:0.88; }}
.l-badge {{ display:inline-block; padding:2px 8px; border-radius:6px; font-size:0.78rem; font-weight:800; margin-left:6px;
            background:rgba(255,255,255,0.18); color:#fff; border:1px solid rgba(255,255,255,0.35); }}
.near-miss-card {{ background:#fff3e0; border-left:4px solid #ef6c00; border-radius:6px; padding:0.8rem 1rem; margin:0.5rem 0; }}
.telemetry-row {{ display:flex; flex-wrap:wrap; gap:14px; margin:1rem 0; }}
.telemetry-item {{ background:#fff; border:1px solid #e0e0e0; border-radius:8px; padding:10px 14px; min-width:160px; flex:1 }}
.telemetry-item .t-val {{ font-size:1.4rem; font-weight:800; }}
.telemetry-item .t-lbl {{ font-size:0.78rem; color:#667085; font-weight:600; }}

@media print {{
  body {{ background: #fff; margin: 0.8cm; }}
  .tabs, .tab-btn, script {{ display: none !important; }}
  .tabcontent {{ display: block !important; }}
  .charts-container, canvas {{ display: none !important; }}
  .card {{ box-shadow: none; border: 1px solid #ddd; }}
  a[href]:after {{ content: ""; }}
}}

</style>
</head>
<body>
<div class="header">
<h1>Reporte de Vulnerabilidades — ESCepcion</h1>
<p><strong>Dominio:</strong> {esc(dominio)}<br><strong>Generado:</strong> {now}</p>
</div>

<div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom: 12px;">
  <button class="tab-btn" onclick="window.print()">Imprimir / Exportar PDF</button>
"""
    if bloodhound_path_global:
        filename = os.path.basename(bloodhound_path_global)
        html_report += f"""
  <a href="{esc(filename)}" download="{esc(filename)}" style="text-decoration:none;">
    <button class="tab-btn" style="background:#2980b9; color:white;">Descargar Export BloodHound JSON</button>
  </a>
"""
    html_report += """
</div>

<div class="tabs" role="tablist" aria-label="ESCepcion Report Tabs">
  <button class="tab-btn active" data-tab="tab-resumen">Resumen</button>
  <button class="tab-btn" data-tab="tab-top">Top Findings</button>
  <button class="tab-btn" data-tab="tab-esc">Detalle por ESC</button>
  <button class="tab-btn" data-tab="tab-ddcc">Análisis de Consecuencias (DDCC)</button>
  <button class="tab-btn" data-tab="tab-chains">Combo Chains</button>"""
    diff_summary = resultados[0].get("Diff_Summary") if resultados else None
    if diff_summary:
        html_report += """\n  <button class="tab-btn" data-tab="tab-diff">Comparativa (Diff)</button>"""
    html_report += f"""\n  <button class="tab-btn" data-tab="tab-glosario">Glosario</button>
</div>

<script>
function setActiveTab(tabId) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tabcontent').forEach(c => c.classList.toggle('active', c.id === tabId));
}}
document.addEventListener('DOMContentLoaded', () => {{
  document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => setActiveTab(btn.dataset.tab)));
  setActiveTab('tab-resumen');
}});
</script>

<div id="tab-resumen" class="tabcontent active">

<div class="scorecard">
  <div class="card">
    <div class="card-title">Ruta Determinística al Dominio (DDCC)</div>
    <div class="card-value">
      <span class="pill {'bad' if ddcc_status == 'COMPROMETIDO' else 'ok' if ddcc_status == 'SIN RUTA DIRECTA' else 'warn'}">{ddcc_status}</span>
    </div>
    <div style="margin-top:6px; color:#667085; font-size:0.9rem;">
      Deterministic Paths: {det_paths_count if det_paths_count is not None else 'UNKNOWN'} | Risk Paths: {risk_paths_count if risk_paths_count is not None else 'UNKNOWN'}
    </div>
  </div>
  <div class="card">
    <div class="card-title">Templates (analyzed / published)</div>
    <div class="card-value">{total_templates} / {published_templates}</div>
  </div>
  <div class="card">
    <div class="card-title">Findings (High / Medium / Low)</div>
    <div class="card-value">{high} / {medium} / {low}</div>
  </div>
  <div class="card">
    <div class="card-title">CA Findings</div>
    <div class="card-value">ESC7: {esc7_vuln} | ESC8: {esc8_vuln}</div>
    <div style="margin-top:6px; color:#667085; font-size:0.9rem;">
      ESC11: {esc11_vuln} | ESC16: {esc16_vuln}
    </div>
  </div>
  """
    
    hybrid_for_scorecard = resultados[0].get("HYBRID_Global", {}) if resultados else {}
    if hybrid_for_scorecard:
        is_hybrid = hybrid_for_scorecard.get("hybrid_detected", False)
        tenant = hybrid_for_scorecard.get("tenant") or "Desconocido"
        sync_accts = len(hybrid_for_scorecard.get("sync_accounts", []))
        if is_hybrid:
            html_report += f"""
  <div class="card">
    <div class="card-title">Entorno Híbrido</div>
    <div class="card-value">
      <span class="pill good">DETECTADO</span>
    </div>
    <div style="margin-top:6px; color:#667085; font-size:0.9rem;">
      Tenant: <strong>{esc(tenant)}</strong> | Cuentas Sync: <strong>{sync_accts}</strong>
    </div>
  </div>
  """
        else:
            html_report += f"""
  <div class="card">
    <div class="card-title">Entorno Híbrido</div>
    <div class="card-value">
      <span class="pill ok">NO DETECTADO</span>
    </div>
  </div>
  """
    
    shadow_for_scorecard = resultados[0].get("SHADOW_CREDENTIALS_Global", []) if resultados else []
    if shadow_for_scorecard:
        priv_sh = sum(1 for s in shadow_for_scorecard if s.get("severity") == "Critical")
        sh_badge = "bad" if priv_sh > 0 else "warn"
        html_report += f"""
  <div class="card">
    <div class="card-title">Shadow Credentials</div>
    <div class="card-value">
      <span class="pill {sh_badge}">{len(shadow_for_scorecard)} expuestas</span>
    </div>
    <div style="margin-top:6px; color:#667085; font-size:0.9rem;">
      Cuentas Privilegiadas: <strong>{priv_sh}</strong>
    </div>
  </div>
  """

    html_report += f"""
  <div class="card">
    <div class="card-title">Posture Score (Operational Indicator)</div>
    <div class="card-value">{posture_score}/100</div>
    <div style="margin-top:6px; color:#667085; font-size:0.9rem;">Interpretación: <strong>{esc(posture_label)}</strong> — indicador operativo (no CVSS).</div>
  </div>
</div>

<div class="info-block">
  <h2 style="margin-top:0;">Executive Summary</h2>
  <div style="margin: 6px 0 10px 0; color:#667085; font-size:0.95rem;">
    <strong>Risk posture statement (copy/paste):</strong><br>
    <em>{esc(risk_posture_statement)}</em>
  </div>

  <ul style="margin: 0.5rem 0 0 1.2rem;">
    <li><strong>Qué significa DDCC (Sin Ruta Directa):</strong> Significa que un usuario raso (ej. Domain Users) no puede comprometer el dominio de manera automatizada de un solo golpe. NO significa que el entorno sea seguro si hay 'Cadenas de Ataque' que requieran pasos previos (como comprometer una máquina específica o alterar plantillas).</li>
    <li><strong>Por qué es positivo con misconfigurations:</strong> una finding High puede no ser explotable por falta de publicación, permisos efectivos o fricción (aprobación/firma).</li>
    <li><strong>Susceptibilidad residual:</strong> depende de risk paths / near-misses y hallazgos CA-level (ESC7/ESC8). Etiqueta actual: <strong>{esc(attack_susceptibility)}</strong> — {esc(susceptibility_expl)}</li>
    <li><strong>Qué priorizar (operacional):</strong> templates publicadas con enroll efectivo y estado EXPLOITABLE_NOW; luego CA-level ESC7/ESC8 y near-misses/risk paths.</li>
    <li><strong>Confianza/Evidencia:</strong> confidence={esc(ddcc_confidence)}; evidence_level={esc(evidence_level)}.</li>
  </ul>

  <div style="margin-top: 10px; display:flex; gap:10px; flex-wrap:wrap;">
    {ddcc_html_cta}
    {ddcc_json_cta}
  </div>
</div>

<div class="info-block" style="margin-top: 20px;">
  <h2 style="margin-top:0;">Cobertura del Escaneo (Coverage Map)</h2>
  <div style="margin: 6px 0; color:#667085; font-size:0.95rem;">
    Esta tabla refleja las verificaciones técnicas reales soportadas por la herramienta en esta versión.
  </div>
  <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.95rem;">
    <thead>
      <tr style="background-color: #f8f9fa; border-bottom: 2px solid #ddd;">
        <th style="padding: 10px; text-align: left;">Técnica</th>
        <th style="padding: 10px; text-align: left;">Descripción</th>
        <th style="padding: 10px; text-align: center;">Estado</th>
      </tr>
    </thead>
    <tbody>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC1 - ESC8</strong></td>
        <td style="padding: 10px;">Plantillas vulnerables, OBO, Takeover, CA Backdoors, Relay</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC9</strong></td>
        <td style="padding: 10px;">No Security Extension (ByPass KB5014754) con Write Access</td>
        <td style="padding: 10px; text-align: center;"><span class="pill warn">Parcial</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC10</strong></td>
        <td style="padding: 10px;">Weak Certificate Mapping (Registry/UPN)</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC11</strong></td>
        <td style="padding: 10px;">Relay to RPC (NTLM fallback habilitado)</td>
        <td style="padding: 10px; text-align: center;"><span class="pill gray">No Implementado</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC12</strong></td>
        <td style="padding: 10px;">Shell access a CA (YubiKey/Smartcard requerida)</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC13</strong></td>
        <td style="padding: 10px;">OID Group Link Privilege Escalation</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC14</strong></td>
        <td style="padding: 10px;">Weak Explicit Mapping (Write to altSecurityIdentities)</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
      <tr style="border-bottom: 1px solid #eee;">
        <td style="padding: 10px;"><strong>ESC15</strong></td>
        <td style="padding: 10px;">EKAN (Enterprise Key Admin Network) - v1 Schema Bypass</td>
        <td style="padding: 10px; text-align: center;"><span class="pill ok">Completo</span></td>
      </tr>
    </tbody>
  </table>
</div>
  <details style="margin-top: 0.8rem;">
    <summary style="cursor:pointer; font-weight:800;">Score Breakdown</summary>
    <table style="margin-top:0.6rem;">
      <thead><tr><th>Factor</th><th>Delta</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td>{esc(b.get('label'))}</td><td>{int(b.get('delta') or 0)}</td></tr>" for b in score_breakdown)}
        <tr><td><strong>Total</strong></td><td><strong>{posture_score}</strong></td></tr>
      </tbody>
    </table>
  </details>
</div>

<div class="info-block">
  <h2 style="margin-top:0;">Model Confidence & Evidence</h2>
  <p><strong>Confidence:</strong> {esc(ddcc_confidence)}<br>{esc(confidence_expl)}</p>
  <p><strong>Evidence Level:</strong> {esc(evidence_level)} (CLI flag <code>--evidence-level</code>)</p>
</div>

<div class="info-block">
  <strong>Severidad (Critical – Low) no es CVSS</strong><br>
  La severidad Critical-Low describe el <em>impacto de identidad</em> que habilita una plantilla/camino (autenticación, suplantación privilegiada, minting, autoridad). No es una puntuación CVSS ni intenta modelar todas las condiciones de explotación.
</div>

<div class="charts-container">
  <div class="chart-box">
    <h2>Resumen de Vulnerabilidades</h2>
    <canvas id="chartResumen"></canvas>
  </div>
  <div class="chart-box">
    <h2>Plantillas Identificadas</h2>
    <p><strong>Total:</strong> {stats['templates_total']} | <strong>Vulnerables:</strong> {stats['templates_vulnerables']}</p>
    <canvas id="chartTemplates"></canvas>
  </div>
</div>

<script>
new Chart(document.getElementById('chartResumen').getContext('2d'), {{
  type: 'bar',
  data: {{
    labels: ['Critical','High','Medium','Low'],
    datasets: [{{ label:'Cantidad', data:[{stats['critical']},{stats['high']},{stats['medium']},{stats['low']}],
    backgroundColor:['#c62828','#ef6c00','#fbc02d','#2e7d32'] }}]
  }},
  options: {{ plugins: {{ legend: {{ display:false }} }}, scales: {{ y: {{ beginAtZero:true, ticks:{{ stepSize:1 }} }} }} }}
}});
new Chart(document.getElementById('chartTemplates').getContext('2d'), {{
  type:'pie',
  data:{{ labels:['Vulnerables','No vulnerables'],
  datasets:[{{ data:[{stats['templates_vulnerables']},{stats['templates_total'] - stats['templates_vulnerables']}],
  backgroundColor:['#e53935','#43a047'] }}]}},
  options:{{ plugins:{{ legend:{{ position:'bottom' }} }} }}
}});
</script>

<h2>Índice (Detalle por ESC)</h2>
<ul>
{"".join(f"<li><a href='#esc-{esc_name}' onclick='setActiveTab(&quot;tab-esc&quot;)'>{esc_name}</a></li>" for esc_name in esc_present) if esc_present else "<li>Sin hallazgos</li>"}
</ul>
</div>

<div id="tab-top" class="tabcontent">

<h2>Top Findings (Real Risk Score)</h2>
<div class="info-block">
  <p>Ordenado por <strong>risk_score</strong> (priorización operativa) y muestra <strong>Severidad</strong> separada de <strong>Exploitability</strong>.</p>
</div>
<table>
  <thead><tr><th>Plantilla</th><th>risk_score</th><th>Exploitability</th><th>Severidad</th></tr></thead>
  <tbody>
  {"".join(
    f"<tr><td>{esc(t.get('displayName') or t.get('cn') or 'N/A')}</td><td>{int(t.get('risk_score') or 0)}</td><td>{esc(t.get('exploitability_status') or 'UNKNOWN')}</td><td>{esc((t.get('riesgos') or [{}])[0].get('nivel') if t.get('riesgos') else 'Info')}</td></tr>"
    for t in top_findings
  ) if top_findings else "<tr><td colspan='4'>Sin hallazgos</td></tr>"}
  </tbody>
</table>

</div>

<div id="tab-esc-context" class="tabcontent" style="display:none;">

<h2>Default Template Context</h2>
<div class="info-block">
  <p>Contexto para plantillas por defecto. Si no hay certeza, se marca como <strong>unknown</strong>.</p>
</div>
<table>
  <thead><tr><th>Plantilla</th><th>is_default_template</th><th>Exploitability</th><th>Why not exploitable</th></tr></thead>
  <tbody>
  {"".join(
    f"<tr><td>{esc(t.get('displayName') or t.get('cn') or 'N/A')}</td><td>{esc(t.get('is_default_template', 'unknown'))}</td><td>{esc(t.get('exploitability_status') or 'UNKNOWN')}</td><td>{esc('; '.join((t.get('exploitability_reasons') or [])[:6]) or '')}</td></tr>"
    for t in top_findings
  ) if top_findings else "<tr><td colspan='4'>Sin hallazgos</td></tr>"}
  </tbody>
</table>

</div>

<div id="tab-chains" class="tabcontent">
"""
    combo_chains = resultados[0].get("Combo_Chains_Global", []) if resultados else []
    if combo_chains:
        html_report += """
<div class="vulnerability" style="background:#fff3e0; border:1px solid #ffb74d;" id="combo-chains">
  <h2 style="color:#d84315; margin-top:0;">⚡ Attack Chains Detectadas</h2>
"""
        for chain in combo_chains:
            html_report += f"""
  <div class="info-block" style="border-left-color:#d84315; background:#fbe9e7;">
    <h3 style="color:#bf360c; margin-top:0; margin-bottom:8px;">{esc(chain.get('name'))}</h3>
    <p><strong>Severidad:</strong> <span class="severity-badge badge-critical">CRITICAL</span> | <strong>ESCs:</strong> {esc(', '.join(chain.get('escs', [])))}</p>
    <p><strong>Descripción:</strong> {esc(chain.get('description'))}</p>
    <div style="background:#fff; padding:10px; border-radius:6px; border:1px solid #ffccbc;">
      <h4 style="margin-top:0; color:#555;">Pasos del Ataque:</h4>
      <pre style="margin:0; white-space:pre-wrap; font-size:0.9rem;">{esc(chr(10).join(chain.get('steps', [])))}</pre>
    </div>
  </div>
"""
        html_report += "</div>"
    else:
        html_report += """
<div class="info-block" style="border-left-color:#2e7d32; background:#e8f5e9;">
  <h2 style="color:#1b5e20; margin-top:0;">⚡ Attack Chains Detectadas</h2>
  <p>✅ No se detectaron cadenas de ataque en este escaneo. Las chains requieren combinaciones específicas de ESCs activos simultáneamente (ej: ESC4+ESC1, ESC6+ESC9).</p>
</div>
"""
    html_report += "</div>\n"

    html_report += """
<div id="tab-esc" class="tabcontent">
<h2>Detalle por Tipo de Vulnerabilidad</h2>
"""

    for esc_name in esc_present:
        data = grouped[esc_name]
        vulns_sorted = sorted(
            data["vulnerabilities"],
            key=lambda v: (int(v.get("risk_score") or 0), SEV_ORDER.get(v.get("level", "Info"), 0)),
            reverse=True
        )

        levels = [v.get("level", "Info") for v in data["vulnerabilities"]]
        sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        max_level = max(levels, key=lambda x: sev_map.get(x, 0)) if levels else "Info"
        badge_cls = f"badge-{max_level.lower()}"

        html_report += f"""
<div class="vulnerability" id="esc-{esc_name}">
  <h3>{esc(esc_name)} <span class="severity-badge {badge_cls}">{max_level.upper()}</span></h3>
  <div class="info-block"><strong>Descripción:</strong><br>{esc(data['description'])}</div>
  <div class="info-block"><strong>Explotación paso a paso:</strong><br><pre>{esc(data['exploitation'])}</pre></div>
  <div class="info-block"><strong>Mitigación:</strong><br>{esc(data['mitigation'])}</div>
  <p><strong>Plantillas afectadas:</strong> {len(vulns_sorted)}</p>
  <table>
    <thead><tr><th>Plantilla</th><th>Detalles</th><th>Severidad</th><th>Exploitability</th><th>risk_score</th></tr></thead>
    <tbody>
"""

        for v in vulns_sorted:
            # Replaced manual HTML escape for details so we don't destroy our <span tags>
            details_html = "<br>".join(
                line if "<span style=" in line else esc(line) 
                for line in v["details"]
            )
            lvl = esc(v.get("level", "Info"))
            exp = esc(v.get("exploitability_status") or "UNKNOWN")
            rs = esc(v.get("risk_score") or 0)
            badge_extra = ""
            if esc_name == "ESC6":
                badge_extra = "&nbsp;<span style='background:#e67e22;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem;font-weight:bold;'>⚠️ Requiere confirmación RPC</span>"

            html_report += f"""
      <tr>
        <td>{esc(v['template'])}{badge_extra}</td>
        <td>{details_html}</td>
        <td>{lvl}</td>
        <td>{exp}</td>
        <td>{rs}</td>
      </tr>"""
            playbook = v.get("remediation_playbook")
            if playbook:
                cmds_html = "".join([f"<li><code>{esc(cmd)}</code></li>" for cmd in playbook.get("commands", [])])
                refs_html = "".join([f"<li><a href='{esc(ref)}' target='_blank'>{esc(ref)}</a></li>" for ref in playbook.get("refs", [])])
                html_report += f"""
      <tr>
        <td colspan="5" style="padding: 0; border: none; background: #fafafa;">
          <details style="margin: 5px 10px 15px; border: 1px solid #ccc; border-radius: 4px;">
            <summary style="padding: 10px; background: #e0f7fa; font-weight: bold; cursor: pointer; color: #006064;">🔧 Cómo arreglarlo (Playbook {esc(esc_name)})</summary>
            <div style="padding: 10px; border-top: 1px solid #ccc;">
              <p><strong>Riesgo:</strong> {esc(playbook.get('risk', 'N/A'))} | <strong>Tiempo estimado:</strong> {esc(playbook.get('time_estimate', 'N/A'))}</p>
              <h4 style="margin: 10px 0 5px;">Comandos:</h4>
              <ul style="background: #272822; color: #f8f8f2; padding: 10px 20px; border-radius: 4px; font-family: monospace;">
                {cmds_html}
              </ul>
              """
                if refs_html:
                    html_report += f"<h4 style='margin: 10px 0 5px;'>Referencias:</h4><ul>{refs_html}</ul>"
                html_report += """
            </div>
          </details>
        </td>
      </tr>"""

        html_report += """
    </tbody>
  </table>
</div>
"""

    esc5_global = resultados[0].get("ESC5_Global", []) if resultados else []
    esc14_global = resultados[0].get("ESC14_Global", []) if resultados else []
    esc10_global = resultados[0].get("ESC10_Global", {}) if resultados else {}
    esc12_global = resultados[0].get("ESC12_Global", []) if resultados else []
    certifried_global = resultados[0].get("CERTIFRIED_Global", {}) if resultados else {}
    shadow_global = resultados[0].get("SHADOW_CREDENTIALS_Global", []) if resultados else []
    hybrid_global = resultados[0].get("HYBRID_Global", {}) if resultados else {}

    html_report += """
<div class="vulnerability" style="background:#fdfdfd; border:1px solid #ccc;" id="esc-globals">
  <h3 style="color:#555;">🌍 Evaluaciones Globales de Infraestructura</h3>
"""
    if hybrid_global and hybrid_global.get("hybrid_detected"):
        tenant = hybrid_global.get("tenant") or "Desconocido"
        accts = hybrid_global.get("sync_accounts", [])
        
        html_report += f"""<div class="info-block" style="border-left-color:#2980b9;">
    <h4 style="margin:0;">Análisis de Entorno Híbrido (Tenant: {esc(tenant)})</h4>
    <p>{esc(hybrid_global.get("impact_statement", ""))}</p>
    """
        if accts:
            html_report += "<ul>"
            for a in accts:
                risks_str = ", ".join(a.get("risks", []))
                if risks_str:
                    risks_str = f" - <strong style='color:#c62828;'>Riesgos: {esc(risks_str)}</strong>"
                html_report += f"<li><strong>{esc(a.get('samAccountName'))}</strong> (Pwd Age: {a.get('pwd_age_days')} días){risks_str}</li>"
            html_report += "</ul>"
            
        html_report += "<p><strong>Verificaciones manuales requeridas en Azure:</strong></p><ul>"
        for v in hybrid_global.get("cloud_verification_required", []):
            html_report += f"<li>{esc(v)}</li>"
        html_report += "</ul></div>"
    if esc5_global:
        html_report += f"""<div class="info-block" style="border-left-color:#ef6c00;">
    <h4 style="margin:0;">ESC5 (PKI Object ACLs Inseguras)</h4>"""
        for e5 in esc5_global:
            dn_val = esc(e5.get('dn', ''))
            html_report += f"<div style='margin-bottom:8px;'><p style='margin:0;'><strong>{dn_val}</strong></p><ul>"
            for d in e5.get('ESC5_Details', []):
                rights = ", ".join(d.get("rights", []))
                html_report += f"<li>{esc(d.get('principal', ''))} &rarr; {esc(rights)}</li>"
            html_report += "</ul></div>"
        html_report += "</div>"

    if esc14_global:
        html_report += f"""<div class="info-block" style="border-left-color:#8e44ad;">
    <h4 style="margin:0;">ESC14 (Explicit Certificate Mapping)</h4>"""
        for e14 in esc14_global:
            html_report += f"<p><strong>[{esc(e14.get('status'))}] {esc(e14.get('target_account'))}</strong>: {esc(e14.get('mapping_type'))} - Severidad: {esc(e14.get('severity'))}<br>Atacante: {esc(e14.get('attacker_account'))}</p>"
        html_report += "</div>"
        
    if esc10_global:
        html_report += f"""<div class="info-block" style="border-left-color:#2980b9;">
    <h4 style="margin:0;">ESC10 (Weak Certificate Mapping)</h4>
    <p><strong>[{esc(esc10_global.get('status'))}]</strong> {esc(esc10_global.get('reason'))}</p>
    <p><em>Nota:</em> {esc(esc10_global.get('note', ''))}</p>
</div>"""

    if esc12_global:
        html_report += f"""<div class="info-block" style="border-left-color:#27ae60;">
    <h4 style="margin:0;">ESC12 (YubiHSM CA / Web Enrollment)</h4>"""
        for e12 in esc12_global:
            html_report += f"<p><strong>[{esc(e12.get('status'))}] {esc(e12.get('ca_host'))}</strong>: {esc(e12.get('note', ''))}</p>"
        html_report += "</div>"
        
    if certifried_global:
        status = certifried_global.get("status", "SAFE")
        badge = "badge-critical" if status in ["EXPLOITABLE", "NEAR_MISS"] else "badge-low"
        html_report += f"""<div class="info-block" style="border-left-color:#c62828;">
    <h4 style="margin:0;">Certifried (CVE-2022-26923) <span class="severity-badge {badge}">⚡ CVE-2022-26923</span></h4>
    <p><strong>[{esc(status)}]</strong> Quota: {esc(str(certifried_global.get('machine_account_quota')))} | Plantilla: {esc(str(certifried_global.get('machine_template_published')))}</p>
</div>"""

    if shadow_global:
        # Separate privileged vs non-privileged
        priv_accounts = [sh for sh in shadow_global if sh.get("severity") == "Critical"]
        non_priv_accounts = [sh for sh in shadow_global if sh.get("severity") != "Critical"]
        
        html_report += f"""<div class="info-block" style="border-left-color:#34495e;">
    <h4 style="margin:0; margin-bottom:15px;">Shadow Credentials ({len(shadow_global)} cuentas expuestas)</h4>
    <table class="data-table">
        <thead>
            <tr>
                <th>Severidad</th>
                <th>Cuenta Target</th>
                <th>Permiso Abusado</th>
                <th>Atacante</th>
                <th>Estado</th>
            </tr>
        </thead>
        <tbody>
"""
        for sh in shadow_global:
            sev = sh.get("severity", "Info")
            sev_class = "badge-critical" if sev == "Critical" else "badge-high" if sev == "High" else "badge-low"
            html_report += f"""            <tr>
                <td><span class="severity-badge {sev_class}">{esc(sev)}</span></td>
                <td><strong>{esc(sh.get("target_account"))}</strong></td>
                <td>{esc(sh.get("mapping_type"))}</td>
                <td>{esc(sh.get("attacker_account"))}</td>
                <td>{esc(sh.get("status"))}</td>
            </tr>
"""
        html_report += """        </tbody>
    </table>
</div>"""
        
    html_report += "</div>"
    html_report += "</div>"  # end tab-esc



    # TAB DIFF
    if diff_summary:
        html_report += """<div id="tab-diff" class="tabcontent">"""
        html_report += f"<h3>Comparativa respecto al reporte: <code>{esc(diff_summary.get('prev_file', ''))}</code></h3>"
        
        nuevas = diff_summary.get("nuevas", [])
        if nuevas:
            html_report += "<div class='info-block' style='border-left-color:#c62828;'><h4 style='margin:0;color:#c62828;'>🚨 Nuevas Vulnerabilidades Detectadas</h4><ul>"
            for n in nuevas:
                html_report += f"<li><strong>{esc(n['template'])}</strong> (Risk Score: {n['risk_score']})</li>"
            html_report += "</ul></div>"
        
        resueltas = diff_summary.get("resueltas", [])
        if resueltas:
            html_report += "<div class='info-block' style='border-left-color:#2e7d32;'><h4 style='margin:0;color:#2e7d32;'>✅ Vulnerabilidades Resueltas</h4><ul>"
            for r in resueltas:
                html_report += f"<li><strong>{esc(r['template'])}</strong>: {esc(r['reason'])}</li>"
            html_report += "</ul></div>"
            
        cambios_risk = diff_summary.get("cambios_risk", [])
        if cambios_risk:
            html_report += "<div class='info-block' style='border-left-color:#ef6c00;'><h4 style='margin:0;color:#ef6c00;'>⚠️ Cambios en Risk Score</h4><ul>"
            for c in cambios_risk:
                flecha = "⬆️ Subió" if c['delta'] > 0 else "⬇️ Bajó"
                html_report += f"<li><strong>{esc(c['template'])}</strong>: {c['old_risk']} → {c['new_risk']} ({flecha})</li>"
            html_report += "</ul></div>"
            
        if not nuevas and not resueltas and not cambios_risk:
            html_report += "<p>No hubo cambios significativos en las plantillas respecto al escaneo anterior.</p>"
            
        html_report += "</div>"

    ddcc_html = ""
    if ddcc_report is not None:
        try:
            from modules.report_json import _ddcc_resultado, _build_ddcc_block
            ddcc_block = _build_ddcc_block(ddcc_report)
            resultado = ddcc_block.get("resultado", "SAFE_NO_DATA")
            is_comp = bool(getattr(ddcc_report, "is_compromisable", False))
            det_paths_list = getattr(ddcc_report, "deterministic_critical_paths", []) or []
            risk_paths_list = getattr(ddcc_report, "non_deterministic_risk_paths", []) or []
            near_misses_list = ddcc_block.get("near_misses", [])
            root_cause_list = ddcc_block.get("root_cause_analysis", [])
            eval_summary = ddcc_block.get("evaluation_summary", {})
            condicion_faltante = ddcc_block.get("condicion_faltante", "")
            confidence = ddcc_block.get("confidence_level", "UNKNOWN")
            razon = ddcc_block.get("razon", "")

            # Verdict hero config
            hero_class_map = {
                "COMPROMISED": "compromised",
                "NEAR_MISS": "near-miss",
                "SAFE_ANALYZED": "safe-analyzed",
                "SAFE_NO_DATA": "safe-no-data",
            }
            hero_label_map = {
                "COMPROMISED": "⚔️ COMPROMISED",
                "NEAR_MISS": "⚠️ NEAR MISS",
                "SAFE_ANALYZED": "✅ SAFE — Analyzed",
                "SAFE_NO_DATA": "🔍 SAFE — No Data",
            }
            hero_sub_map = {
                "COMPROMISED": "Se encontraron paths determinísticos low-trust → L3+ vía AD CS.",
                "NEAR_MISS": "No hay paths determinísticos pero existen risk paths Human-in-the-Loop.",
                "SAFE_ANALYZED": "Análisis completo. No se encontraron paths críticos desde entrypoints low-trust.",
                "SAFE_NO_DATA": "El motor analizó templates pero no encontró enroll principals efectivos para construir paths.",
            }
            hero_class = hero_class_map.get(resultado, "safe-no-data")
            hero_label = hero_label_map.get(resultado, resultado)
            hero_sub = hero_sub_map.get(resultado, "")

            # Model telemetry grid
            telem_items = [
                ("total_templates_evaluated", "Templates evaluadas"),
                ("published_templates_count", "Templates publicadas"),
                ("templates_with_effective_enroll_count", "Con enroll efectivo"),
                ("templates_with_low_trust_intersection_count", "Low-trust reachable"),
                ("deterministic_edges_created", "Edges determinísticos"),
                ("risk_edges_created", "Edges de riesgo"),
                ("discarded_not_published", "Descartadas (no publicada)"),
                ("discarded_no_enroll_principals", "Descartadas (sin enroll)"),
                ("discarded_no_low_trust_intersection", "Descartadas (sin low-trust)"),
                ("discarded_manager_approval", "Descartadas (manager approval)"),
            ]
            telemetry_html = "<div class='telemetry-row'>"
            for key, label in telem_items:
                val = int(eval_summary.get(key, 0) or 0)
                telemetry_html += f"<div class='telemetry-item'><div class='t-val'>{val}</div><div class='t-lbl'>{esc(label)}</div></div>"
            telemetry_html += "</div>"

            # Near-miss cards
            near_miss_html = ""
            if near_misses_list:
                near_miss_html = "<h3 style='margin-top:1.5rem;'>⚠️ Near Misses</h3>"
                for nm in near_misses_list:
                    tpl_nm = esc(nm.get("template_name", "?"))
                    frictions = esc(", ".join(nm.get("friction_factors", []) or []) or "—")
                    principals_nm = esc(", ".join(nm.get("effective_enroll_principals", [])[:4] or []) or "—")
                    low_trust = "Sí" if nm.get("low_trust_intersection") else "No"
                    near_miss_html += f"""<div class='near-miss-card'>
  <strong>{tpl_nm}</strong><br>
  <span>Friction: {frictions}</span><span style='margin-left:12px;'>Low-trust reachable: {low_trust}</span><br>
  <span>Principals: {principals_nm}</span>
</div>"""

            # Attack paths table (deterministic)
            paths_html = ""
            if det_paths_list:
                paths_html = "<h3 style='margin-top:1.5rem;color:#b71c1c;'>⚔️ Attack Paths</h3><table>"
                paths_html += "<thead><tr><th>#</th><th>Descripción</th><th>Hops</th><th>Confianza</th></tr></thead><tbody>"
                for i, path in enumerate(det_paths_list[:10], 1):
                    desc = esc(getattr(path, "description", ""))
                    length = len(getattr(path, "edges", []) or [])
                    conf = esc(getattr(path, "confidence", "unknown"))
                    paths_html += f"<tr><td>{i}</td><td>{desc}</td><td>{length}</td><td>{conf}</td></tr>"
                paths_html += "</tbody></table>"
            elif risk_paths_list:
                paths_html = "<h3 style='margin-top:1.5rem;color:#ef6c00;'>🛡️ Risk Paths (Human-in-the-Loop)</h3><table>"
                paths_html += "<thead><tr><th>#</th><th>Descripción</th><th>Hops</th></tr></thead><tbody>"
                for i, path in enumerate(risk_paths_list[:10], 1):
                    desc = esc(getattr(path, "description", ""))
                    length = len(getattr(path, "edges", []) or [])
                    paths_html += f"<tr><td>{i}</td><td>{desc}</td><td>{length}</td></tr>"
                paths_html += "</tbody></table>"

            # Root cause
            root_cause_html = ""
            if root_cause_list:
                items_html = "".join(f"<li>{esc(rc)}</li>" for rc in root_cause_list)
                root_cause_html = f"<div class='info-block'><strong>Root Cause Analysis:</strong><ul style='margin:0.5rem 0 0 1.2rem;'>{items_html}</ul></div>"

            # Condicion faltante
            cond_html = ""
            if condicion_faltante:
                cond_html = f"<div class='info-block' style='border-left-color:#90a4ae;'><strong>Condición que impidió paths críticos:</strong><br><code>{esc(condicion_faltante)}</code></div>"

            ddcc_html = f"""
<div class='ddcc-hero {hero_class}'>
  <div class='ddcc-verdict-label'>{hero_label}</div>
  <div class='ddcc-verdict-sub'>{esc(hero_sub)}</div>
  <div style='margin-top:1rem; opacity:0.9; font-size:0.93rem;'>
    Confidence: <strong>{esc(confidence)}</strong> &nbsp;|&nbsp;
    Paths determinísticos: <strong>{len(det_paths_list)}</strong> &nbsp;|&nbsp;
    Risk paths: <strong>{len(risk_paths_list)}</strong> &nbsp;|&nbsp;
    Near misses: <strong>{len(near_misses_list)}</strong>
  </div>
</div>

<h3>📊 Model Telemetry</h3>
{telemetry_html}

<div class='info-block' style='border-left-color:#90a4ae; margin-top:0.5rem;'>
  <strong>Evidence:</strong> {esc(razon)}
</div>

{root_cause_html}
{cond_html}
{near_miss_html}
{paths_html}
"""
        except Exception as e:
            ddcc_html = f"<div class='info-block'><strong>DDCC Summary</strong><br>Error generando bloque DDCC: {esc(str(e))}</div>"
    else:
        ddcc_html = "<div class='info-block'><strong>DDCC</strong><br>No se recibió objeto DDCC. Verifica que el motor corrió correctamente y que existen enroll_principals en las plantillas publicadas.</div>"

    html_report += f"""
<div id="tab-ddcc" class="tabcontent">
  <h2>DDCC — Deterministic Domain Compromise Check</h2>
  {ddcc_html}
  <div class='info-block'>
    <strong>Nota:</strong> El detalle granular de paths, evidencia full y telemetría extendida se entrega en el reporte DDCC HTML dedicado.
    {ddcc_html_cta}
  </div>
</div>
"""


    html_report += f"""
<div id="tab-glosario" class="tabcontent">
  <h2>Glosario & Leyendas</h2>
  <div class='info-block'>
    <strong>L1–L5 (IdentitySeverity)</strong>
    <ul style="margin: 0.5rem 0 0 1.2rem;">
      <li><strong>L1:</strong> Self authentication — ejemplo: un usuario obtiene un certificado para autenticarse como sí mismo.</li>
      <li><strong>L2:</strong> Arbitrary user authentication — ejemplo: suplantar a otro usuario estándar vía SAN/UPN controlable.</li>
      <li><strong>L3:</strong> Privileged authentication (validated) — ejemplo: autenticación como miembro de un grupo privilegiado explícitamente validado.</li>
      <li><strong>L4:</strong> Identity minting / delegation severe — ejemplo: Enrollment Agent permite emitir credenciales para terceros (delegación/impersonation).</li>
      <li><strong>L5:</strong> Authority compromise (CA-level) — ejemplo: SubCA/CA-level authority permite emitir confianza amplia (impacto sistémico).</li>
    </ul>
  </div>
  <div class='info-block'>
    <strong>Exploitability Status</strong>
    <ul style="margin: 0.5rem 0 0 1.2rem;">
      <li><strong>EXPLOITABLE_NOW:</strong> Publicada, con enroll efectivo y sin fricción relevante. Acción: priorizar mitigación inmediata.</li>
      <li><strong>NOT_EXPLOITABLE_NOT_PUBLISHED:</strong> No publicada; no explotable vía inscripción. Acción: monitorear cambios de publicación.</li>
      <li><strong>NOT_EXPLOITABLE_NO_EFFECTIVE_ENROLL:</strong> No hay principals con enroll/autoenroll efectivo. Acción: revisar permisos y evitar ampliación accidental.</li>
      <li><strong>NOT_EXPLOITABLE_FRICTION:</strong> Requiere aprobación o firmas; depende de humano. Acción: validar controles de aprobación y signers.</li>
      <li><strong>REQUIRES_LAB_VALIDATION:</strong> La evidencia es insuficiente o depende de edge cases (EKU desconocido/AnyPurpose). Acción: validar en laboratorio y recolectar evidencia full si aplica.</li>
    </ul>
  </div>
  <div class='info-block'>
    <strong>DDCC (Deterministic Domain Compromise Check)</strong><br>
    <ul style="margin: 0.5rem 0 0 1.2rem;">
      <li><strong>Qué responde:</strong> ¿existe una cadena <em>determinística</em> low-trust→L3+ vía AD CS con la evidencia recolectada?</li>
      <li><strong>Qué NO responde:</strong> no modela toda la superficie del dominio (solo AD CS + datos disponibles en el run).</li>
      <li><strong>Qué requiere validación:</strong> casos con <code>requires_lab_validation</code> (EKU desconocido/AnyPurpose) pueden necesitar evidencia <em>full</em> y pruebas prácticas.</li>
    </ul>
  </div>
  <div class='info-block'>
    <strong>Por qué puede salir SAFE aunque existan misconfigurations</strong>
    <ul style="margin: 0.5rem 0 0 1.2rem;">
      <li>Plantillas no publicadas no son explotables vía inscripción, aunque tengan propiedades de alto impacto.</li>
      <li>Permisos de enroll efectivos restringidos impiden interacción low-trust (sin entrypoint real).</li>
      <li>Fricción (aprobaciones/firma) y/o confianza reducida (requires_lab_validation) degrada caminos determinísticos.</li>
    </ul>
  </div>
  <div class='info-block'>
    <strong>Confidence</strong>
    <ul style="margin: 0.5rem 0 0 1.2rem;">
      <li><strong>high:</strong> Modelado determinístico con condiciones observables.</li>
      <li><strong>medium:</strong> Lógicamente viable pero con fricción/human-in-the-loop o limitaciones de resolución.</li>
      <li><strong>requires_lab_validation:</strong> Necesita verificación práctica (OID desconocido/AnyPurpose/edge cases).</li>
    </ul>
  </div>
</div>
"""

    html_report += f"""
<div id="tab-evidencia" class="tabcontent">
  <h2>Evidencia de Campo (Queries LDAP)</h2>
  <div class="info-block" style="border-left-color:#546e7a;">
    <p>Los siguientes filtros y atributos LDAP fueron utilizados para extraer la información analizada en este reporte:</p>
    <ul>
      <li><strong>CAs y Servicios de Inscripción:</strong> <code>(objectClass=pKIEnrollmentService)</code>, <code>(objectClass=certificationAuthority)</code> en <code>CN=Configuration</code></li>
      <li><strong>Plantillas de Certificados:</strong> <code>(objectClass=pKICertificateTemplate)</code></li>
      <li><strong>Certifried (ESC15/CVE-2022-26923):</strong> <code>(objectClass=domain)</code> &rarr; <code>ms-DS-MachineAccountQuota</code></li>
      <li><strong>Shadow Credentials:</strong> <code>(|(objectClass=user)(objectClass=computer))</code> &rarr; <code>msDS-KeyCredentialLink</code>, <code>nTSecurityDescriptor</code></li>
      <li><strong>Explicit Mapping (ESC14):</strong> <code>(|(objectClass=user)(objectClass=computer))</code> &rarr; <code>altSecurityIdentities</code></li>
      <li><strong>Hybrid Environment:</strong> <code>(name=Microsoft Azure AD Connect)</code>, <code>(|(samAccountName=MSOL_*)(samAccountName=AAD_*)(samAccountName=Sync_*))</code></li>
    </ul>
  </div>
</div>
"""

    # Add button to tab bar for "Evidencia"
    html_report = html_report.replace(
        """  <button class="tab-btn" data-tab="tab-glosario">Glosario</button>""",
        """  <button class="tab-btn" data-tab="tab-glosario">Glosario</button>\n  <button class="tab-btn" data-tab="tab-evidencia">Evidencia de Campo</button>"""
    )

    html_report += f"""
<footer>
  <p>Reporte generado por ESCepcion v{version} — {now}</p>
  <p style="font-size:0.8rem; opacity:0.8; max-width:800px; margin:0 auto; padding-top:10px;">
    Este reporte cubre la superficie on-premises de AD CS. Para análisis completo del entorno híbrido incluyendo 
    Entra ID, CBA policies y Conditional Access, se requiere módulo --hybrid-scan (disponible en v2.0).
  </p>
</footer>
</body>
</html>
"""

    out_name = f"ESCepcion_Reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    base_out = output_dir or os.getcwd()
    out_path = os.path.join(base_out, out_name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"[OK] Reporte HTML generado exitosamente: {out_path}")
    return out_path
