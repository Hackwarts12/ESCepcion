import json
import os
from datetime import datetime
from typing import List, Dict, Any
from modules.graph.models import AttackPath
from modules.analysis.ddcc import DomainCompromiseReport

REPORT_VERSION = "ddcc-report/1.0"

def format_path_for_json(path: AttackPath, evidence_level: str = "summary") -> Dict[str, Any]:
    edges_data = []
    
    for edge in getattr(path, "edges", []) or []:
        outcome = getattr(edge, "outcome", None)
        evidence = getattr(outcome, "evidence", None) if outcome else None
        if not isinstance(evidence, dict):
            evidence = {}
        
        # Determine if we should trim evidence based on args
        if evidence_level == "summary":
            trimmed_evidence = {
                "observed_ekus": evidence.get("observed_ekus", []),
                "observed_flags": evidence.get("observed_flags", []),
                "issuance_reqs": evidence.get("issuance_reqs", {}),
                "inferred_capabilities": evidence.get("inferred_capabilities", []),
                "confidence": evidence.get("confidence", "unknown"),
                "severity_reasons": evidence.get("severity_reasons", []),
                "notes": evidence.get("notes", [])
            }
        else:
            trimmed_evidence = evidence # Full evidence
            
        edge_data = {
            "source_principal": getattr(edge, "source_principal", ""),
            "edge_type": edge.edge_type.name if hasattr(getattr(edge, "edge_type", None), 'name') else str(getattr(edge, "edge_type", "")),
            "template": getattr(edge, "template_name", ""),
            "capability": edge.capability.name if hasattr(getattr(edge, "capability", None), 'name') else str(getattr(edge, "capability", "")),
            "outcome": {
                "severity": outcome.severity.name if outcome and hasattr(getattr(outcome, "severity", None), 'name') else str(getattr(outcome, "severity", "UNKNOWN") if outcome else "UNKNOWN"),
                "target_identity": getattr(outcome, "target_identity", "Unknown") if outcome else "Unknown",
            },
            "explanations": getattr(edge, "explanations", []) or [],
            "evidence": trimmed_evidence
        }
        edges_data.append(edge_data)

    edges = getattr(path, "edges", []) or []
    target_outcome = edges[-1].outcome if edges else None
    target_evidence = getattr(target_outcome, "evidence", None) if target_outcome else None
    if not isinstance(target_evidence, dict):
        target_evidence = {}

    return {
        "path_id": hash(path.description) & 0xfffffff, # Simple ID
        "start_principal": getattr(path, "start_principal", ""),
        "end_outcome": {
            "severity": target_outcome.severity.name if target_outcome and hasattr(getattr(target_outcome, "severity", None), 'name') else "UNKNOWN",
            "target_identity": getattr(target_outcome, "target_identity", "Unknown") if target_outcome else "Unknown",
        },
        "confidence": getattr(path, "confidence", None) or target_evidence.get("confidence", "unknown"),
        "length": getattr(path, "length", len(edges)),
        "description": getattr(path, "description", ""),
        "max_severity": getattr(getattr(path, "max_severity", None), "name", "UNKNOWN"),
        "reasons": getattr(path, "reasons", None) or target_evidence.get("severity_reasons", []),
        "edges": edges_data
    }

def generate_ddcc_json(report: DomainCompromiseReport, domain: str, dc_ip: str, output_dir: str, top_paths: int = 3, include_non_deterministic: bool = True, evidence_level: str = "summary"):
    
    det_paths = getattr(report, "deterministic_critical_paths", []) or []
    risk_paths = getattr(report, "non_deterministic_risk_paths", []) or []
    summary_obj = getattr(report, "evaluation_summary", None)
    near_misses = getattr(report, "near_misses", None)
    if near_misses is None:
        near_misses = getattr(report, "near_miss_paths", []) or []

    sorted_det = sorted(det_paths, key=lambda p: (-getattr(p, "severity", 0), getattr(p, "length", 0)))[:top_paths]
    
    sorted_risk = []
    if include_non_deterministic:
        sorted_risk = sorted(risk_paths, key=lambda p: (-getattr(p, "severity", 0), getattr(p, "length", 0)))[:top_paths]

    near_misses = getattr(report, "near_misses", None)
    if near_misses is None:
        near_misses = getattr(report, "near_miss_paths", []) or []

    # Collect stats
    det_counts = {}
    risk_counts = {}
    
    for p in det_paths:
        edges = getattr(p, "edges", []) or []
        sev = edges[-1].outcome.severity.name if edges and hasattr(getattr(edges[-1].outcome, "severity", None), 'name') else "UNKNOWN"
        det_counts[sev] = det_counts.get(sev, 0) + 1
        
    for p in risk_paths:
        edges = getattr(p, "edges", []) or []
        sev = edges[-1].outcome.severity.name if edges and hasattr(getattr(edges[-1].outcome, "severity", None), 'name') else "UNKNOWN"
        risk_counts[sev] = risk_counts.get(sev, 0) + 1

    json_output = {
        "report_version": REPORT_VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "domain": domain,
        "dc": dc_ip,
        "ddcc": report.is_compromisable,
        "confidence_level": getattr(report, "confidence_level", "UNKNOWN"),
        "summary": {
            "deterministic_paths_count": len(det_paths),
            "non_deterministic_paths_count": len(risk_paths),
            "severity_counts_deterministic": det_counts,
            "severity_counts_risk": risk_counts
        },
        "evaluation_summary": {
            "sources_used": getattr(summary_obj, "sources_used", []) if summary_obj else [],
            "total_templates_evaluated": getattr(summary_obj, "total_templates_evaluated", 0) if summary_obj else 0,
            "discarded_not_published": getattr(summary_obj, "discarded_not_published", 0) if summary_obj else 0,
            "discarded_no_enroll_principals": getattr(summary_obj, "discarded_no_enroll_principals", 0) if summary_obj else 0,
            "discarded_no_low_trust_intersection": getattr(summary_obj, "discarded_no_low_trust_intersection", 0) if summary_obj else 0,
            "discarded_manager_approval": getattr(summary_obj, "discarded_manager_approval", 0) if summary_obj else 0,
            "discarded_authorized_signatures": getattr(summary_obj, "discarded_authorized_signatures", 0) if summary_obj else 0,
            "discarded_flag_restrictions": getattr(summary_obj, "discarded_flag_restrictions", 0) if summary_obj else 0,
            "total_edges_generated": getattr(summary_obj, "total_edges_generated", 0) if summary_obj else 0,
            "total_paths_attempted": getattr(summary_obj, "total_paths_attempted", 0) if summary_obj else 0,
        },
        "DDCC_EVALUATION_SUMMARY": {
            "sources_used": getattr(summary_obj, "sources_used", []) if summary_obj else [],
            "total_templates_evaluated": getattr(summary_obj, "total_templates_evaluated", 0) if summary_obj else 0,
            "discarded_not_published": getattr(summary_obj, "discarded_not_published", 0) if summary_obj else 0,
            "discarded_no_enroll_principals": getattr(summary_obj, "discarded_no_enroll_principals", 0) if summary_obj else 0,
            "discarded_no_low_trust_intersection": getattr(summary_obj, "discarded_no_low_trust_intersection", 0) if summary_obj else 0,
            "discarded_manager_approval": getattr(summary_obj, "discarded_manager_approval", 0) if summary_obj else 0,
            "discarded_authorized_signatures": getattr(summary_obj, "discarded_authorized_signatures", 0) if summary_obj else 0,
            "discarded_flag_restrictions": getattr(summary_obj, "discarded_flag_restrictions", 0) if summary_obj else 0,
            "total_edges_generated": getattr(summary_obj, "total_edges_generated", 0) if summary_obj else 0,
            "total_paths_attempted": getattr(summary_obj, "total_paths_attempted", 0) if summary_obj else 0,
        },
        "near_misses": [
            {
                "template_name": m.template_name,
                "published": m.published,
                "effective_enroll_principals": m.effective_enroll_principals,
                "low_trust_intersection": m.low_trust_intersection,
                "friction_factors": m.friction_factors,
                "severity": m.severity
            } for m in (near_misses or [])
        ],
        "near_miss_paths": [
            {
                "template_name": m.template_name,
                "published": m.published,
                "effective_enroll_principals": m.effective_enroll_principals,
                "low_trust_intersection": m.low_trust_intersection,
                "friction_factors": m.friction_factors,
                "severity": m.severity
            } for m in (near_misses or [])
        ],
        "root_cause_analysis": getattr(report, "root_cause_analysis", []) or [],
        "deterministic_critical_paths": [format_path_for_json(p, evidence_level) for p in sorted_det],
        "non_deterministic_risk_paths": [format_path_for_json(p, evidence_level) for p in sorted_risk],
        "model_limitations": [
            "Requires Lab Validation items are excluded from deterministic paths.",
            "Cross-forest trust capabilities mapped as non-deterministic until proven."
        ]
    }
    
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{domain.replace('.', '_')}_DDCC.json")
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=4)
        
    return out_path

def generate_ddcc_html(report: DomainCompromiseReport, domain: str, dc_ip: str, output_dir: str, top_paths: int = 3, include_non_deterministic: bool = True, evidence_level: str = "summary"):
    det_paths = getattr(report, "deterministic_critical_paths", []) or []
    risk_paths = getattr(report, "non_deterministic_risk_paths", []) or []
    summary_obj = getattr(report, "evaluation_summary", None)
    sorted_det = sorted(det_paths, key=lambda p: (-getattr(p, "severity", 0), getattr(p, "length", 0)))[:top_paths]
    
    sorted_risk = []
    if include_non_deterministic:
        sorted_risk = sorted(risk_paths, key=lambda p: (-getattr(p, "severity", 0), getattr(p, "length", 0)))[:top_paths]

    near_misses = getattr(report, "near_misses", None)
    if near_misses is None:
        near_misses = getattr(report, "near_miss_paths", []) or []

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDCC Report - {domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ padding: 10px 20px; border-radius: 5px; font-weight: bold; font-size: 1.2em; }}
        .badge.yes {{ background-color: #e74c3c; color: white; }}
        .badge.no {{ background-color: #27ae60; color: white; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .section-title {{ color: #2c3e50; border-bottom: 2px solid #bdc3c7; padding-bottom: 10px; margin-top: 40px; }}
        .path-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; border-left: 5px solid #bdc3c7; }}
        .path-critical {{ border-left-color: #e74c3c; }}
        .path-risk {{ border-left-color: #f39c12; }}
        .sev-badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-size: 0.8em; font-weight: bold; margin-bottom: 10px; background: #34495e; color: white; }}
        .sev-L5 {{ background: #c0392b; }}
        .sev-L4 {{ background: #d35400; }}
        .sev-L3 {{ background: #e67e22; }}
        .sev-L2 {{ background: #f39c12; }}
        .sev-L1 {{ background: #f1c40f; color: #333; }}
        .notes-warning {{ background: #ffeaa7; padding: 10px; border-left: 4px solid #fdcb6e; margin-top: 10px; font-weight: bold; color: #d35400; }}
        .evidence-btn {{ background: #3498db; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; margin-top: 10px; }}
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1 style="margin:0;">DDCC — Deterministic Domain Compromise Check</h1>
        <p style="margin:5px 0 0 0; opacity:0.8;">Target: {domain} | DC: {dc_ip} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    </div>
    <div style="display:flex; flex-direction:column; align-items:flex-end;">
        <div class="badge {'yes' if report.is_compromisable else 'no'}">
            DDCC = {"YES (Exploitable)" if report.is_compromisable else "NO (Secured)"}
        </div>
        <div style="margin-top:5px; font-size:0.9em; font-weight:bold; color:{'#e74c3c' if report.confidence_level == 'LOW' else '#f1c40f' if report.confidence_level == 'MEDIUM' else '#2ecc71'}">
            CONFIDENCE: {report.confidence_level}
        </div>
    </div>
</div>

<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-value">{len(report.deterministic_critical_paths)}</div>
        <div class="stat-label">Deterministic Critical Paths</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{len(report.non_deterministic_risk_paths)}</div>
        <div class="stat-label">Non-Deterministic Risk Paths</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{report.evaluation_summary.total_templates_evaluated}</div>
        <div class="stat-label">Templates Evaluated</div>
    </div>
</div>

<h2 class="section-title">Model assumptions & limitations</h2>
<div style="background:#ecf0f1; padding:20px; border-radius:6px; margin-bottom: 20px;">
  <p style="margin-top:0;">Nivel de evidencia (run): <strong>{evidence_level}</strong>. En <em>summary</em> se omiten detalles extensos de evidencia por edge; en <em>full</em> se incluye evidencia ampliada por path/edge cuando aplica.</p>
  <ul>
    <li>Requires Lab Validation items are excluded from deterministic paths.</li>
    <li>Cross-forest trust capabilities mapped as non-deterministic until proven.</li>
  </ul>
</div>
"""

    ddcc_yes = bool(getattr(report, "is_compromisable", False))
    det_count = len(det_paths)
    risk_count = len(risk_paths)
    near_miss_count = len(near_misses or [])
    susceptibility = "LOW"
    if ddcc_yes or det_count > 0:
        susceptibility = "HIGH"
    elif risk_count > 0 or near_miss_count > 0:
        susceptibility = "MEDIUM"

    safe_narrative = ""
    if not ddcc_yes:
        if det_count == 0:
            safe_narrative = "DDCC=NO indica que no existe una cadena determinística desde entrypoints low-trust hacia impacto L3+ vía AD CS en los datos evaluados. Esto es una señal positiva de hardening efectivo."
        if risk_count > 0 or near_miss_count > 0:
            safe_narrative += " Aún así, existen señales de susceptibilidad (near-misses/risk paths) que requieren interacción humana o validación adicional."

    html += f"""
<h2 class="section-title">Executive Summary</h2>
<div style="background:#ecf0f1; border-left:5px solid #2ecc71; padding:20px; border-radius:6px; margin-bottom: 20px;">
  <p style="margin-top:0;"><strong>DDCC Status:</strong> {'COMPROMISED' if ddcc_yes else 'SAFE'}</p>
  <p><strong>Attack Susceptibility:</strong> {susceptibility}</p>
  <p style="margin-bottom:0;">{safe_narrative if safe_narrative else 'DDCC=YES indica paths determinísticos; requiere priorización inmediata de mitigación.'}</p>
</div>
"""

    html += f"""
<h2 class="section-title">Model Telemetry</h2>
<p>Esta tabla explica por qué puede haber 0 paths: descarte por publicación, permisos, intersección low-trust, fricción, o restricciones de confianza.</p>
<table style="width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 4px rgba(0,0,0,0.06);">
  <thead>
    <tr style="background:#ecf0f1;">
      <th style="text-align:left; padding:10px; border-bottom:1px solid #ddd;">Metric</th>
      <th style="text-align:left; padding:10px; border-bottom:1px solid #ddd;">Value</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">total_templates_evaluated</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'total_templates_evaluated', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">published_templates_count</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'published_templates_count', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">templates_with_effective_enroll_count</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'templates_with_effective_enroll_count', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">templates_with_low_trust_intersection_count</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'templates_with_low_trust_intersection_count', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">deterministic_edges_created</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'deterministic_edges_created', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">risk_edges_created</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'risk_edges_created', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_not_published</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_not_published', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_no_enroll_principals</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_no_enroll_principals', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_no_low_trust_intersection</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_no_low_trust_intersection', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_manager_approval</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_manager_approval', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_authorized_signatures</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_authorized_signatures', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">discarded_flag_restrictions</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'discarded_flag_restrictions', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px; border-bottom:1px solid #eee;">total_edges_generated</td><td style="padding:10px; border-bottom:1px solid #eee;">{getattr(summary_obj, 'total_edges_generated', 0) if summary_obj else 0}</td></tr>
    <tr><td style="padding:10px;">total_paths_attempted</td><td style="padding:10px;">{getattr(summary_obj, 'total_paths_attempted', 0) if summary_obj else 0}</td></tr>
  </tbody>
</table>
"""
    root_cause = getattr(report, "root_cause_analysis", []) or []
    if root_cause:
        title = "Why DDCC = NO" if not getattr(report, "is_compromisable", False) else "Root Cause Analysis"
        html += f"""
<div style="background: #ecf0f1; border-left: 5px solid #3498db; padding: 20px; border-radius: 5px; margin-bottom: 30px;">
    <h3 style="margin-top:0; color: #2980b9;">{title}</h3>
    <ul style="margin-bottom:0;">
        {''.join(f"<li>{r}</li>" for r in root_cause)}
    </ul>
</div>
"""
        
    html += f"""
<h2 class="section-title">Section A — Deterministic Critical Paths (Top {top_paths})</h2>
"""
    if not sorted_det:
        html += "<p>No deterministic critical paths found. Domain logic is sound against current definitions.</p>"
        
    for i, path in enumerate(sorted_det):
        edges = getattr(path, "edges", []) or []
        last_outcome = edges[-1].outcome if edges else None
        sev_name = last_outcome.severity.name if last_outcome and hasattr(getattr(last_outcome, "severity", None), 'name') else "UNKNOWN"
        sev_class = sev_name.split("_")[0] if "_" in sev_name else "L0"
        
        reasons = getattr(path, "reasons", []) or []
        if not reasons:
            ev = getattr(last_outcome, "evidence", None) if last_outcome else None
            if isinstance(ev, dict):
                reasons = ev.get("severity_reasons", []) or []
            
        html += f"""
<div class="path-card path-critical">
    <div class="sev-badge sev-{sev_class}">{sev_name}</div>
    <h3>{path.description}</h3>
    <p><strong>Start Principal:</strong> {path.start_principal}</p>
    <p><strong>Length:</strong> {path.length} hops</p>
    <div><strong>Why this is deterministic:</strong>
        <ul>
            {''.join(f"<li>{r}</li>" for r in reasons)}
        </ul>
    </div>
</div>
"""

    html += f"""
<h2 class="section-title">Section B — Non-Deterministic Risk Paths (Top {top_paths})</h2>
"""
    if not sorted_risk:
        html += "<p>No risk paths found or inclusion disabled.</p>"
        
    for i, path in enumerate(sorted_risk):
        edges = getattr(path, "edges", []) or []
        last_outcome = edges[-1].outcome if edges else None
        sev_name = last_outcome.severity.name if last_outcome and hasattr(getattr(last_outcome, "severity", None), 'name') else "UNKNOWN"
        sev_class = sev_name.split("_")[0] if "_" in sev_name else "L0"
        
        notes = []
        ev = getattr(last_outcome, "evidence", None) if last_outcome else None
        if isinstance(ev, dict):
            notes = ev.get("notes", []) or []
            
        warning_html = ""
        for n in notes:
            if "WARNING!" in n:
                warning_html += f"<div class='notes-warning'>️ {n}</div>"
                
        html += f"""
<div class="path-card path-risk">
    <div class="sev-badge sev-{sev_class}">{sev_name}</div>
    <h3>{path.description}</h3>
    <p><strong>Required Interaction:</strong> Human-in-the-loop (Manager Approval or Agent Signatures)</p>
    {warning_html}
</div>
"""

    near_misses = getattr(report, "near_misses", None)
    if near_misses is None:
        near_misses = getattr(report, "near_miss_paths", []) or []

    if near_misses:
        html += f"""
<h2 class="section-title">Section C — Near Miss Paths (High/Medium Contextual)</h2>
<p>Templates with inherently high capabilities but lacking immediate deterministic vectors from supplied sources.</p>
"""
        for m in near_misses:
            fric_html = ", ".join(m.friction_factors) if m.friction_factors else "None directly flagged"
            
            # Print intersection visual
            intersection_str = "<strong>[LOW-TRUST REACHABLE]</strong>" if m.low_trust_intersection else "<strong>[ADMIN ONLY TARGETING]</strong>"
            published_str = "<strong>[PUBLISHED]</strong>" if m.published else "<strong>[NOT PUBLISHED]</strong>"
            
            html += f"""
<div class="path-card" style="border-left-color: #34495e;">
    <h3>{m.template_name} {published_str} {intersection_str}</h3>
    <p><strong>Friction Detected:</strong> {fric_html}</p>
    <p><strong>Effective Enroll Principals:</strong> {', '.join(m.effective_enroll_principals[:10])}</p>
</div>
"""

    html += f"""
<h2 class="section-title">Section D — Model Assumptions & Limitations</h2>
<ul>
    <li>Requires Lab Validation paths are gracefully degraded and excluded from Critical Paths to avoid False Positives.</li>
    <li>CA-Level overrides (like ESC6) are evaluated globally if detected.</li>
    <li>Application Policies are merged with Extended Key Usages for Enrollment Agent definitions.</li>
</ul>
<h2 class="section-title">Glossary & Legends</h2>
<div style="background:#ecf0f1; border-left:5px solid #9b59b6; padding:20px; border-radius:6px;">
  <h3 style="margin-top:0;">L1–L5 (IdentitySeverity)</h3>
  <ul style="margin-bottom:0;">
    <li><strong>L1:</strong> Self authentication</li>
    <li><strong>L2:</strong> Arbitrary user authentication</li>
    <li><strong>L3:</strong> Privileged authentication (validated)</li>
    <li><strong>L4:</strong> Identity minting / delegation severe</li>
    <li><strong>L5:</strong> Authority compromise (CA-level)</li>
  </ul>
  <h3>Confidence</h3>
  <ul style="margin-bottom:0;">
    <li><strong>high:</strong> Deterministic conditions observed and mapped.</li>
    <li><strong>medium:</strong> Viable but includes friction/interaction or partial resolution.</li>
    <li><strong>requires_lab_validation:</strong> Needs practical verification (unknown EKU / AnyPurpose / edge cases).</li>
  </ul>
</div>

<div style="margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 0.9em;">
    <p>ESCepcion Research-Grade Model | Report Version {REPORT_VERSION} | AI Generated</p>
</div>

</body>
</html>
"""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{domain.replace('.', '_')}_DDCC.html")
    
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
        
    return out_path
