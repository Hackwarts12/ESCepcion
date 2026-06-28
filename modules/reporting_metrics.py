from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from data.report_strings import POSTURE_INTERPRETATION


def interpret_posture(score: int) -> str:
    for min_score, label in POSTURE_INTERPRETATION:
        if score >= min_score:
            return label
    return POSTURE_INTERPRETATION[-1][1] if POSTURE_INTERPRETATION else "UNKNOWN"


def compute_posture_score(
    *,
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


def compute_attack_susceptibility(
    *,
    ddcc_yes: Optional[bool],
    deterministic_paths: Optional[int],
    risk_paths: Optional[int],
    near_miss_paths: Optional[int],
    templates_with_effective_enroll: Optional[int],
) -> str:
    if ddcc_yes is True or (deterministic_paths is not None and deterministic_paths > 0):
        return "HIGH"
    if (risk_paths is not None and risk_paths > 0) or (near_miss_paths is not None and near_miss_paths > 0):
        return "MEDIUM"
    if templates_with_effective_enroll is not None and templates_with_effective_enroll == 0:
        return "LOW"
    return "LOW"


def compute_report_meta_global(
    *,
    resultados: List[Dict[str, Any]],
    ddcc_report: Any = None,
    evidence_level: str = "summary",
    published_count: Optional[int] = None,
) -> Dict[str, Any]:
    templates_analyzed = len(resultados)
    templates_published = published_count if published_count is not None else sum(1 for r in resultados if r.get("is_published") is True)
    templates_with_effective_enroll_local = sum(
        1 for r in resultados if (r.get("is_published") is True and (r.get("enroll_principals") or []))
    )

    high_count = sum(1 for r in resultados for v in (r.get("riesgos") or []) if v.get("nivel") == "High")
    medium_count = sum(1 for r in resultados for v in (r.get("riesgos") or []) if v.get("nivel") == "Medium")
    low_count = sum(1 for r in resultados for v in (r.get("riesgos") or []) if v.get("nivel") == "Low")
    critical_count = sum(1 for r in resultados for v in (r.get("riesgos") or []) if v.get("nivel") == "Critical")

    exploitable_now_count = sum(1 for r in resultados if r.get("exploitability_status") == "EXPLOITABLE_NOW")

    esc7_count = 0
    esc8_count = 0
    if resultados and isinstance(resultados[0], dict):
        esc7_count = sum(1 for r in (resultados[0].get("ESC7_CA_Level", []) or []) if r.get("ESC7_CA"))
        esc8_count = sum(1 for r in (resultados[0].get("ESC8_CA_Level", []) or []) if r.get("ESC8_CA"))

    ddcc_yes: Optional[bool] = None
    det_paths = None
    risk_paths = None
    near_miss_paths = None
    ddcc_confidence = "UNKNOWN"
    templates_with_effective_enroll = templates_with_effective_enroll_local

    if ddcc_report is not None:
        try:
            ddcc_yes = bool(getattr(ddcc_report, "is_compromisable", False))
            det_paths = len(getattr(ddcc_report, "deterministic_critical_paths", []) or [])
            risk_paths = len(getattr(ddcc_report, "non_deterministic_risk_paths", []) or [])
            ddcc_confidence = str(getattr(ddcc_report, "confidence_level", "UNKNOWN") or "UNKNOWN")

            nm = getattr(ddcc_report, "near_misses", None)
            if nm is None:
                nm = getattr(ddcc_report, "near_miss_paths", []) or []
            near_miss_paths = len(nm or [])

            summary_obj = getattr(ddcc_report, "evaluation_summary", None)
            if summary_obj is not None:
                templates_with_effective_enroll = int(
                    getattr(summary_obj, "templates_with_effective_enroll_count", templates_with_effective_enroll) or templates_with_effective_enroll
                )
        except Exception:
            pass

    posture_score, score_breakdown = compute_posture_score(
        ddcc_yes=ddcc_yes,
        exploitable_now_count=exploitable_now_count,
        high_count=high_count,
        low_count=low_count,
        esc7_count=esc7_count,
        esc8_count=esc8_count,
    )
    posture_label = interpret_posture(posture_score)

    attack_susceptibility = compute_attack_susceptibility(
        ddcc_yes=ddcc_yes,
        deterministic_paths=det_paths,
        risk_paths=risk_paths,
        near_miss_paths=near_miss_paths,
        templates_with_effective_enroll=templates_with_effective_enroll,
    )

    ddcc_status = "UNKNOWN"
    if ddcc_yes is True:
        ddcc_status = "COMPROMISED"
    elif ddcc_yes is False:
        ddcc_status = "SAFE"

    return {
        "posture_score": posture_score,
        "posture_label": posture_label,
        "ddcc_status": ddcc_status,
        "attack_susceptibility": attack_susceptibility,
        "evidence_level": evidence_level,
        "score_breakdown": score_breakdown,
        "counts": {
            "templates_analyzed": templates_analyzed,
            "templates_published": templates_published,
            "templates_with_effective_enroll": templates_with_effective_enroll,
            "findings_critical": critical_count,
            "findings_high": high_count,
            "findings_medium": medium_count,
            "findings_low": low_count,
            "exploitable_now": exploitable_now_count,
            "esc7_ca": esc7_count,
            "esc8": esc8_count,
            "ddcc_deterministic_paths": det_paths,
            "ddcc_risk_paths": risk_paths,
            "ddcc_near_miss_paths": near_miss_paths,
            "ddcc_confidence": ddcc_confidence,
        },
    }
