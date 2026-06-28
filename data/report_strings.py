POSTURE_INTERPRETATION = [
    (85, "Excelente"),
    (70, "Buena"),
    (50, "Moderada"),
    (0, "Crítica"),
]

SUSCEPTIBILITY_EXPLANATIONS = {
    "LOW": "No hay paths desde low-trust; misconfiguraciones no son explotables sin publicación/permisos efectivos.",
    "MEDIUM": "No hay paths determinísticos, pero existen near-misses (riesgo latente) que dependen de fricción o interacción.",
    "HIGH": "Existen paths determinísticos (DDCC COMPROMISED) o escalación verificable hacia L3+.",
}

CONFIDENCE_EXPLANATIONS = {
    "HIGH": "Alto: condiciones determinísticas observables y modeladas.",
    "MEDIUM": "Medio: cobertura parcial o fricción/human-in-the-loop en paths de riesgo.",
    "LOW": "Bajo: evidencia incompleta o cobertura limitada del entorno.",
    "requires_lab_validation": "Requiere validación: depende de verificación práctica (EKU desconocido/AnyPurpose/edge cases).",
}
