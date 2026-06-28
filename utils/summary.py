from colorama import Fore, Style

def print_summary(resultados, resultados_esc7, resultados_esc8):
    total_vulns = len(resultados)
    high = sum(1 for r in resultados if any(x["nivel"].lower() == "high" for x in r.get("riesgos", [])))
    medium = sum(1 for r in resultados if any(x["nivel"].lower() == "medium" for x in r.get("riesgos", [])))
    low = sum(1 for r in resultados if any(x["nivel"].lower() == "low" for x in r.get("riesgos", [])))

    esc7_vuln = sum(1 for c in resultados_esc7 if c.get("ESC7_CA_Severidad") == "High")
    esc8_vuln = sum(1 for c in resultados_esc8 if c.get("ESC8_CA_Severidad") == "High")

    print(Fore.WHITE + "\n═══════════════════════════════════════════════════════════════")
    print(Fore.MAGENTA + "  RESUMEN FINAL DEL ANÁLISIS")
    print(Fore.WHITE + "───────────────────────────────────────────────────────────────")
    print(f" • Plantillas analizadas: {len(resultados)}")
    print(f" • Vulnerables (High): {Fore.RED}{high}{Style.RESET_ALL}")
    print(f" • Vulnerables (Medium): {Fore.YELLOW}{medium}{Style.RESET_ALL}")
    print(f" • Vulnerables (Low): {Fore.LIGHTBLACK_EX}{low}{Style.RESET_ALL}")
    print(f" • CAs vulnerables (ESC7): {Fore.RED}{esc7_vuln}{Style.RESET_ALL}")
    print(f" • Enrollment Services vulnerables (ESC8): {Fore.RED}{esc8_vuln}{Style.RESET_ALL}")
    print(Fore.WHITE + "═══════════════════════════════════════════════════════════════\n")
