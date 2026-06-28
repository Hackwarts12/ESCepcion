from colorama import Fore, Style, init, just_fix_windows_console
init(autoreset=True, convert=True)
just_fix_windows_console()

def colorize(text, severity=None):
    if not severity:
        return text
    sev = severity.lower()
    if sev == "high":
        return Fore.RED + text + Style.RESET_ALL
    if sev == "medium":
        return Fore.YELLOW + text + Style.RESET_ALL
    if sev == "low":
        return Fore.LIGHTBLACK_EX + text + Style.RESET_ALL
    return text

def format_risks(riesgos):
    if not riesgos:
        return Fore.LIGHTBLACK_EX + "None" + Style.RESET_ALL
    colores = []
    for r in riesgos:
        colores.append(colorize(r, r))
    return " | ".join(colores)

def print_template_result(plantilla, vulns, riesgos):
    print(Fore.CYAN + f"\n╔═ Plantilla: {plantilla}" + Style.RESET_ALL)
    print(Fore.CYAN + "╚═══════════════════════════════════════════════════════════════")
    for v in vulns:
        esc, estado, razon, severidad = v
        if estado == "":
            icon = "" if severidad.lower() == "high" else "" if severidad.lower() == "medium" else ""
            print(f" {icon} {colorize(esc, severidad)} → {razon} ({colorize(severidad, severidad)})")
    print(f"  Riesgos globales: {format_risks(riesgos)}")
    print(Fore.CYAN + "──────────────────────────────────────────────────────────────" + Style.RESET_ALL)

def print_ca_results(resultados_esc7, resultados_esc8):
    if resultados_esc7:
        print(Fore.MAGENTA + "\n Resultados de ESC7 (CA-Level):" + Style.RESET_ALL)
        for ca in resultados_esc7:
            if ca.get("ESC7_CA") and ca.get("ESC7_CA_Severidad") != "Low":
                ca_name = ca.get("ca_name")
                razon = ca.get("ESC7_CA_Reason")
                sev = ca.get("ESC7_CA_Severidad")
                print(f"   • {Fore.CYAN}{ca_name}{Style.RESET_ALL} → {colorize(razon, sev)} ({colorize(sev, sev)})")
    if resultados_esc8:
        print(Fore.MAGENTA + "\n Resultados de ESC8 (Enrollment Service):" + Style.RESET_ALL)
        for svc in resultados_esc8:
            if svc.get("ESC8_CA") and svc.get("ESC8_CA_Severidad") != "Low":
                name = svc.get("service_name")
                razon = svc.get("ESC8_CA_Reason")
                sev = svc.get("ESC8_CA_Severidad")
                print(f"   • {Fore.CYAN}{name}{Style.RESET_ALL} → {colorize(razon, sev)} ({colorize(sev, sev)})")
