from colorama import Fore, Style, init, just_fix_windows_console
init(autoreset=True, convert=True)
just_fix_windows_console()

def print_banner():
    banner = f"""
{Fore.MAGENTA}{Style.BRIGHT}
/$$$$$$$$  /$$$$$$   /$$$$$$                                          /$$
| $$_____/ /$$__  $$ /$$__  $$                                        |__/
| $$      | $$  \\__/| $$  \\__/  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$$ /$$  /$$$$$$  /$$$$$$$
| $$$$$   |  $$$$$$ | $$       /$$__  $$ /$$_____/ /$$__  $$ /$$_____/| $$ /$$__  $$| $$__  $$
| $$__/    \\____  $$| $$      | $$$$$$$$| $$      | $$  \\ $$| $$      | $$| $$  \\ $$| $$  \\ $$
| $$       /$$  \\ $$| $$    $$| $$_____/| $$      | $$  | $$| $$      | $$| $$  | $$| $$  | $$
| $$$$$$$$|  $$$$$$/|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$$$$$$/|  $$$$$$$| $$|  $$$$$$/| $$  | $$
|________/ \\______/  \\______/  \\_______/ \\_______/| $$____/  \\_______/|__/ \\______/ |__/  |__/
                                                  | $$
                                                  | $$
                                                  |__/

{Style.RESET_ALL}
{Fore.CYAN}   Active Directory Certificate Services Auditor — ESCepcion v1.0{Style.RESET_ALL}
{Fore.CYAN}   Developed by [Red Spear Labs] ([Author emaldonado/Hackwarts12]){Style.RESET_ALL}
"""
    print(banner)
