import os
from datetime import datetime
from colorama import Fore, Style


BANNER = f"""
{Fore.RED}
███╗   ██╗███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
████╗  ██║██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██╔██╗ ██║█████╗  ███████║███████║██║     █████╔╝ 
██║╚██╗██║██╔══╝  ██╔══██║██╔══██║██║     ██╔═██╗ 
██║ ╚████║██║     ██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Fore.YELLOW}
           NFS Auditing Tool — by Nanoxsec
{Style.RESET_ALL}
"""

RISK_COLORS = {
    "CRÍTICO": Fore.RED,
    "ALTO":    Fore.MAGENTA,
    "MÉDIO":   Fore.YELLOW,
    "BAIXO":   Fore.GREEN,
    "INFO":    Fore.CYAN,
}


def log(msg, level="info"):
    now = datetime.now().strftime("%H:%M:%S")
    colors = {
        "info":    Fore.CYAN    + "[*]",
        "success": Fore.GREEN   + "[+]",
        "error":   Fore.RED     + "[!]",
        "warning": Fore.YELLOW  + "[~]",
        "attack":  Fore.MAGENTA + "[>]",
    }
    prefix = colors.get(level, Fore.WHITE + "[?]")
    print(f"{prefix} {Style.RESET_ALL}{Fore.WHITE}[{now}] {msg}{Style.RESET_ALL}")


def save_log(msg, path="loot/session.log"):
    os.makedirs("loot", exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a") as f:
        f.write(f"[{now}] {msg}\n")
