#!/usr/bin/env python3
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init
init(autoreset=True)

from core.utils import log, save_log, BANNER
from core.scanner import scan_network, scan_single
from core.auditor import (
    enumerate_shares, check_permissions,
    analyze_risk, print_analysis,
    generate_report, interactive_shell
)


# ------------------------------------------------------------------ #
#  HELPERS                                                            #
# ------------------------------------------------------------------ #

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input(f"\n{Fore.WHITE}  Pressione ENTER para continuar...{Style.RESET_ALL}")


def print_menu(hosts, current_host, shares, analyzed):
    host_str     = current_host if current_host else f"{Fore.RED}Nenhum selecionado{Style.RESET_ALL}"
    shares_str   = str(len(shares))    if shares   else f"{Fore.RED}0{Style.RESET_ALL}"
    analyzed_str = str(len(analyzed))  if analyzed else f"{Fore.RED}0{Style.RESET_ALL}"

    print(f"""
{Fore.RED}  ┌─────────────────────────────────────────┐
  │         NFHACK — NFS Auditing Tool      │
  └─────────────────────────────────────────┘{Style.RESET_ALL}

{Fore.CYAN}  Host atual  : {Fore.WHITE}{host_str}
{Fore.CYAN}  Hosts NFS   : {Fore.WHITE}{len(hosts)}
{Fore.CYAN}  Shares      : {Fore.WHITE}{shares_str}
{Fore.CYAN}  Analisados  : {Fore.WHITE}{analyzed_str}
{Style.RESET_ALL}
{Fore.YELLOW}  [1]{Fore.WHITE} Escanear hosts com NFS ativo
{Fore.YELLOW}  [2]{Fore.WHITE} Enumerar shares de um host
{Fore.YELLOW}  [3]{Fore.WHITE} Verificar permissões dos shares
{Fore.YELLOW}  [4]{Fore.WHITE} Analisar nível de risco
{Fore.YELLOW}  [5]{Fore.WHITE} Gerar relatório
{Fore.YELLOW}  [6]{Fore.WHITE} Explorar share (shell interativa)
{Fore.YELLOW}  [0]{Fore.WHITE} Sair
""")


def print_hosts(hosts):
    if not hosts:
        log("Nenhum host com NFS encontrado.", "warning")
        return

    print(f"\n{Fore.CYAN}  {'#':<5} {'IP':<20}{Style.RESET_ALL}")
    print(f"  {'─'*25}")
    for i, h in enumerate(hosts, 1):
        print(f"  {Fore.YELLOW}{i:<5}{Style.RESET_ALL} {h}")
    print()


def select_host(hosts):
    print_hosts(hosts)
    try:
        choice = input(f"{Fore.YELLOW}  Número do host (ou IP manual): {Style.RESET_ALL}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(hosts):
            return hosts[int(choice) - 1]
        elif choice:
            return choice
    except KeyboardInterrupt:
        pass
    return None


def select_share(shares):
    """Let user select a share from list."""
    print(f"\n{Fore.CYAN}  {'#':<5} {'SHARE':<25} {'ACESSO'}{Style.RESET_ALL}")
    print(f"  {'─'*40}")
    for i, s in enumerate(shares, 1):
        print(f"  {Fore.YELLOW}{i:<5}{Style.RESET_ALL} {s['share']:<25} {s['access']}")
    print()

    try:
        choice = input(f"{Fore.YELLOW}  Número do share: {Style.RESET_ALL}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(shares):
            return shares[int(choice) - 1]["share"]
    except KeyboardInterrupt:
        pass
    return None


# ------------------------------------------------------------------ #
#  ACTIONS                                                            #
# ------------------------------------------------------------------ #

def action_scan(hosts):
    clear()
    try:
        target = input(f"{Fore.YELLOW}  Rede ou IP alvo (ex: 192.168.0.0 ou 192.168.0.10): {Style.RESET_ALL}").strip()
    except KeyboardInterrupt:
        return hosts

    if not target:
        return hosts

    clear()

    if "/" not in target and target.count(".") == 3:
        if scan_single(target):
            if target not in hosts:
                hosts.append(target)
    else:
        found = scan_network(target)
        for h in found:
            if h not in hosts:
                hosts.append(h)

    if hosts:
        log(f"{len(hosts)} host(s) com NFS encontrado(s).", "success")
    else:
        log("Nenhum host com NFS ativo encontrado.", "warning")

    save_log(f"SCAN DONE | hosts={hosts}")
    pause()
    return hosts


def action_enumerate(hosts):
    clear()
    if not hosts:
        log("Faça um scan primeiro (opção 1).", "warning")
        pause()
        return None, []

    host = select_host(hosts)
    if not host:
        return None, []

    clear()
    log(f"Enumerando shares de {host} ...", "info")
    shares = enumerate_shares(host)

    if not shares:
        log("Nenhum share encontrado.", "warning")
    else:
        log(f"{len(shares)} share(s) encontrado(s).", "success")

    pause()
    return host, shares


def action_permissions(host, shares):
    clear()
    if not host or not shares:
        log("Enumere os shares primeiro (opção 2).", "warning")
        pause()
        return []

    log(f"Verificando permissões em {host} ...", "info")
    log("Isso pode levar alguns segundos por share.", "warning")

    results = check_permissions(host, shares)
    pause()
    return results


def action_analyze(host, results):
    clear()
    if not results:
        log("Verifique as permissões primeiro (opção 3).", "warning")
        pause()
        return []

    log(f"Analisando nível de risco para {host} ...", "info")
    analyzed = analyze_risk(results)
    print_analysis(analyzed)
    save_log(f"ANALYSIS DONE | host={host} shares={len(analyzed)}")
    pause()
    return analyzed


def action_report(host, analyzed):
    clear()
    if not analyzed:
        log("Faça a análise de risco primeiro (opção 4).", "warning")
        pause()
        return

    generate_report(host, analyzed)
    pause()


def action_shell(host, shares):
    clear()
    if not host:
        log("Selecione um host primeiro (opção 2).", "warning")
        pause()
        return

    if not shares:
        log("Enumere os shares primeiro (opção 2).", "warning")
        pause()
        return

    share = select_share(shares)
    if not share:
        return

    clear()
    interactive_shell(host, share)
    pause()


# ------------------------------------------------------------------ #
#  MAIN                                                               #
# ------------------------------------------------------------------ #

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Execute como root (sudo python3 nfhack.py){Style.RESET_ALL}")
        sys.exit(1)

    os.makedirs("loot", exist_ok=True)

    clear()
    print(BANNER)
    time.sleep(0.5)

    save_log("SESSION START")

    hosts        = []
    current_host = None
    shares       = []
    results      = []
    analyzed     = []

    while True:
        clear()
        print_menu(hosts, current_host, shares, analyzed)

        try:
            opt = input(f"{Fore.YELLOW}  nfhack > {Style.RESET_ALL}").strip()
        except KeyboardInterrupt:
            opt = "0"

        if opt == "1":
            hosts = action_scan(hosts)

        elif opt == "2":
            current_host, shares = action_enumerate(hosts)
            results  = []
            analyzed = []

        elif opt == "3":
            results  = action_permissions(current_host, shares)
            analyzed = []

        elif opt == "4":
            analyzed = action_analyze(current_host, results)

        elif opt == "5":
            action_report(current_host, analyzed)

        elif opt == "6":
            action_shell(current_host, shares)

        elif opt == "0":
            clear()
            save_log("SESSION END")
            log("Até logo!", "success")
            sys.exit(0)


if __name__ == "__main__":
    main()
