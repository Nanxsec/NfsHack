import subprocess
import os
import shutil
import tempfile
from core.utils import log, save_log, RISK_COLORS
from colorama import Fore, Style


CRITICAL_PATHS = ["/", "/root", "/etc", "/home", "/var", "/opt"]
SENSITIVE_PATHS = ["/srv", "/data", "/backup", "/mnt", "/storage"]


def enumerate_shares(ip):
    """Enumerate NFS shares via showmount."""
    try:
        result = subprocess.run(
            ["showmount", "-e", ip, "--no-headers"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            log(f"Sem shares acessíveis em {ip}", "warning")
            return []

        shares = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if parts:
                share  = parts[0]
                access = parts[1] if len(parts) > 1 else "*"
                shares.append({"share": share, "access": access})
                log(f"Share encontrado: {share} → acesso: {access}", "success")
                save_log(f"SHARE | host={ip} share={share} access={access}")

        return shares

    except FileNotFoundError:
        log("'showmount' não encontrado. Instale: sudo apt install nfs-common", "error")
        return []
    except Exception as e:
        log(f"Erro ao enumerar shares: {e}", "error")
        return []


def check_permissions(ip, shares):
    """Try to mount each share and check read/write permissions."""
    results = []

    for s in shares:
        share_path = s["share"]
        info = {
            "share":  share_path,
            "access": s["access"],
            "read":   False,
            "write":  False,
            "files":  [],
            "error":  None
        }

        mount_point = tempfile.mkdtemp(prefix="nfhack_")

        try:
            mount_result = subprocess.run(
                ["mount", "-t", "nfs", "-o", "nolock,soft,timeo=5",
                 f"{ip}:{share_path}", mount_point],
                capture_output=True, text=True, timeout=10
            )

            if mount_result.returncode != 0:
                info["error"] = "Montagem negada"
                log(f"{share_path} → montagem negada", "warning")
            else:
                try:
                    files = os.listdir(mount_point)
                    info["read"]  = True
                    info["files"] = files[:20]
                    log(f"{share_path} → READ ✅ ({len(files)} itens visíveis)", "success")
                    save_log(f"READ | host={ip} share={share_path} files={len(files)}")
                except PermissionError:
                    log(f"{share_path} → sem permissão de leitura", "warning")

                test_file = os.path.join(mount_point, ".nfhack_test")
                try:
                    with open(test_file, "w") as f:
                        f.write("test")
                    os.remove(test_file)
                    info["write"] = True
                    log(f"{share_path} → WRITE ✅", "success")
                    save_log(f"WRITE | host={ip} share={share_path}")
                except Exception:
                    log(f"{share_path} → sem permissão de escrita", "info")

                subprocess.run(["umount", "-f", mount_point], capture_output=True, timeout=5)

        except Exception as e:
            info["error"] = str(e)
            log(f"Erro ao verificar {share_path}: {e}", "error")
        finally:
            try:
                os.rmdir(mount_point)
            except Exception:
                pass

        results.append(info)

    return results


def analyze_risk(results):
    analyzed = []

    for r in results:
        share   = r["share"]
        risk    = "BAIXO"
        reasons = []

        if r["error"] and not r["read"]:
            risk = "INFO"
            reasons.append("Share não acessível")

        if share in CRITICAL_PATHS:
            risk = "CRÍTICO"
            reasons.append(f"Path crítico exposto: {share}")
        elif any(share.startswith(p) for p in CRITICAL_PATHS):
            risk = "ALTO"
            reasons.append(f"Subpath crítico exposto: {share}")
        elif share in SENSITIVE_PATHS or any(share.startswith(p) for p in SENSITIVE_PATHS):
            risk = "MÉDIO"
            reasons.append(f"Path sensível exposto: {share}")

        if r["access"] == "*":
            if risk != "CRÍTICO":
                risk = "ALTO" if risk == "BAIXO" else risk
            reasons.append("Acesso liberado para qualquer IP (*)")

        if r["write"]:
            if risk == "BAIXO":
                risk = "MÉDIO"
            reasons.append("Escrita permitida")

        if r["read"]:
            reasons.append(f"{len(r['files'])} item(s) visível(is)")

        analyzed.append({**r, "risk": risk, "reasons": reasons})

    return analyzed


def print_analysis(analyzed):
    print(f"\n{Fore.CYAN}  {'SHARE':<25} {'ACESSO':<18} {'LEITURA':<10} {'ESCRITA':<10} {'RISCO'}{Style.RESET_ALL}")
    print(f"  {'─'*75}")

    for a in analyzed:
        color = RISK_COLORS.get(a["risk"], Fore.WHITE)
        read  = f"{Fore.GREEN}✅{Style.RESET_ALL}" if a["read"]  else f"{Fore.RED}❌{Style.RESET_ALL}"
        write = f"{Fore.GREEN}✅{Style.RESET_ALL}" if a["write"] else f"{Fore.RED}❌{Style.RESET_ALL}"
        print(f"  {a['share']:<25} {a['access']:<18} {read:<10} {write:<10} {color}{a['risk']}{Style.RESET_ALL}")

        for reason in a["reasons"]:
            print(f"  {Fore.WHITE}   └─ {reason}{Style.RESET_ALL}")

        if a["files"]:
            print(f"  {Fore.WHITE}   └─ Arquivos: {', '.join(a['files'][:5])}{'...' if len(a['files']) > 5 else ''}{Style.RESET_ALL}")

    print()


def generate_report(ip, analyzed, path="loot/report.txt"):
    os.makedirs("loot", exist_ok=True)
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"NFHACK REPORT — {ip}\n")
        f.write(f"Data: {now}\n")
        f.write(f"{'='*60}\n\n")

        for a in analyzed:
            f.write(f"Share   : {a['share']}\n")
            f.write(f"Acesso  : {a['access']}\n")
            f.write(f"Leitura : {'Sim' if a['read'] else 'Não'}\n")
            f.write(f"Escrita : {'Sim' if a['write'] else 'Não'}\n")
            f.write(f"Risco   : {a['risk']}\n")
            for r in a["reasons"]:
                f.write(f"  - {r}\n")
            if a["files"]:
                f.write(f"Arquivos: {', '.join(a['files'])}\n")
            f.write("\n")

    log(f"Relatório salvo em {path}", "success")
    save_log(f"REPORT | host={ip} path={path}")


# ------------------------------------------------------------------ #
#  SHELL INTERATIVA                                                   #
# ------------------------------------------------------------------ #

def _print_ls(path):
    """List directory contents with type indicators."""
    try:
        entries = sorted(os.listdir(path))
        if not entries:
            print(f"  {Fore.YELLOW}(diretório vazio){Style.RESET_ALL}")
            return

        for entry in entries:
            full = os.path.join(path, entry)
            if os.path.isdir(full):
                print(f"  {Fore.CYAN}📁 {entry}/{Style.RESET_ALL}")
            elif os.access(full, os.R_OK):
                size = os.path.getsize(full)
                print(f"  {Fore.WHITE}📄 {entry:<40} {Fore.YELLOW}{size} bytes{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}🔒 {entry} (sem permissão){Style.RESET_ALL}")
    except PermissionError:
        log("Sem permissão para listar este diretório.", "error")
    except Exception as e:
        log(f"Erro: {e}", "error")


def _print_cat(filepath):
    """Read and print a text file."""
    try:
        size = os.path.getsize(filepath)
        if size > 1024 * 1024:
            log("Arquivo maior que 1MB — use download para copiar.", "warning")
            return

        with open(filepath, "r", errors="replace") as f:
            content = f.read()

        print(f"\n{Fore.CYAN}  ── conteúdo: {os.path.basename(filepath)} ──{Style.RESET_ALL}")
        print(content)
        print(f"{Fore.CYAN}  ── fim ──{Style.RESET_ALL}\n")
        save_log(f"CAT | {filepath}")

    except PermissionError:
        log("Sem permissão para ler este arquivo.", "error")
    except Exception as e:
        log(f"Erro ao ler arquivo: {e}", "error")


def _download(filepath, dest_dir="loot/downloads"):
    """Download a file from the NFS share to local loot."""
    try:
        os.makedirs(dest_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        dest     = os.path.join(dest_dir, filename)
        shutil.copy2(filepath, dest)
        log(f"Arquivo salvo em {dest}", "success")
        save_log(f"DOWNLOAD | {filepath} → {dest}")
    except PermissionError:
        log("Sem permissão para baixar este arquivo.", "error")
    except Exception as e:
        log(f"Erro ao baixar: {e}", "error")


def interactive_shell(ip, share):
    """Mount NFS share and open an interactive shell for navigation."""
    mount_point = tempfile.mkdtemp(prefix="nfhack_shell_")

    log(f"Montando {ip}:{share} ...", "info")

    mount_result = subprocess.run(
        ["mount", "-t", "nfs", "-o", "nolock,soft,timeo=5",
         f"{ip}:{share}", mount_point],
        capture_output=True, text=True, timeout=10
    )

    if mount_result.returncode != 0:
        log(f"Falha ao montar share: {mount_result.stderr.strip()}", "error")
        try:
            os.rmdir(mount_point)
        except Exception:
            pass
        return

    log(f"Share montado! Digite 'help' para ver os comandos.", "success")
    save_log(f"SHELL START | {ip}:{share}")

    cwd = mount_point  # diretório atual dentro do share

    print(f"\n{Fore.YELLOW}  Comandos: ls, cd <dir>, pwd, cat <arquivo>, download <arquivo>, exit{Style.RESET_ALL}\n")

    try:
        while True:
            # Prompt no estilo Phantom
            rel = cwd.replace(mount_point, share) or share
            prompt = f"{Fore.RED}┌──({Fore.YELLOW}nfhack{Fore.RED}@{Fore.WHITE}{ip}{Fore.RED})-[{Fore.WHITE}{rel}{Fore.RED}]\n└─${Style.RESET_ALL} "

            try:
                cmd = input(prompt).strip()
            except KeyboardInterrupt:
                print()
                break

            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            command = parts[0].lower()
            argument = parts[1] if len(parts) > 1 else ""

            # ── ls ──
            if command == "ls":
                _print_ls(cwd)

            # ── cd ──
            elif command == "cd":
                if not argument:
                    log("Uso: cd <diretório>", "warning")
                    continue

                if argument == "..":
                    parent = os.path.dirname(cwd)
                    # Não sai do mount point
                    if parent.startswith(mount_point):
                        cwd = parent
                    else:
                        log("Já está na raiz do share.", "warning")
                else:
                    target = os.path.join(cwd, argument)
                    if os.path.isdir(target):
                        cwd = target
                    else:
                        log(f"Diretório não encontrado: {argument}", "error")

            # ── pwd ──
            elif command == "pwd":
                rel_path = cwd.replace(mount_point, share)
                print(f"  {Fore.WHITE}{rel_path}{Style.RESET_ALL}")

            # ── cat ──
            elif command == "cat":
                if not argument:
                    log("Uso: cat <arquivo>", "warning")
                    continue
                filepath = os.path.join(cwd, argument)
                if os.path.isfile(filepath):
                    _print_cat(filepath)
                else:
                    log(f"Arquivo não encontrado: {argument}", "error")

            # ── download ──
            elif command == "download":
                if not argument:
                    log("Uso: download <arquivo>", "warning")
                    continue
                filepath = os.path.join(cwd, argument)
                if os.path.isfile(filepath):
                    _download(filepath)
                else:
                    log(f"Arquivo não encontrado: {argument}", "error")

            # ── help ──
            elif command == "help":
                print(f"""
{Fore.CYAN}  Comandos disponíveis:{Style.RESET_ALL}
  {Fore.YELLOW}ls{Style.RESET_ALL}                  → listar arquivos e pastas
  {Fore.YELLOW}cd <dir>{Style.RESET_ALL}             → entrar em um diretório
  {Fore.YELLOW}cd ..{Style.RESET_ALL}                → voltar um nível
  {Fore.YELLOW}pwd{Style.RESET_ALL}                  → exibir caminho atual
  {Fore.YELLOW}cat <arquivo>{Style.RESET_ALL}        → ler conteúdo de um arquivo
  {Fore.YELLOW}download <arquivo>{Style.RESET_ALL}   → salvar arquivo em loot/downloads/
  {Fore.YELLOW}exit{Style.RESET_ALL}                 → sair da shell
""")

            # ── exit ──
            elif command in ("exit", "quit", "q"):
                break

            else:
                log(f"Comando desconhecido: {command}. Digite 'help'.", "warning")

    finally:
        log("Desmontando share...", "info")
        subprocess.run(["umount", "-f", mount_point], capture_output=True, timeout=5)
        try:
            os.rmdir(mount_point)
        except Exception:
            pass
        save_log(f"SHELL END | {ip}:{share}")
        log("Shell encerrada.", "success")
