import socket
import subprocess
import concurrent.futures
from core.utils import log, save_log


NFS_PORT = 2049


def check_nfs(ip, timeout=1):
    """Check if host has NFS port open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, NFS_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_network_hosts(network):
    """Generate all IPs in a /24 network range."""
    base = ".".join(network.split(".")[:3])
    return [f"{base}.{i}" for i in range(1, 255)]


def showmount(ip):
    """Run showmount -e to get exported shares."""
    try:
        result = subprocess.run(
            ["showmount", "-e", ip, "--no-headers"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            shares = []
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if parts:
                    share = parts[0]
                    access = parts[1] if len(parts) > 1 else "*"
                    shares.append({"share": share, "access": access})
            return shares
        return []
    except Exception:
        return []


def scan_network(network, threads=50):
    """Scan network for hosts with NFS active."""
    hosts_ip = get_network_hosts(network)
    nfs_hosts = []

    log(f"Escaneando {len(hosts_ip)} hosts em {network} ...", "info")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_nfs, ip): ip for ip in hosts_ip}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    log(f"NFS ativo → {ip}", "success")
                    save_log(f"NFS FOUND | {ip}")
                    nfs_hosts.append(ip)
            except Exception:
                pass

    return nfs_hosts


def scan_single(ip):
    """Check a single host for NFS."""
    if check_nfs(ip):
        log(f"NFS ativo → {ip}", "success")
        return True
    else:
        log(f"NFS não detectado em {ip}", "warning")
        return False
