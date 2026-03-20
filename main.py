import argparse
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table

console = Console()

COMMON_PORTS = [
    21, 22, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443,
    445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 5985, 5986, 8080, 8443, 9000, 3268, 3269
]

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM over TLS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9000: "HTTP-alt",
    3268: "Global Catalog",
    3269: "Global Catalog over TLS",
}


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"No se pudo resolver el objetivo '{target}': {exc}") from exc


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(sock, port)
                return {
                    "port": port,
                    "service_guess": PORT_SERVICE_MAP.get(port, "Unknown"),
                    "banner": banner,
                }
    except Exception:
        return None
    return None


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    try:
        if port in [80, 8080, 8000, 8443, 9000, 443]:
            return None

        sock.sendall(b"\r\n")
        data = sock.recv(1024)
        banner = data.decode(errors="ignore").strip()
        return banner if banner else None
    except Exception:
        return None


def run_command(command: List[str]) -> Dict:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "command": " ".join(command),
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except FileNotFoundError:
        return {
            "command": " ".join(command),
            "error": "Herramienta no instalada o no encontrada en PATH"
        }
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(command),
            "error": "Timeout ejecutando comando"
        }
    except Exception as exc:
        return {
            "command": " ".join(command),
            "error": str(exc)
        }


def analyze_ad_likelihood(open_ports: List[int]) -> Dict:
    ad_ports = {53, 88, 135, 139, 389, 445, 636, 3268, 3269}
    matched = sorted(list(ad_ports.intersection(open_ports)))
    return {
        "possible_ad": len(matched) >= 3,
        "matched_ports": matched
    }


def run_web_module(target: str, open_ports: List[int]) -> List[Dict]:
    results = []
    http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 9000]]

    for port in http_ports:
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{target}:{port}"
        results.append(run_command(["whatweb", url]))

    return results


def run_dns_module(target: str) -> List[Dict]:
    results = []

    # consulta simple
    results.append(run_command(["dig", target]))

    # intento de SRV típicos AD
    results.append(run_command(["dig", f"_ldap._tcp.dc._msdcs.{target}", "SRV"]))
    results.append(run_command(["dig", f"_kerberos._tcp.{target}", "SRV"]))

    return results


def run_smb_module(target: str) -> Dict:
    return run_command(["nxc", "smb", target])


def save_results(data: Dict, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def print_results_table(scan_results: List[Dict]) -> None:
    table = Table(title="Puertos abiertos detectados")
    table.add_column("Puerto", justify="right")
    table.add_column("Servicio")
    table.add_column("Banner")

    for item in sorted(scan_results, key=lambda x: x["port"]):
        table.add_row(
            str(item["port"]),
            item["service_guess"],
            item["banner"] or "-"
        )

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnumForge - escaneo de puertos + enumeración contextual"
    )
    parser.add_argument("target", help="IP o dominio objetivo")
    parser.add_argument(
        "-p",
        "--ports",
        help="Lista de puertos separados por coma. Si no se indica, usa comunes.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Número de hilos para el escaneo"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="results.json",
        help="Archivo JSON de salida"
    )

    args = parser.parse_args()

    try:
        ip = resolve_target(args.target)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return

    ports = COMMON_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            console.print("[red]Formato de puertos inválido[/red]")
            return

    console.print(f"[cyan]Objetivo:[/cyan] {args.target} -> {ip}")
    console.print(f"[cyan]Escaneando {len(ports)} puertos con {args.threads} hilos...[/cyan]")

    scan_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                scan_results.append(result)

    open_ports = sorted([item["port"] for item in scan_results])

    if scan_results:
        print_results_table(scan_results)
    else:
        console.print("[yellow]No se detectaron puertos abiertos en la lista escaneada.[/yellow]")

    ad_analysis = analyze_ad_likelihood(open_ports)

    modules = {
        "web": [],
        "dns": [],
        "smb": None,
    }

    if any(port in open_ports for port in [80, 443, 8080, 8443, 9000]):
        console.print("[green]HTTP/HTTPS detectado -> lanzando whatweb[/green]")
        modules["web"] = run_web_module(args.target, open_ports)

    if 53 in open_ports:
        console.print("[green]DNS detectado -> lanzando dig[/green]")
        modules["dns"] = run_dns_module(args.target)

    if 445 in open_ports:
        console.print("[green]SMB detectado -> lanzando nxc smb[/green]")
        modules["smb"] = run_smb_module(args.target)

    results = {
        "target": args.target,
        "resolved_ip": ip,
        "open_ports": scan_results,
        "ad_analysis": ad_analysis,
        "modules": modules,
    }

    save_results(results, args.output)
    console.print(f"[bold green]Resultados guardados en {args.output}[/bold green]")

    if ad_analysis["possible_ad"]:
        console.print(
            f"[bold magenta]Posible entorno AD detectado[/bold magenta] "
            f"(puertos: {ad_analysis['matched_ports']})"
        )


if __name__ == "__main__":
    main()
