import argparse
import json
import socket
import subprocess
import sys
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

    results.append(run_command(["dig", target]))
    results.append(run_command(["dig", f"_ldap._tcp.dc._msdcs.{target}", "SRV"]))
    results.append(run_command(["dig", f"_kerberos._tcp.{target}", "SRV"]))

    return results


def run_smb_module(target: str) -> Dict:
    return run_command(["nxc", "smb", target])


def save_json_results(data: Dict, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def save_plain_results(content: str, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)


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


def format_command_result(result: Dict) -> List[str]:
    lines = []
    lines.append(f"$ {result.get('command', '-')}")
    if result.get("stdout"):
        lines.append(result["stdout"])
    if result.get("stderr"):
        lines.append("[stderr]")
        lines.append(result["stderr"])
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    lines.append("")
    return lines


def generate_plain_output(
    target: str,
    ip: str,
    scan_results: List[Dict],
    ad_analysis: Dict,
    modules: Dict
) -> str:
    lines = []
    lines.append(f"EnumForge scan report for {target} ({ip})")
    lines.append("=" * 60)
    lines.append("")

    if scan_results:
        header = f"{'PORT':<10}{'STATE':<10}{'SERVICE':<22}{'BANNER'}"
        lines.append(header)
        lines.append("-" * len(header))

        for item in sorted(scan_results, key=lambda x: x["port"]):
            port_field = f"{item['port']}/tcp"
            state_field = "open"
            service_field = item["service_guess"]
            banner_field = item["banner"] or "-"
            lines.append(f"{port_field:<10}{state_field:<10}{service_field:<22}{banner_field}")
    else:
        lines.append("No se detectaron puertos abiertos en la lista escaneada.")

    lines.append("")
    lines.append("ANALYSIS")
    lines.append("-" * 60)
    lines.append(f"Possible Active Directory: {ad_analysis['possible_ad']}")
    lines.append(
        f"Matched AD ports: {', '.join(map(str, ad_analysis['matched_ports'])) if ad_analysis['matched_ports'] else '-'}"
    )

    if modules.get("web"):
        lines.append("")
        lines.append("WEB ENUMERATION")
        lines.append("-" * 60)
        for result in modules["web"]:
            lines.extend(format_command_result(result))

    if modules.get("dns"):
        lines.append("")
        lines.append("DNS ENUMERATION")
        lines.append("-" * 60)
        for result in modules["dns"]:
            lines.extend(format_command_result(result))

    if modules.get("smb"):
        lines.append("")
        lines.append("SMB ENUMERATION")
        lines.append("-" * 60)
        lines.extend(format_command_result(modules["smb"]))

    return "\n".join(lines).rstrip() + "\n"


def parse_ports(ports_arg: Optional[str]) -> List[int]:
    if not ports_arg:
        return COMMON_PORTS

    try:
        return [int(p.strip()) for p in ports_arg.split(",")]
    except ValueError:
        raise ValueError("Formato de puertos inválido. Usa algo como: 80,443,445")


def run_scan(ip: str, ports: List[int], threads: int) -> List[Dict]:
    scan_results = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, ip, port): port for port in ports}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    scan_results.append(result)

    except KeyboardInterrupt:
        console.print("\n[yellow]Escaneo interrumpido por el usuario.[/yellow]")
        raise

    return scan_results


def save_outputs(
    output_format: str,
    output_path: str,
    results: Dict,
    plain_output: str
) -> None:
    if output_format == "json":
        save_json_results(results, output_path)
        console.print(f"[bold green]Resultados guardados en {output_path}[/bold green]")

    elif output_format == "plain":
        save_plain_results(plain_output, output_path)
        console.print(f"[bold green]Resultados guardados en {output_path}[/bold green]")

    elif output_format == "both":
        save_json_results(results, f"{output_path}.json")
        save_plain_results(plain_output, f"{output_path}.txt")
        console.print(
            f"[bold green]Resultados guardados en {output_path}.json y {output_path}.txt[/bold green]"
        )


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
        help="Archivo de salida o prefijo de salida"
    )
    parser.add_argument(
        "--format",
        choices=["json", "plain", "both"],
        default="json",
        help="Formato de salida a fichero: json, plain o both"
    )

    args = parser.parse_args()

    try:
        ip = resolve_target(args.target)
        ports = parse_ports(args.ports)

        console.print(f"[cyan]Objetivo:[/cyan] {args.target} -> {ip}")
        console.print(f"[cyan]Escaneando {len(ports)} puertos con {args.threads} hilos...[/cyan]")

        scan_results = run_scan(ip, ports, args.threads)
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

        plain_output = generate_plain_output(
            args.target,
            ip,
            scan_results,
            ad_analysis,
            modules
        )

        save_outputs(args.format, args.output, results, plain_output)

        if ad_analysis["possible_ad"]:
            console.print(
                f"[bold magenta]Posible entorno AD detectado[/bold magenta] "
                f"(puertos: {ad_analysis['matched_ports']})"
            )

    except KeyboardInterrupt:
        console.print("[bold yellow]Saliendo limpiamente...[/bold yellow]")
        sys.exit(130)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Error inesperado:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
