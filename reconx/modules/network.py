import socket
import platform
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
}


def get_interfaces():
    """Get IPv4 network interfaces from Linux."""

    interfaces = []

    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            check=True,
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            if len(parts) >= 4:
                interfaces.append({
                    "name": parts[1],
                    "ipv4": parts[3].split("/")[0],
                })

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return interfaces


def get_network_info():
    """Collect basic network information."""

    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_version": platform.release(),
        "interfaces": get_interfaces(),
    }


def display_network_info():
    """Display network information."""

    info = get_network_info()

    print("\nRECONX NETWORK INFORMATION")
    print("────────────────────────────────")

    print(f"Hostname        : {info['hostname']}")
    print(f"Operating System: {info['platform']}")
    print(f"OS Version      : {info['platform_version']}")

    print("\nNETWORK INTERFACES")
    print("────────────────────────────────")

    if not info["interfaces"]:
        print("No interfaces detected.")
    else:
        for interface in info["interfaces"]:
            print(
                f"Interface: {interface['name']:<10}"
                f" IPv4: {interface['ipv4']}"
            )

    print("\n────────────────────────────────")


def scan_port(target, port, timeout=0.5):
    """Check whether a TCP port accepts a connection."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0

    except (socket.timeout, socket.gaierror, OSError):
        return False


def scan_common_ports(target):
    """Scan common TCP ports concurrently."""

    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n[!] Unable to resolve target: {target}")
        return

    print("\nRECONX TCP PORT SCANNER")
    print("────────────────────────────────")
    print(f"Target      : {target}")
    print(f"Ports       : {len(COMMON_PORTS)} common ports")
    print("Timeout     : 0.5s")
    print("\nPORT     STATE      SERVICE")
    print("────────────────────────────────")

    start_time = time.perf_counter()
    results = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        jobs = {
            executor.submit(scan_port, target, port): port
            for port in COMMON_PORTS
        }

        for job in as_completed(jobs):
            port = jobs[job]
            results[port] = job.result()

    open_ports = 0

    for port in sorted(COMMON_PORTS):
        service = COMMON_PORTS[port]

        if results[port]:
            state = "OPEN"
            open_ports += 1
        else:
            state = "CLOSED"

        print(f"{port:<8} {state:<10} {service}")

    elapsed = time.perf_counter() - start_time

    print("\n────────────────────────────────")
    print(f"Finished in {elapsed:.2f}s")
    print(f"Open ports: {open_ports}")
