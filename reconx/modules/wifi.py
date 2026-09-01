import subprocess


def get_wifi_interfaces():
    """Find wireless interfaces visible to Linux."""

    try:
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            check=False,
        )

        interfaces = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("Interface "):
                interfaces.append(line.split()[1])

        return interfaces

    except FileNotFoundError:
        return []


def scan_wifi():
    """Display wireless interfaces and nearby networks when supported."""

    print("\nRECONX WI-FI")
    print("────────────────────────────────")

    interfaces = get_wifi_interfaces()

    if not interfaces:
        print("[!] No Linux Wi-Fi interface detected.")
        print()
        print("This can happen in WSL2 because the physical")
        print("Wi-Fi adapter may not be exposed to Linux.")
        print()
        print("RECONX can still inspect your WSL network")
        print("interfaces with:")
        print("  reconx network")

        print("\n────────────────────────────────")
        return

    print(f"[+] Wireless interfaces: {len(interfaces)}")

    for interface in interfaces:
        print(f"    • {interface}")

    print("\nNearby network scanning will be added")
    print("when wireless scanning is supported.")

    print("────────────────────────────────")
