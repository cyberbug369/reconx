import socket


def _resolve_record(target, record_type):
    """Resolve a DNS record type using the system resolver."""

    try:
        import subprocess

        result = subprocess.run(
            ["getent", "ahostsv4", target],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return []

        addresses = []

        for line in result.stdout.splitlines():
            parts = line.split()

            if parts:
                address = parts[0]

                if address not in addresses:
                    addresses.append(address)

        if record_type == "A":
            return addresses

        return []

    except (
        subprocess.SubprocessError,
        OSError,
    ):
        return []


def inspect_dns(target):
    """Inspect basic DNS information for an authorized target."""

    target = target.strip()

    # Remove a URL scheme if the user accidentally supplied one.
    target = target.replace("https://", "")
    target = target.replace("http://", "")
    target = target.split("/")[0]

    print("\nRECONX DNS INSPECTOR")
    print("────────────────────────────────")
    print(f"Target: {target}")

    result = {
        "target": target,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "cname_records": [],
    }

    # A records
    print("\nA RECORDS")
    print("────────────────────────────────")

    try:
        ipv4 = socket.getaddrinfo(
            target,
            None,
            socket.AF_INET,
        )

        result["a_records"] = sorted(
            set(item[4][0] for item in ipv4)
        )

    except socket.gaierror:
        result["a_records"] = []

    if result["a_records"]:
        for address in result["a_records"]:
            print(f"  {address}")
    else:
        print("  No records detected.")

    # AAAA records
    print("\nAAAA RECORDS")
    print("────────────────────────────────")

    try:
        ipv6 = socket.getaddrinfo(
            target,
            None,
            socket.AF_INET6,
        )

        result["aaaa_records"] = sorted(
            set(item[4][0] for item in ipv6)
        )

    except socket.gaierror:
        result["aaaa_records"] = []

    if result["aaaa_records"]:
        for address in result["aaaa_records"]:
            print(f"  {address}")
    else:
        print("  No records detected.")

    # MX, NS and CNAME are intentionally kept conservative here.
    # We don't require third-party DNS libraries for the basic module.

    print("\nMX RECORDS")
    print("────────────────────────────────")
    print("  DNS resolver lookup not enabled.")

    print("\nNS RECORDS")
    print("────────────────────────────────")
    print("  DNS resolver lookup not enabled.")

    print("\nCNAME")
    print("────────────────────────────────")

    try:
        canonical_name = socket.getfqdn(target)

        if canonical_name and canonical_name != target:
            result["cname_records"] = [canonical_name]
            print(f"  {canonical_name}")
        else:
            print("  No records detected.")

    except OSError:
        print("  No records detected.")

    print("\n────────────────────────────────")
    print("DNS inspection complete.")

    return result
