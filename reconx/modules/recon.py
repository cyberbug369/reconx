import json
import os
from datetime import datetime

from reconx.modules.dns import inspect_dns
from reconx.modules.network import scan_common_ports
from reconx.modules.web import (
    detect_technologies,
    inspect_headers,
)


def save_recon_report(target, report, output_format):
    """Save a consolidated RECONX report."""

    os.makedirs("reports", exist_ok=True)

    safe_target = (
        target.replace("://", "_")
        .replace("/", "_")
        .replace(":", "_")
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if output_format == "json":
        filename = (
            f"reports/{safe_target}-recon-{timestamp}.json"
        )

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=2,
                default=str,
            )

    else:
        filename = (
            f"reports/{safe_target}-recon-{timestamp}.md"
        )

        with open(filename, "w", encoding="utf-8") as file:
            file.write("# RECONX Security Assessment\n\n")
            file.write(
                f"**Target:** `{target}`\n\n"
            )
            file.write(
                f"**Generated:** "
                f"{report['generated_at']}\n\n"
            )

            file.write("## Assessment\n\n")
            file.write(
                "This report contains read-only "
                "reconnaissance results.\n\n"
            )

            for section, data in report["results"].items():
                file.write(
                    f"## {section.title()}\n\n"
                )

                if isinstance(data, dict):
                    for key, value in data.items():
                        file.write(
                            f"- **{key}:** {value}\n"
                        )
                else:
                    file.write(
                        f"{data}\n"
                    )

                file.write("\n")

            file.write("---\n\n")
            file.write(
                "**RECONX** — Intelligent Recon Assistant\n\n"
            )
            file.write(
                "**Founder: EZEWELE aka cyberbug**\n"
            )

    return filename


def run_recon(target, output_format=None):
    """Run a consolidated authorized reconnaissance workflow."""

    print("\nRECONX RECON WORKFLOW")
    print("════════════════════════════════════════")
    print(f"Target: {target}")

    report = {
        "tool": "RECONX",
        "version": "0.1.0",
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "results": {},
    }

    print("\n[1/4] DNS INSPECTION")
    print("────────────────────────────────")

    try:
        dns_result = inspect_dns(target)

        report["results"]["dns"] = (
            dns_result
            if dns_result is not None
            else "DNS inspection completed."
        )

    except Exception as error:
        print(f"[!] DNS module error: {error}")

        report["results"]["dns"] = {
            "error": str(error)
        }

    print("\n[2/4] HTTP HEADER INSPECTION")
    print("────────────────────────────────")

    try:
        header_result = inspect_headers(target)

        report["results"]["headers"] = (
            header_result
            if header_result is not None
            else "HTTP header inspection completed."
        )

    except Exception as error:
        print(f"[!] HTTP module error: {error}")

        report["results"]["headers"] = {
            "error": str(error)
        }

    print("\n[3/4] TECHNOLOGY DETECTION")
    print("────────────────────────────────")

    try:
        tech_result = detect_technologies(target)

        report["results"]["technologies"] = (
            tech_result
            if tech_result is not None
            else "Technology detection completed."
        )

    except Exception as error:
        print(f"[!] Technology module error: {error}")

        report["results"]["technologies"] = {
            "error": str(error)
        }

    print("\n[4/4] COMMON TCP PORT CHECK")
    print("────────────────────────────────")

    try:
        port_result = scan_common_ports(target)

        report["results"]["ports"] = (
            port_result
            if port_result is not None
            else "Port check completed."
        )

    except Exception as error:
        print(f"[!] Port module error: {error}")

        report["results"]["ports"] = {
            "error": str(error)
        }

    if output_format:
        filename = save_recon_report(
            target,
            report,
            output_format,
        )

        print("\n────────────────────────────────")
        print(
            f"[+] {output_format.upper()} report saved:"
        )
        print(f"    {filename}")

    print("\n════════════════════════════════════════")
    print("RECON WORKFLOW COMPLETE")
    print("All checks were read-only.")

    return report
