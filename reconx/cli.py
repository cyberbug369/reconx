import click

from reconx.modules.dns import inspect_dns
from reconx.modules.malware import analyze_file
from reconx.modules.network import (
    display_network_info,
    scan_common_ports,
)
from reconx.modules.recon import run_recon
from reconx.modules.report import (
    save_json_report,
    save_markdown_report,
)
from reconx.modules.web import (
    detect_technologies,
    inspect_headers,
    inspect_metadata,
)
from reconx.modules.wifi import scan_wifi


BANNER = r"""
╔══════════════════════════════════════════╗
║                  RECONX                  ║
║       Intelligent Recon Assistant        ║
║                                          ║
║       Founder: EZEWELE aka cyberbug      ║
╚══════════════════════════════════════════╝
"""


@click.group()
def cli():
    """RECONX - Intelligent Recon Assistant."""

    click.echo(
        click.style(
            BANNER,
            fg="magenta",
            bold=True,
        )
    )

    click.echo(
        click.style(
            "Authorized security testing only.\n",
            fg="yellow",
            bold=True,
        )
    )


@cli.command()
def version():
    """Show the RECONX version."""

    click.echo(
        click.style(
            "RECONX v0.2.0",
            fg="cyan",
            bold=True,
        )
    )


@cli.command()
def network():
    """Show information about the current network environment."""

    display_network_info()


@cli.command()
@click.argument("target")
def ports(target):
    """Scan common TCP ports on an authorized target."""

    scan_common_ports(target)


@cli.command()
def wifi():
    """Inspect Wi-Fi capabilities available to the system."""

    scan_wifi()


@cli.command()
@click.argument("file_path")
@click.option(
    "--json",
    "json_report",
    is_flag=True,
    help="Save the analysis as a JSON report.",
)
@click.option(
    "--markdown",
    "markdown_report",
    is_flag=True,
    help="Save the analysis as a Markdown report.",
)
def analyze(file_path, json_report, markdown_report):
    """Analyze a file without executing it."""

    result = analyze_file(file_path)

    if result is None:
        return

    if json_report:
        output = f"reports/{file_path.replace('/', '_')}.json"

        save_json_report(
            result,
            output,
        )

        click.echo(
            click.style(
                f"\n[+] JSON report saved: {output}",
                fg="green",
                bold=True,
            )
        )

    if markdown_report:
        output = f"reports/{file_path.replace('/', '_')}.md"

        save_markdown_report(
            result,
            output,
        )

        click.echo(
            click.style(
                f"[+] Markdown report saved: {output}",
                fg="green",
                bold=True,
            )
        )


@cli.command()
@click.argument("target")
def dns(target):
    """Inspect DNS information for an authorized target."""

    inspect_dns(target)


@cli.command()
@click.argument("target")
def headers(target):
    """Inspect HTTP headers for an authorized target."""

    inspect_headers(target)


@cli.command()
@click.argument("target")
def tech(target):
    """Passively identify technologies exposed by a web target."""

    detect_technologies(target)


@cli.command()
@click.argument("target")
def metadata(target):
    """Inspect publicly exposed web metadata."""

    inspect_metadata(target)


@cli.command()
@click.argument("target")
@click.option(
    "--json",
    "json_report",
    is_flag=True,
    help="Save the complete assessment as JSON.",
)
@click.option(
    "--markdown",
    "markdown_report",
    is_flag=True,
    help="Save the complete assessment as Markdown.",
)
def recon(target, json_report, markdown_report):
    """Run a consolidated authorized reconnaissance workflow."""

    output_format = None

    if json_report and markdown_report:
        raise click.UsageError(
            "Choose either --json or --markdown, not both."
        )

    if json_report:
        output_format = "json"

    elif markdown_report:
        output_format = "markdown"

    run_recon(
        target,
        output_format=output_format,
    )


if __name__ == "__main__":
    cli()
