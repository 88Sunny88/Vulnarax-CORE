import click
import json
from rich.console import Console
from rich.table import Table
from rich.text import Text
from .scanner import scan_image
from .scanner import generate_sbom

console = Console()


def _get_highest_severity(severity_list):
    """
    Convert severity array to single string for display:
    CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN
    """
    levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_level = 0
    max_sev = "UNKNOWN"
    for sev in severity_list:
        score = sev.get("score", "").upper()
        if score in levels and levels[score] > max_level:
            max_level = levels[score]
            max_sev = score
        elif score.startswith("CVSS"):  # treat CVSS3 as HIGH for display
            if 3 > max_level:
                max_level = 3
                max_sev = "HIGH"
    return max_sev


@click.group()
def main():
    """VulnaraX CLI - Container vulnerability scanner"""
    pass


@main.command()
@click.argument("image")
@click.option("--output", default=None, help="Output file for JSON report")
@click.option("--only-high", is_flag=True, help="Show only HIGH/CRITICAL vulnerabilities")
@click.option("--top", type=int, default=None, help="Show top N vulnerabilities by severity")
@click.option("--sbom", default=None, help="Generate CycloneDX SBOM JSON file")
def scan(image, output, only_high, top, sbom):
    """Scan a Docker IMAGE for vulnerabilities."""
    console.print(f"[bold cyan]Scanning image:[/bold cyan] {image} ...")
    results = scan_image(image)

    vulnerabilities = results.get("vulnerabilities", [])

    if not vulnerabilities:
        console.print("[green]No vulnerabilities found![/green]")
        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            console.print(f"[bold cyan]Report saved to:[/bold cyan] {output}")
        return

    # Annotate each vuln with highest severity
    for v in vulnerabilities:
        sev_list = v.get("severity")
        if isinstance(sev_list, list):
            v["_display_severity"] = _get_highest_severity(sev_list)
        else:
            v["_display_severity"] = str(sev_list).upper()

    # Apply filters
    if only_high:
        vulnerabilities = [v for v in vulnerabilities if v["_display_severity"] in ("HIGH", "CRITICAL")]
    if top:
        vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["_display_severity"], 0),
            reverse=True
        )[:top]

    table = Table(title="Vulnerabilities Summary")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("CVE ID", style="yellow")
    table.add_column("Fixed Version", style="green")
    table.add_column("Instructions", style="white")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    for v in vulnerabilities:
        severity = v.get("_display_severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity in ("HIGH", "CRITICAL"):
            severity_text = Text(severity, style="bold red")
        elif severity == "MEDIUM":
            severity_text = Text(severity, style="yellow")
        elif severity == "LOW":
            severity_text = Text(severity, style="green")
        else:
            severity_text = Text(severity, style="white")

        table.add_row(
            v.get("package", ""),
            v.get("version", ""),
            severity_text,
            v.get("id", ""),
            v.get("fixed_version") or "-",
            v.get("instructions", "-")
        )

    console.print(table)

    # Summary counts
    summary = " | ".join(f"{k}: {v}" for k, v in severity_counts.items() if v > 0)
    console.print(f"[bold]Summary:[/bold] {summary}")

    # Save JSON report
    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[bold cyan]Report saved to:[/bold cyan] {output}")
    
    if sbom:
        generate_sbom(image, vulnerabilities, sbom)
        console.print(f"[bold cyan]SBOM saved to:[/bold cyan] {sbom}")