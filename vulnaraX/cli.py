import click
from .scanner import scan_image

@click.group()
def main():
    """VulnaraX CLI - Container vulnerability scanner"""
    pass

@main.command()
@click.argument("image")
@click.option("--output", default=None, help="Output file for JSON report")
def scan(image, output):
    """Scan a Docker IMAGE for vulnerabilities."""
    click.echo(f"Scanning image: {image}")

    # For now, just return dummy data
    results = scan_image(image)

    if output:
        import json
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        click.echo(f"Report saved to {output}")
    else:
        click.echo(results)