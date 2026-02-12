"""CLI entry point for NucleiReport."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .models import Severity
from .parser import parse_jsonl_file
from .processor import process_findings
from .report_builder import generate_report


SEVERITY_CHOICES = ["critical", "high", "medium", "low", "info"]


def _parse_and_check(input_file: str) -> list:
    """Parse input file and exit on failure."""
    try:
        result = parse_jsonl_file(input_file)
    except FileNotFoundError:
        click.secho(f"Error: File not found: {input_file}", fg="red")
        sys.exit(1)
    except PermissionError:
        click.secho(f"Error: Permission denied: {input_file}", fg="red")
        sys.exit(1)

    if result.skipped_lines:
        click.secho(
            f"Warning: Skipped {result.skipped_lines} malformed lines",
            fg="yellow",
        )
        for err in result.errors[:5]:
            click.echo(f"  {err}")
        if len(result.errors) > 5:
            click.echo(f"  ... and {len(result.errors) - 5} more")

    if result.success_count == 0:
        click.secho("Error: No valid findings found in input file.", fg="red")
        sys.exit(1)

    return result


@click.group()
@click.version_option(package_name="nucleireport")
def main():
    """NucleiReport - Professional PDF reports from Nuclei scan results."""
    pass


@main.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True),
              help="Path to Nuclei JSONL output file.")
@click.option("-o", "--output", "output_file", required=True, type=click.Path(),
              help="Output PDF file path.")
@click.option("--title", default="Vulnerability Assessment Report",
              help="Report title displayed on cover page.")
@click.option("--min-severity", type=click.Choice(SEVERITY_CHOICES, case_sensitive=False),
              default=None, help="Minimum severity to include (excludes lower).")
@click.option("--logo", type=click.Path(exists=True), default=None,
              help="Company logo image to display on cover page (PNG/JPG).")
def generate(input_file, output_file, title, min_severity, logo):
    """Generate a PDF report from Nuclei JSONL output."""
    click.echo(f"Reading {input_file}...")
    result = _parse_and_check(input_file)
    click.echo(f"  Parsed {result.success_count} findings")

    min_sev = Severity(min_severity) if min_severity else None

    click.echo("Processing findings...")
    report = process_findings(
        result.findings,
        title=title,
        min_severity=min_sev,
    )
    click.echo(f"  {report.total_findings} findings across {len(report.targets)} targets")

    if min_sev:
        click.echo(f"  Filtered to {min_severity}+ severity")

    click.echo("Generating PDF...")
    out_path = generate_report(report, output_file)
    size_kb = out_path.stat().st_size / 1024

    click.secho(f"\nReport generated: {out_path}", fg="green", bold=True)
    click.echo(f"  File size: {size_kb:.1f} KB")

    # Quick severity summary
    for sev in SEVERITY_CHOICES:
        count = report.severity_counts.get(sev, 0)
        if count > 0:
            color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "blue", "info": "white"}.get(sev, "white")
            click.secho(f"  {sev.upper():10s} {count}", fg=color)


@main.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True),
              help="Path to Nuclei JSONL output file.")
def validate(input_file):
    """Validate a Nuclei JSONL file without generating a report."""
    click.echo(f"Validating {input_file}...")
    result = _parse_and_check(input_file)

    click.secho(f"\nValid: {result.success_count} findings parsed successfully", fg="green")

    if result.skipped_lines:
        click.secho(f"Skipped: {result.skipped_lines} lines", fg="yellow")
    else:
        click.echo("No errors found.")

    # Severity breakdown
    counts: dict[str, int] = {}
    for f in result.findings:
        sev = f.info.severity.value
        counts[sev] = counts.get(sev, 0) + 1

    click.echo("\nSeverity breakdown:")
    for sev in SEVERITY_CHOICES:
        count = counts.get(sev, 0)
        click.echo(f"  {sev.upper():10s} {count}")


@main.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True),
              help="Path to Nuclei JSONL output file.")
@click.option("--min-severity", type=click.Choice(SEVERITY_CHOICES, case_sensitive=False),
              default=None, help="Minimum severity to include.")
def summary(input_file, min_severity):
    """Print summary statistics from a Nuclei JSONL file (no PDF)."""
    click.echo(f"Reading {input_file}...")
    result = _parse_and_check(input_file)

    min_sev = Severity(min_severity) if min_severity else None

    report = process_findings(
        result.findings,
        min_severity=min_sev,
    )

    click.echo("")
    click.secho("Scan Summary", bold=True)
    click.echo("=" * 45)
    click.echo(f"  Total findings:  {report.total_findings}")
    click.echo(f"  Unique targets:  {len(report.targets)}")

    if report.scan_time_range[0]:
        click.echo(f"  Scan start:      {report.scan_time_range[0][:19]}")
        click.echo(f"  Scan end:        {report.scan_time_range[1][:19]}")

    click.echo("")
    click.secho("Severity Breakdown", bold=True)
    click.echo("-" * 45)
    for sev in SEVERITY_CHOICES:
        count = report.severity_counts.get(sev, 0)
        pct = f"{count / report.total_findings * 100:.1f}%" if report.total_findings else "0%"
        bar = "#" * min(count, 30)
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "blue", "info": "white"}.get(sev, "white")
        click.secho(f"  {sev.upper():10s} {count:3d} ({pct:5s}) {bar}", fg=color)

    click.echo("")
    click.secho("Targets", bold=True)
    click.echo("-" * 45)
    for target in report.targets:
        click.echo(f"  {target}")

    if report.top_critical:
        click.echo("")
        click.secho("Top 5 Most Critical", bold=True)
        click.echo("-" * 45)
        for i, f in enumerate(report.top_critical, 1):
            cvss = f"CVSS {f.cvss_score}" if f.cvss_score else ""
            click.echo(f"  {i}. [{f.info.severity.value.upper()}] {f.info.name} {cvss}")
            click.echo(f"     {f.host}")


if __name__ == "__main__":
    main()
