"""Data processor — groups, sorts, deduplicates, and summarizes findings."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .models import NucleiFinding, ScanReport, Severity


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def deduplicate(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    """Remove duplicate findings (same template-id + same host).

    Keeps the first occurrence of each unique finding.
    """
    seen: dict[str, NucleiFinding] = {}
    for f in findings:
        if f.dedup_key not in seen:
            seen[f.dedup_key] = f
    return list(seen.values())


def filter_by_min_severity(
    findings: list[NucleiFinding],
    min_severity: Severity,
) -> list[NucleiFinding]:
    """Filter findings to only include those at or above the minimum severity.

    Severity order: critical > high > medium > low > info
    Lower sort_order = more severe.
    """
    threshold = min_severity.sort_order
    return [f for f in findings if f.info.severity.sort_order <= threshold]


def group_by_severity(
    findings: list[NucleiFinding],
) -> dict[str, list[NucleiFinding]]:
    """Group findings by severity level, sorted by CVSS score descending within each group."""
    groups: dict[str, list[NucleiFinding]] = {s.value: [] for s in SEVERITY_ORDER}

    for f in findings:
        groups[f.info.severity.value].append(f)

    # Sort each group by CVSS score descending
    for sev in groups:
        groups[sev].sort(key=lambda f: f.cvss_score, reverse=True)

    return groups


def extract_targets(findings: list[NucleiFinding]) -> list[str]:
    """Extract unique host targets, preserving first-seen order."""
    seen: set[str] = set()
    targets: list[str] = []
    for f in findings:
        if f.host not in seen:
            seen.add(f.host)
            targets.append(f.host)
    return targets


def extract_time_range(findings: list[NucleiFinding]) -> tuple[str, str]:
    """Extract earliest and latest timestamps from findings."""
    if not findings:
        return ("", "")
    timestamps = [f.timestamp for f in findings]
    return (min(timestamps), max(timestamps))


def extract_top_critical(
    findings: list[NucleiFinding],
    limit: int = 5,
) -> list[NucleiFinding]:
    """Extract the top N most severe findings across all severity levels.

    Sorted by: severity (critical first), then CVSS score descending.
    """
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.info.severity.sort_order, -f.cvss_score),
    )
    return sorted_findings[:limit]


def process_findings(
    findings: list[NucleiFinding],
    title: str = "Vulnerability Assessment Report",
    min_severity: Optional[Severity] = None,
    dedup: bool = True,
) -> ScanReport:
    """Process raw findings into a ScanReport ready for PDF rendering.

    Args:
        findings: Raw list of NucleiFinding objects from the parser.
        title: Report title.
        min_severity: If set, exclude findings below this severity.
        dedup: If True, deduplicate by template-id + host.

    Returns:
        ScanReport with all processed data.
    """
    if dedup:
        findings = deduplicate(findings)

    if min_severity is not None:
        findings = filter_by_min_severity(findings, min_severity)

    grouped = group_by_severity(findings)
    severity_counts = {sev: len(items) for sev, items in grouped.items()}

    return ScanReport(
        title=title,
        generated_at=datetime.now(),
        total_findings=len(findings),
        targets=extract_targets(findings),
        severity_counts=severity_counts,
        findings_by_severity=grouped,
        top_critical=extract_top_critical(findings),
        scan_time_range=extract_time_range(findings),
    )
