"""Pydantic models for parsing Nuclei JSONL output."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_order(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


class NucleiClassification(BaseModel):
    """CVE/CWE/CVSS classification data for a finding."""

    model_config = ConfigDict(populate_by_name=True)

    cve_id: Optional[list[str]] = Field(default=None, alias="cve-id")
    cwe_id: Optional[list[str]] = Field(default=None, alias="cwe-id")
    cvss_metrics: Optional[str] = Field(default=None, alias="cvss-metrics")
    cvss_score: Optional[float] = Field(default=None, alias="cvss-score")


class NucleiInfo(BaseModel):
    """Metadata about the vulnerability from the Nuclei template."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    author: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    description: Optional[str] = None
    reference: Optional[list[str]] = None
    severity: Severity
    classification: Optional[NucleiClassification] = None
    remediation: Optional[str] = None


class NucleiFinding(BaseModel):
    """A single finding from Nuclei JSONL output (one per line)."""

    model_config = ConfigDict(populate_by_name=True)

    template_id: str = Field(alias="template-id")
    template_url: Optional[str] = Field(default=None, alias="template-url")
    info: NucleiInfo
    type: str
    host: str
    matched_at: str = Field(alias="matched-at")
    extracted_results: Optional[list[str]] = Field(default=None, alias="extracted-results")
    ip: Optional[str] = None
    timestamp: str
    curl_command: Optional[str] = Field(default=None, alias="curl-command")
    matcher_status: bool = Field(alias="matcher-status")

    @property
    def dedup_key(self) -> str:
        """Unique key for deduplication: same template + same host = one finding."""
        return f"{self.template_id}::{self.host}"

    @property
    def cvss_score(self) -> float:
        """Convenience accessor for CVSS score, defaults to 0.0."""
        if self.info.classification and self.info.classification.cvss_score is not None:
            return self.info.classification.cvss_score
        return 0.0


class ScanReport(BaseModel):
    """Processed scan data ready for PDF rendering."""

    title: str
    generated_at: datetime
    total_findings: int
    targets: list[str]
    severity_counts: dict[str, int]
    findings_by_severity: dict[str, list[NucleiFinding]]
    top_critical: list[NucleiFinding]
    scan_time_range: tuple[str, str]
