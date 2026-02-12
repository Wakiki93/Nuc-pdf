"""Tests for the data processor."""

import json
import pytest

from nucleireport.models import NucleiFinding, Severity
from nucleireport.processor import (
    deduplicate,
    filter_by_min_severity,
    group_by_severity,
    extract_targets,
    extract_time_range,
    extract_top_critical,
    process_findings,
)
from nucleireport.parser import parse_jsonl_file
from pathlib import Path


SAMPLE_DATA = Path(__file__).parent.parent / "sample_data" / "sample_scan.jsonl"


def _make_finding(
    template_id: str = "test-001",
    host: str = "https://example.com",
    severity: str = "high",
    cvss_score: float | None = None,
    timestamp: str = "2025-02-10T12:00:00-05:00",
) -> NucleiFinding:
    """Helper to create a NucleiFinding for testing."""
    data = {
        "template-id": template_id,
        "info": {
            "name": f"Test {template_id}",
            "severity": severity,
        },
        "type": "http",
        "host": host,
        "matched-at": f"{host}/test",
        "timestamp": timestamp,
        "matcher-status": True,
    }
    if cvss_score is not None:
        data["info"]["classification"] = {"cvss-score": cvss_score}
    return NucleiFinding.model_validate(data)


class TestDeduplicate:
    def test_no_dupes(self):
        findings = [
            _make_finding(template_id="a", host="https://1.com"),
            _make_finding(template_id="b", host="https://2.com"),
        ]
        assert len(deduplicate(findings)) == 2

    def test_removes_dupes(self):
        findings = [
            _make_finding(template_id="a", host="https://1.com"),
            _make_finding(template_id="a", host="https://1.com"),
            _make_finding(template_id="a", host="https://1.com"),
        ]
        assert len(deduplicate(findings)) == 1

    def test_same_template_different_host_kept(self):
        findings = [
            _make_finding(template_id="a", host="https://1.com"),
            _make_finding(template_id="a", host="https://2.com"),
        ]
        assert len(deduplicate(findings)) == 2

    def test_empty_list(self):
        assert deduplicate([]) == []


class TestFilterBySeverity:
    def test_filter_medium_and_above(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
            _make_finding(severity="low"),
            _make_finding(severity="info"),
        ]
        filtered = filter_by_min_severity(findings, Severity.MEDIUM)
        severities = {f.info.severity.value for f in filtered}
        assert severities == {"critical", "high", "medium"}

    def test_filter_critical_only(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        filtered = filter_by_min_severity(findings, Severity.CRITICAL)
        assert len(filtered) == 1
        assert filtered[0].info.severity == Severity.CRITICAL

    def test_filter_info_keeps_all(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="info"),
        ]
        filtered = filter_by_min_severity(findings, Severity.INFO)
        assert len(filtered) == 2


class TestGroupBySeverity:
    def test_groups_correctly(self):
        findings = [
            _make_finding(severity="critical", cvss_score=10.0),
            _make_finding(severity="high", cvss_score=8.0),
            _make_finding(severity="medium", cvss_score=5.0),
            _make_finding(severity="low", cvss_score=3.0),
            _make_finding(severity="info", cvss_score=0.0),
        ]
        groups = group_by_severity(findings)
        assert len(groups["critical"]) == 1
        assert len(groups["high"]) == 1
        assert len(groups["medium"]) == 1
        assert len(groups["low"]) == 1
        assert len(groups["info"]) == 1

    def test_sorted_by_cvss_within_group(self):
        findings = [
            _make_finding(template_id="a", severity="high", cvss_score=7.0),
            _make_finding(template_id="b", severity="high", cvss_score=9.8),
            _make_finding(template_id="c", severity="high", cvss_score=8.5),
        ]
        groups = group_by_severity(findings)
        scores = [f.cvss_score for f in groups["high"]]
        assert scores == [9.8, 8.5, 7.0]

    def test_empty_groups_present(self):
        groups = group_by_severity([])
        assert set(groups.keys()) == {"critical", "high", "medium", "low", "info"}
        assert all(len(v) == 0 for v in groups.values())


class TestExtractTargets:
    def test_unique_ordered(self):
        findings = [
            _make_finding(host="https://b.com"),
            _make_finding(host="https://a.com"),
            _make_finding(host="https://b.com"),  # dupe
            _make_finding(host="https://c.com"),
        ]
        targets = extract_targets(findings)
        assert targets == ["https://b.com", "https://a.com", "https://c.com"]

    def test_empty(self):
        assert extract_targets([]) == []


class TestExtractTimeRange:
    def test_range(self):
        findings = [
            _make_finding(timestamp="2025-02-10T14:00:00-05:00"),
            _make_finding(timestamp="2025-02-10T16:00:00-05:00"),
            _make_finding(timestamp="2025-02-10T12:00:00-05:00"),
        ]
        earliest, latest = extract_time_range(findings)
        assert "12:00:00" in earliest
        assert "16:00:00" in latest

    def test_empty(self):
        assert extract_time_range([]) == ("", "")


class TestExtractTopCritical:
    def test_top_5_by_severity_then_cvss(self):
        findings = [
            _make_finding(template_id="c1", severity="critical", cvss_score=10.0),
            _make_finding(template_id="c2", severity="critical", cvss_score=9.8),
            _make_finding(template_id="h1", severity="high", cvss_score=9.8),
            _make_finding(template_id="h2", severity="high", cvss_score=8.0),
            _make_finding(template_id="m1", severity="medium", cvss_score=6.0),
            _make_finding(template_id="l1", severity="low", cvss_score=3.0),
        ]
        top = extract_top_critical(findings, limit=5)
        assert len(top) == 5
        # Critical first, then high, then medium
        assert top[0].template_id == "c1"
        assert top[1].template_id == "c2"
        assert top[2].info.severity == Severity.HIGH
        assert top[4].info.severity == Severity.MEDIUM

    def test_fewer_than_limit(self):
        findings = [_make_finding(severity="high")]
        assert len(extract_top_critical(findings, limit=5)) == 1


class TestProcessFindings:
    def test_full_pipeline_with_sample_data(self):
        result = parse_jsonl_file(SAMPLE_DATA)
        report = process_findings(result.findings)

        assert report.total_findings == 26
        assert report.severity_counts["critical"] == 5
        assert report.severity_counts["high"] == 8
        assert len(report.targets) > 0
        assert len(report.top_critical) == 5
        assert report.top_critical[0].info.severity == Severity.CRITICAL
        assert report.scan_time_range[0] != ""

    def test_dedup_applied(self):
        findings = [
            _make_finding(template_id="a", host="https://x.com"),
            _make_finding(template_id="a", host="https://x.com"),
        ]
        report = process_findings(findings)
        assert report.total_findings == 1

    def test_min_severity_filter(self):
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="low", template_id="low-1"),
            _make_finding(severity="info", template_id="info-1"),
        ]
        report = process_findings(findings, min_severity=Severity.MEDIUM)
        assert report.total_findings == 1
        assert report.severity_counts["low"] == 0
        assert report.severity_counts["info"] == 0

    def test_custom_title(self):
        report = process_findings([], title="Custom Report")
        assert report.title == "Custom Report"

    def test_empty_findings(self):
        report = process_findings([])
        assert report.total_findings == 0
        assert report.targets == []
        assert report.top_critical == []
        assert report.scan_time_range == ("", "")
