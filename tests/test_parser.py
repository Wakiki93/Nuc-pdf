"""Tests for the JSONL parser."""

import io
import json
import pytest
from pathlib import Path

from nucleireport.parser import parse_jsonl_file, parse_jsonl_stream


SAMPLE_DATA = Path(__file__).parent.parent / "sample_data" / "sample_scan.jsonl"

VALID_LINE = json.dumps({
    "template-id": "test-vuln-001",
    "info": {
        "name": "Test Vulnerability",
        "severity": "high",
        "description": "A test finding.",
    },
    "type": "http",
    "host": "https://example.com",
    "matched-at": "https://example.com/test",
    "timestamp": "2025-02-10T12:00:00-05:00",
    "matcher-status": True,
})


class TestParseJsonlStream:
    def test_valid_single_line(self):
        stream = io.StringIO(VALID_LINE + "\n")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 1
        assert result.skipped_lines == 0
        assert result.findings[0].template_id == "test-vuln-001"

    def test_empty_stream(self):
        stream = io.StringIO("")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 0
        assert result.total_lines == 0

    def test_blank_lines_skipped(self):
        stream = io.StringIO("\n\n" + VALID_LINE + "\n\n")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 1
        assert result.total_lines == 1

    def test_malformed_json_skipped(self):
        stream = io.StringIO("not valid json\n" + VALID_LINE + "\n")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 1
        assert result.skipped_lines == 1
        assert len(result.errors) == 1
        assert "invalid JSON" in result.errors[0]

    def test_valid_json_but_invalid_model_skipped(self):
        bad_data = json.dumps({"foo": "bar"})  # missing required fields
        stream = io.StringIO(bad_data + "\n" + VALID_LINE + "\n")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 1
        assert result.skipped_lines == 1
        assert "validation failed" in result.errors[0]

    def test_multiple_valid_lines(self):
        lines = "\n".join([VALID_LINE] * 5) + "\n"
        stream = io.StringIO(lines)
        result = parse_jsonl_stream(stream)
        assert result.success_count == 5
        assert result.skipped_lines == 0

    def test_optional_fields_missing(self):
        """Findings with only required fields should parse fine."""
        minimal = json.dumps({
            "template-id": "minimal-001",
            "info": {"name": "Minimal", "severity": "info"},
            "type": "http",
            "host": "https://example.com",
            "matched-at": "https://example.com/",
            "timestamp": "2025-01-01T00:00:00Z",
            "matcher-status": False,
        })
        stream = io.StringIO(minimal + "\n")
        result = parse_jsonl_stream(stream)
        assert result.success_count == 1
        f = result.findings[0]
        assert f.info.classification is None
        assert f.info.remediation is None
        assert f.ip is None
        assert f.curl_command is None

    def test_summary_output(self):
        stream = io.StringIO("bad\n" + VALID_LINE + "\n")
        result = parse_jsonl_stream(stream)
        summary = result.summary()
        assert "1/2" in summary
        assert "Skipped 1" in summary


class TestParseJsonlFile:
    def test_sample_data_parses(self):
        result = parse_jsonl_file(SAMPLE_DATA)
        assert result.success_count == 26
        assert result.skipped_lines == 0

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_jsonl_file("/nonexistent/path.jsonl")

    def test_all_severities_present(self):
        result = parse_jsonl_file(SAMPLE_DATA)
        severities = {f.info.severity.value for f in result.findings}
        assert severities == {"critical", "high", "medium", "low", "info"}
