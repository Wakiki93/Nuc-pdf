"""JSONL parser for Nuclei scan output."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TextIO

from .models import NucleiFinding

logger = logging.getLogger(__name__)


class ParseResult:
    """Container for parse results with stats on success/failure."""

    def __init__(self) -> None:
        self.findings: list[NucleiFinding] = []
        self.total_lines: int = 0
        self.skipped_lines: int = 0
        self.errors: list[str] = []

    @property
    def success_count(self) -> int:
        return len(self.findings)

    def summary(self) -> str:
        lines = [
            f"Parsed {self.success_count}/{self.total_lines} lines successfully",
        ]
        if self.skipped_lines:
            lines.append(f"Skipped {self.skipped_lines} malformed/empty lines")
        if self.errors:
            lines.append("Errors:")
            for err in self.errors:
                lines.append(f"  - {err}")
        return "\n".join(lines)


def parse_jsonl_file(path: str | Path) -> ParseResult:
    """Parse a Nuclei JSONL file from disk.

    Args:
        path: Path to the .jsonl file.

    Returns:
        ParseResult with findings list and parse statistics.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        PermissionError: If the file can't be read.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"JSONL file not found: {path}")

    with open(path, encoding="utf-8") as f:
        return parse_jsonl_stream(f, source=str(path))


def parse_jsonl_stream(stream: TextIO, source: str = "<stream>") -> ParseResult:
    """Parse Nuclei JSONL data from any text stream.

    Args:
        stream: Any readable text stream producing JSONL lines.
        source: Label for error messages (e.g. filename).

    Returns:
        ParseResult with findings list and parse statistics.
    """
    result = ParseResult()

    for line_num, raw_line in enumerate(stream, 1):
        line = raw_line.strip()
        if not line:
            continue

        result.total_lines += 1

        # Step 1: Parse JSON
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            msg = f"{source} line {line_num}: invalid JSON — {e}"
            logger.warning(msg)
            result.errors.append(msg)
            result.skipped_lines += 1
            continue

        # Step 2: Validate into Pydantic model
        try:
            finding = NucleiFinding.model_validate(data)
            result.findings.append(finding)
        except Exception as e:
            msg = f"{source} line {line_num}: validation failed — {e}"
            logger.warning(msg)
            result.errors.append(msg)
            result.skipped_lines += 1
            continue

    return result
