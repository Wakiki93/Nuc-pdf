# NucleiReport

Professional PDF report generator for [Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner output.

Takes raw JSONL scan results and produces clean, client-ready PDF reports with executive summaries, severity charts, color-coded finding cards, and appendices.

## What It Does

Nuclei outputs findings as JSONL — one JSON object per line. Great for machines, useless for clients. NucleiReport turns that into a multi-page PDF with:

- **Cover page** with scan metadata and severity overview
- **Executive summary** with bar chart, donut chart, severity table, and top 5 critical findings
- **Detailed findings** grouped by severity, each with description, CVE/CVSS data, remediation steps, and references
- **Appendices** with target list, scan metadata, severity definitions, and compact reference table

## Quick Start

### Install

```bash
git clone https://github.com/yourusername/nucleireport.git
cd nucleireport
pip install -r requirements.txt
```

### Generate a Report

```bash
# From sample data
python -m nucleireport generate -i sample_data/sample_scan.jsonl -o report.pdf

# With a custom title
python -m nucleireport generate \
  -i scan_results.jsonl \
  -o report.pdf \
  --title "Acme Corp Q1 2025 Vulnerability Assessment"

# Filter to medium+ severity only
python -m nucleireport generate \
  -i scan_results.jsonl \
  -o report.pdf \
  --min-severity medium
```

Your first report generates in under 2 seconds.

### Docker

```bash
# Build
docker build -t nucleireport .

# Generate a report (mount your scan data)
docker run --rm -v $(pwd)/data:/data nucleireport generate -i /data/scan.jsonl -o /data/report.pdf
```

## CLI Reference

### `nucleireport generate`

Generate a PDF report from Nuclei JSONL output.

| Option | Required | Description |
|--------|----------|-------------|
| `-i, --input` | Yes | Path to Nuclei JSONL file |
| `-o, --output` | Yes | Output PDF file path |
| `--title` | No | Report title (default: "Vulnerability Assessment Report") |
| `--min-severity` | No | Minimum severity to include: `critical`, `high`, `medium`, `low`, `info` |

### `nucleireport validate`

Check a JSONL file for validity without generating a report.

```bash
python -m nucleireport validate -i scan_results.jsonl
```

### `nucleireport summary`

Print scan statistics to the terminal (no PDF generated).

```bash
python -m nucleireport summary -i scan_results.jsonl
```

Output:
```
Scan Summary
=============================================
  Total findings:  26
  Unique targets:  12
  Scan start:      2025-02-10T14:32:07
  Scan end:        2025-02-10T14:37:50

Severity Breakdown
---------------------------------------------
  CRITICAL     5 (19.2%) #####
  HIGH         8 (30.8%) ########
  MEDIUM       6 (23.1%) ######
  LOW          4 (15.4%) ####
  INFO         3 (11.5%) ###
```

## Report Structure

The generated PDF contains these sections:

| Page | Content |
|------|---------|
| 1 | Cover page — title, target count, finding count, severity badges, scan date |
| 2-3 | Executive summary — risk paragraph, bar + donut charts, severity table, top 5 findings |
| 4+ | Detailed findings — grouped by severity (critical first), each with CVE, CVSS, description, target, remediation, references |
| Final | Appendices — targets scanned with finding counts, scan metadata, severity definitions, compact reference table |

## Input Format

NucleiReport expects standard Nuclei JSONL output (generated with `nuclei -jsonl`). Each line is a JSON object with fields like:

```json
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Apache Log4j RCE",
    "severity": "critical",
    "description": "...",
    "classification": { "cvss-score": 10.0 },
    "remediation": "Upgrade to Log4j 2.17.1 or later."
  },
  "host": "https://target.com",
  "matched-at": "https://target.com/api/login",
  "timestamp": "2025-02-10T14:32:07.123456-05:00",
  "matcher-status": true
}
```

Malformed lines are skipped with warnings — the parser won't crash on bad data.

## How It Handles Data

- **Deduplication** — Same template-id + same host = one finding (no duplicates from repeated scan matches)
- **Severity sorting** — Critical first, then high/medium/low/info. Within each group, sorted by CVSS score descending
- **Graceful parsing** — Malformed JSON lines are skipped with warnings. Missing optional fields are handled cleanly
- **Severity filtering** — `--min-severity medium` excludes low and info findings from the report

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| PDF generation | ReportLab (Platypus) |
| CLI | Click |
| Data validation | Pydantic v2 |
| Charts | Matplotlib |
| Containerization | Docker |

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Example Report

An example PDF generated from the included sample data is available at [`docs/example_report.pdf`](docs/example_report.pdf).

The sample data contains 26 findings across 12 targets, including real CVEs like Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), and MOVEit Transfer SQLi (CVE-2023-34362).

## License

MIT
