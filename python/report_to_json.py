#!/usr/bin/env python3

import argparse
import json
import re
import sys

from datetime import datetime, timezone
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Convert a Linux Security Auditor text report to JSON"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the text audit report"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path where the JSON report will be saved"
    )

    return parser.parse_args()

def extract_security_score(lines):
    for line in lines:
        match = re.search(
            r"SECURITY\s+SCORE\s*:?\s*(\d+)\s*/\s*100",
            line,
            re.IGNORECASE
        )

        if match:
            return int(match.group(1))

    return None

def extract_findings(lines):
    findings = []

    finding_pattern = re.compile(
        r"^\[(INFO|PASS|OK|WARNING|CRITICAL|FAIL)\]\s*(.*)$",
        re.IGNORECASE
    )

    for line in lines:
        match = finding_pattern.match(line.strip())

        if match:
            level = match.group(1).upper()
            message = match.group(2).strip()

            findings.append(
                {
                    "level": level,
                    "message": message
                }
            )

    return findings

def extract_recommendations(lines):
    recommendations = []

    recommendation_pattern = re.compile(
        r"^\[RECOMMENDATION\]\s*(.*)$",
        re.IGNORECASE
    )

    for line in lines:
        match = recommendation_pattern.match(line.strip())

        if match:
            recommendation = match.group(1).strip()

            if recommendation:
                recommendations.append(recommendation)

    return recommendations

def count_finding_levels(findings):
    counts = {
        "INFO": 0,
        "PASS": 0,
        "OK": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "FAIL": 0
    }

    for finding in findings:
        level = finding["level"]

        if level in counts:
            counts[level] += 1

    return counts

def convert_report(input_file, output_file):
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.is_file():
        print(
            f"[ERROR] Input report does not exist: {input_path}",
            file=sys.stderr
        )

        return 1

    try:
        report_text = input_path.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except OSError as error:
        print(
            f"[ERROR] Could not read report: {error}",
            file=sys.stderr
        )

        return 1

    lines = report_text.splitlines()
    security_score = extract_security_score(lines)
    findings = extract_findings(lines)
    recommendations = extract_recommendations(lines)
    finding_counts = count_finding_levels(findings)

    json_report = {
        "schema_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_report": input_path.name,
        "summary": {
            "security_score": security_score,
            "finding_counts": finding_counts,
            "total_findings": len(findings),
            "recommendation_count": len(recommendations)
        },
        "findings": findings,
        "recommendations": recommendations
    }

    try:
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        output_path.write_text(
            json.dumps(
                json_report,
                indent=4
            ),
            encoding="utf-8"
        )

    except OSError as error:
        print(
            f"[ERROR] Could not write JSON report: {error}",
            file=sys.stderr
        )

        return 1

    print(f"[OK] JSON report created: {output_path}")

    return 0


def main():
    args = parse_arguments()

    return convert_report(
        args.input,
        args.output
    )


if __name__ == "__main__":
    sys.exit(main())
