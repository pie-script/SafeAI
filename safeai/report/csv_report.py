"""CSV report writer."""

import csv

FIELDNAMES = [
    "rule_id",
    "severity",
    "file",
    "line",
    "message",
    "risk_category",
    "remediation",
]


def write_csv(report, path):
    """Write scan findings to a CSV file."""
    with open(path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=FIELDNAMES,
            lineterminator="\n",
        )

        writer.writeheader()

        for finding in report["findings"]:
            writer.writerow(
                {field: finding.get(field, "") for field in FIELDNAMES}
            )
            