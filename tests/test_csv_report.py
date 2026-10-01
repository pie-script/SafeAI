import csv

from safeai.cmd.cli import main
from safeai.report.csv_report import write_csv

EXPECTED_HEADER = [
    "rule_id",
    "severity",
    "file",
    "line",
    "message",
    "risk_category",
    "remediation",
]


def test_csv_normal_finding(tmp_path):
    finding = {
        "rule_id": "TEST",
        "severity": "high",
        "file": "app.py",
        "line": 42,
        "message": "Example finding",
        "risk_category": "security",
        "remediation": "Validate the input",
    }
    out = tmp_path / "report.csv"

    write_csv({"findings": [finding]}, str(out))

    assert out.exists()
    with out.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.reader(csv_file))

    assert rows == [
        EXPECTED_HEADER,
        ["TEST", "high", "app.py", "42", "Example finding", "security", "Validate the input"],
    ]


def test_csv_empty_findings(tmp_path):
    out = tmp_path / "report.csv"

    write_csv({"findings": []}, str(out))

    assert out.exists()
    with out.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.reader(csv_file))

    assert rows == [EXPECTED_HEADER]


def test_csv_special_characters(tmp_path):
    message = 'He said "check this, carefully".\nThen continue.'
    finding = {
        "rule_id": "TEST",
        "severity": "medium",
        "file": "app.py",
        "line": 7,
        "message": message,
        "risk_category": "security",
        "remediation": "Review the message",
    }
    out = tmp_path / "report.csv"

    write_csv({"findings": [finding]}, str(out))

    with out.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 1
    assert rows[0]["message"] == message


def test_csv_cli_output(tmp_path):
    output = tmp_path / "report.csv"

    main([
        "scan",
        str(tmp_path),
        "--csv",
        str(output),
        "--no-registry",
    ])

    assert output.exists()

    with output.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.reader(csv_file))

    assert rows[0] == EXPECTED_HEADER
    