
from pathlib import Path

from silentsec.scanners.bandit_runner import parse_bandit_payload
from silentsec.scanners.semgrep_runner import parse_semgrep_payload
from silentsec.schemas import Severity


def test_parse_semgrep_finding(tmp_path: Path):
    payload = {
        "results": [
            {
                "check_id": "python.test.eval",
                "path": "app.py",
                "start": {"line": 3},
                "end": {"line": 4},
                "extra": {
                    "message": "Avoid dynamic code execution.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-95"],
                        "confidence": "HIGH",
                    },
                },
            }
        ],
        "errors": [],
    }

    findings, errors = parse_semgrep_payload(payload, tmp_path)

    assert errors == []
    assert len(findings) == 1
    assert findings[0].file_path == "app.py"
    assert findings[0].start_line == 3
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe_id == "CWE-95"


def test_parse_bandit_finding(tmp_path: Path):
    payload = {
        "results": [
            {
                "filename": "app.py",
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Subprocess uses shell=True.",
                "line_number": 5,
                "line_range": [5, 6],
                "issue_cwe": {"id": 78},
            }
        ],
        "errors": [],
    }

    findings, errors = parse_bandit_payload(payload, tmp_path)

    assert errors == []
    assert len(findings) == 1
    assert findings[0].rule_id == "B602"
    assert findings[0].start_line == 5
    assert findings[0].end_line == 6
    assert findings[0].cwe_id == "CWE-78"


def test_semgrep_skips_invalid_result(tmp_path: Path):
    payload = {
        "results": [{"check_id": "bad.result", "path": "app.py"}],
        "errors": [],
    }

    findings, errors = parse_semgrep_payload(payload, tmp_path)

    assert findings == []
    assert errors


def test_bandit_skips_invalid_result(tmp_path: Path):
    payload = {
        "results": [{"test_id": "B602", "filename": "app.py"}],
        "errors": [],
    }

    findings, errors = parse_bandit_payload(payload, tmp_path)

    assert findings == []
    assert errors
