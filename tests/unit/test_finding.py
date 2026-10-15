
import pytest
from pydantic import ValidationError

from silentsec.schemas import Finding, FindingCategory, Severity


def valid_payload():
    return {
        "fingerprint": "example-fingerprint",
        "tool": "example-scanner",
        "rule_id": "TEST001",
        "file_path": "app/main.py",
        "start_line": 10,
        "end_line": 12,
        "category": FindingCategory.SECURITY,
        "severity": Severity.HIGH,
        "message": "Example security finding",
        "confidence": 0.9,
    }


def test_valid_finding():
    finding = Finding(**valid_payload())

    assert finding.file_path == "app/main.py"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9


def test_finding_id_is_generated():
    first = Finding(**valid_payload())
    second = Finding(**valid_payload())

    assert first.finding_id != second.finding_id


def test_start_line_must_be_positive():
    payload = valid_payload()
    payload["start_line"] = 0

    with pytest.raises(ValidationError):
        Finding(**payload)


def test_end_line_cannot_precede_start_line():
    payload = valid_payload()
    payload["start_line"] = 20
    payload["end_line"] = 10

    with pytest.raises(ValidationError):
        Finding(**payload)


def test_confidence_must_be_between_zero_and_one():
    payload = valid_payload()
    payload["confidence"] = 1.5

    with pytest.raises(ValidationError):
        Finding(**payload)


def test_unknown_fields_are_rejected():
    payload = valid_payload()
    payload["unknown_field"] = "unexpected"

    with pytest.raises(ValidationError):
        Finding(**payload)
