
import pytest
from pydantic import ValidationError

from silentsec.triage import TriagePriority, TriageResult


def valid_payload() -> dict:
    return {
        "finding_id": "finding-123",
        "fingerprint": "fingerprint-abc",
        "priority": TriagePriority.HIGH,
        "summary": "Potential unsafe evaluation of input.",
        "rationale": (
            "If untrusted input reaches the evaluation function, "
            "it may be interpreted as executable code."
        ),
        "remediation_steps": [
            "Avoid evaluating untrusted input.",
            "Use a safer parser or explicit input validation."
        ],
        "evidence": ["The scanner flagged an evaluation operation."],
        "limitations": ["Exploitability has not been confirmed."],
    }


def test_valid_triage_result_preserves_finding_identity():
    result = TriageResult(**valid_payload())

    assert result.finding_id == "finding-123"
    assert result.fingerprint == "fingerprint-abc"
    assert result.priority == TriagePriority.HIGH
    assert result.requires_human_review is True


def test_evidence_and_limitations_default_to_empty_lists():
    payload = valid_payload()
    payload.pop("evidence")
    payload.pop("limitations")

    result = TriageResult(**payload)

    assert result.evidence == []
    assert result.limitations == []


def test_blank_summary_is_rejected():
    payload = valid_payload()
    payload["summary"] = "   "

    with pytest.raises(ValidationError):
        TriageResult(**payload)


def test_empty_remediation_steps_are_rejected():
    payload = valid_payload()
    payload["remediation_steps"] = []

    with pytest.raises(ValidationError):
        TriageResult(**payload)


def test_invalid_priority_is_rejected():
    payload = valid_payload()
    payload["priority"] = "urgent-but-not-supported"

    with pytest.raises(ValidationError):
        TriageResult(**payload)


def test_unexpected_fields_are_rejected():
    payload = valid_payload()
    payload["invented_vulnerability"] = True

    with pytest.raises(ValidationError):
        TriageResult(**payload)
