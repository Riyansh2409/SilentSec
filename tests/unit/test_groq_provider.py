import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    Severity,
)
from silentsec.triage.groq_provider import GroqTriageProvider


def make_finding(
    category: FindingCategory = FindingCategory.SECURITY,
) -> Finding:
    return Finding(
        fingerprint="groq-test-fingerprint",
        tool="semgrep",
        rule_id="TEST001",
        file_path="app.py",
        start_line=10,
        end_line=10,
        category=category,
        severity=Severity.HIGH,
        message="Potential command injection",
    )


def make_payload(finding: Finding) -> dict:
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "priority": "high",
        "summary": "Potential command injection risk.",
        "rationale": "Untrusted input may reach command execution.",
        "remediation_steps": [
            "Avoid shell execution with untrusted input.",
        ],
        "evidence": ["Scanner flagged app.py at line 10."],
        "limitations": ["The full call path was not verified."],
        "requires_human_review": True,
    }


def make_client(content: str) -> Mock:
    client = Mock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )
    return client


def test_groq_returns_validated_result():
    finding = make_finding()
    client = make_client(json.dumps(make_payload(finding)))
    provider = GroqTriageProvider(client=client)

    result = provider.triage(finding=finding)

    assert result.finding_id == finding.finding_id
    assert result.fingerprint == finding.fingerprint
    assert result.priority.value == "high"
    assert result.requires_human_review is True


def test_groq_uses_configured_model_and_json_mode():
    finding = make_finding()
    client = make_client(json.dumps(make_payload(finding)))
    provider = GroqTriageProvider(
        client=client,
        model="test-model",
    )

    provider.triage(
        finding=finding,
        context="Example test context",
    )

    call = client.chat.completions.create.call_args
    assert call.kwargs["model"] == "test-model"
    assert call.kwargs["response_format"] == {"type": "json_object"}
    assert "Example test context" in (call.kwargs["messages"][1]["content"])


def test_groq_rejects_invalid_json():
    finding = make_finding()
    provider = GroqTriageProvider(client=make_client("{invalid"))

    with pytest.raises(ValueError, match="invalid JSON"):
        provider.triage(finding=finding)


def test_groq_rejects_invalid_schema():
    finding = make_finding()
    payload = make_payload(finding)
    payload["remediation_steps"] = []

    provider = GroqTriageProvider(client=make_client(json.dumps(payload)))

    with pytest.raises(ValidationError):
        provider.triage(finding=finding)


def test_groq_redacts_secret_finding_content():
    finding = make_finding(FindingCategory.SECRET)
    finding.message = "Leaked token: ghp_example_sensitive_value"

    client = make_client(json.dumps(make_payload(finding)))
    provider = GroqTriageProvider(client=client)

    provider.triage(
        finding=finding,
        context="Token value: ghp_another_sensitive_value",
    )

    user_content = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]

    assert "ghp_example_sensitive_value" not in user_content
    assert "ghp_another_sensitive_value" not in user_content
    assert "original value has been withheld" in user_content


def test_groq_requires_api_key_without_injected_client(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        GroqTriageProvider()


def test_groq_normalizes_string_evidence_and_limitations():
    finding = make_finding()
    payload = make_payload(finding)

    payload["evidence"] = "Scanner flagged app.py at line 10."
    payload["limitations"] = "The full call path was not verified."

    provider = GroqTriageProvider(client=make_client(json.dumps(payload)))

    result = provider.triage(finding=finding)

    assert result.evidence == ["Scanner flagged app.py at line 10."]
    assert result.limitations == ["The full call path was not verified."]


def test_groq_removes_blank_list_entries():
    finding = make_finding()
    payload = make_payload(finding)

    payload["evidence"] = [
        "",
        "   ",
        "Scanner flagged app.py at line 10.",
    ]
    payload["limitations"] = [""]

    provider = GroqTriageProvider(client=make_client(json.dumps(payload)))

    result = provider.triage(finding=finding)

    assert result.evidence == ["Scanner flagged app.py at line 10."]
    assert result.limitations == []
