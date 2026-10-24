import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage.gemini_provider import GeminiTriageProvider


def make_finding() -> Finding:
    return Finding(
        fingerprint="test-fingerprint-123",
        tool="semgrep",
        rule_id="python.security.test-rule",
        file_path="app.py",
        start_line=10,
        end_line=10,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="Potential command injection",
    )


def make_payload(finding: Finding) -> dict:
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "priority": "high",
        "summary": "Potential command injection risk.",
        "rationale": (
            "The finding indicates that untrusted input may "
            "reach command execution."
        ),
        "remediation_steps": [
            "Avoid shell execution with untrusted input.",
            "Pass a fixed executable and separate arguments.",
        ],
        "evidence": ["Scanner flagged app.py at line 10."],
        "limitations": ["The complete call path was not analyzed."],
        "requires_human_review": True,
    }


def make_client(response_text: str) -> Mock:
    client = Mock()
    client.models.generate_content.return_value = SimpleNamespace(
        text=response_text
    )
    return client


def test_triage_returns_validated_result():
    finding = make_finding()
    client = make_client(json.dumps(make_payload(finding)))
    provider = GeminiTriageProvider(
        client=client,
        model="gemini-3.8-flash",
    )

    result = provider.triage(finding=finding)

    assert result.finding_id == finding.finding_id
    assert result.fingerprint == finding.fingerprint
    assert result.priority.value == "high"
    assert result.requires_human_review is True


def test_triage_sends_model_and_context():
    finding = make_finding()
    client = make_client(json.dumps(make_payload(finding)))
    provider = GeminiTriageProvider(
        client=client,
        model="gemini-test-model",
    )

    provider.triage(
        finding=finding,
        context="The function receives HTTP request input.",
    )

    call = client.models.generate_content.call_args
    assert call.kwargs["model"] == "gemini-test-model"
    assert "HTTP request input" in call.kwargs["contents"]
    assert (
        call.kwargs["config"].response_mime_type
        == "application/json"
    )


def test_triage_rejects_invalid_json():
    finding = make_finding()
    provider = GeminiTriageProvider(client=make_client("{invalid"))

    with pytest.raises(ValueError, match="invalid JSON"):
        provider.triage(finding=finding)


def test_triage_rejects_empty_response():
    finding = make_finding()
    provider = GeminiTriageProvider(client=make_client(""))

    with pytest.raises(ValueError, match="empty response"):
        provider.triage(finding=finding)


def test_triage_rejects_invalid_schema():
    finding = make_finding()
    payload = make_payload(finding)
    payload["remediation_steps"] = []

    provider = GeminiTriageProvider(
        client=make_client(json.dumps(payload))
    )

    with pytest.raises(ValidationError):
        provider.triage(finding=finding)


def test_provider_requires_api_key_without_injected_client(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        GeminiTriageProvider()


def test_triage_redacts_credentials_from_outgoing_request():
    finding = make_finding()
    finding.message = "Unsafe request with api_key='finding-secret-value'"

    client = make_client(json.dumps(make_payload(finding)))
    provider = GeminiTriageProvider(client=client)

    provider.triage(
        finding=finding,
        context="Authorization: Bearer contextsecretvalue123",
    )

    prompt = client.models.generate_content.call_args.kwargs["contents"]

    assert "finding-secret-value" not in prompt
    assert "contextsecretvalue123" not in prompt
    assert "[REDACTED]" in prompt
    assert "untrusted data" in prompt

def test_triage_withholds_secret_finding_from_outgoing_request():
    finding = make_finding()
    finding.category = FindingCategory.SECRET
    finding.message = "Leaked token: ghp_example_sensitive_value"

    client = make_client(json.dumps(make_payload(finding)))
    provider = GeminiTriageProvider(client=client)

    provider.triage(
        finding=finding,
        context="Token value: ghp_another_sensitive_value",
    )

    prompt = client.models.generate_content.call_args.kwargs["contents"]

    assert "ghp_example_sensitive_value" not in prompt
    assert "ghp_another_sensitive_value" not in prompt
    assert "original value has been withheld" in prompt
    assert "Context withheld because this is a secret finding." in prompt
