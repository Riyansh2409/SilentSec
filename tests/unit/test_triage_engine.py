import pytest

from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage import TriageEngine, TriagePriority, TriageResult


def make_finding() -> Finding:
    return Finding(
        fingerprint="fingerprint-123",
        tool="semgrep",
        rule_id="python.eval-detected",
        file_path="src/app.py",
        start_line=12,
        end_line=12,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="Potential unsafe evaluation of input.",
        confidence=0.9,
    )


def make_result(finding: Finding) -> TriageResult:
    return TriageResult(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        priority=TriagePriority.HIGH,
        summary="Potentially unsafe evaluation of input.",
        rationale=(
            "If untrusted input reaches this operation, it may be interpreted as executable code."
        ),
        remediation_steps=[
            "Avoid evaluating untrusted input.",
            "Use a safer parser and validate expected input types.",
        ],
        evidence=["The original scanner finding flags an evaluation operation."],
        limitations=["Exploitability has not been confirmed."],
        requires_human_review=True,
    )


class FakeTriageProvider:
    """Deterministic test provider that makes no external API calls."""

    def __init__(self, result: object) -> None:
        self.result = result
        self.received_finding: Finding | None = None
        self.received_context: str | None = None

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        self.received_finding = finding
        self.received_context = context
        return self.result  # type: ignore[return-value]


def test_engine_returns_valid_triage_result():
    finding = make_finding()
    expected = make_result(finding)
    provider = FakeTriageProvider(expected)

    result = TriageEngine(provider).triage_finding(finding)

    assert result == expected
    assert result.finding_id == finding.finding_id
    assert result.fingerprint == finding.fingerprint
    assert result.requires_human_review is True


def test_engine_passes_context_to_provider():
    finding = make_finding()
    provider = FakeTriageProvider(make_result(finding))
    context = "The project accepts user-uploaded expressions."

    TriageEngine(provider).triage_finding(finding, context=context)

    assert provider.received_finding == finding
    assert provider.received_context == context


def test_engine_rejects_mismatched_finding_id():
    finding = make_finding()
    result = make_result(finding).model_copy(update={"finding_id": "different-finding"})
    provider = FakeTriageProvider(result)

    with pytest.raises(ValueError, match="finding_id"):
        TriageEngine(provider).triage_finding(finding)


def test_engine_rejects_mismatched_fingerprint():
    finding = make_finding()
    result = make_result(finding).model_copy(update={"fingerprint": "different-fingerprint"})
    provider = FakeTriageProvider(result)

    with pytest.raises(ValueError, match="fingerprint"):
        TriageEngine(provider).triage_finding(finding)


def test_engine_rejects_triage_without_human_review():
    finding = make_finding()
    result = make_result(finding).model_copy(update={"requires_human_review": False})
    provider = FakeTriageProvider(result)

    with pytest.raises(ValueError, match="human review"):
        TriageEngine(provider).triage_finding(finding)


def test_engine_rejects_unvalidated_provider_output():
    provider = FakeTriageProvider({"priority": "high"})

    with pytest.raises(TypeError, match="TriageResult"):
        TriageEngine(provider).triage_finding(make_finding())
