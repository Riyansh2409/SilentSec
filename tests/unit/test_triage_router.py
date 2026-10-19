import pytest

from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage.router import TriageRouter, TriageRoutingError
from silentsec.triage.schemas import TriagePriority, TriageResult


def make_finding() -> Finding:
    return Finding(
        fingerprint="router-test-fingerprint",
        tool="semgrep",
        rule_id="TEST001",
        file_path="app.py",
        start_line=5,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="Potential security issue",
    )


def make_result(finding: Finding) -> TriageResult:
    return TriageResult(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        priority=TriagePriority.HIGH,
        summary="Potential security risk",
        rationale="The scanner reported a possible issue.",
        remediation_steps=["Review the code and apply a safe fix."],
        requires_human_review=True,
    )


class FakeProvider:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = 0

    def triage(self, *, finding, context=""):
        self.calls += 1

        if isinstance(self.outcome, Exception):
            raise self.outcome

        return self.outcome


def test_router_returns_first_valid_result():
    finding = make_finding()
    result = make_result(finding)
    primary = FakeProvider(result)
    backup = FakeProvider(RuntimeError("Should not be called"))

    router = TriageRouter([
        ("primary", primary),
        ("backup", backup),
    ])

    assert router.triage(finding=finding) == result
    assert primary.calls == 1
    assert backup.calls == 0


def test_router_falls_back_after_timeout():
    finding = make_finding()
    backup_result = make_result(finding)
    primary = FakeProvider(TimeoutError("Provider timed out"))
    backup = FakeProvider(backup_result)

    router = TriageRouter([
        ("primary", primary),
        ("backup", backup),
    ])

    assert router.triage(finding=finding) == backup_result
    assert primary.calls == 1
    assert backup.calls == 1


def test_router_falls_back_after_server_error():
    finding = make_finding()
    backup_result = make_result(finding)

    class FakeServerError(Exception):
        code = 503

    primary = FakeProvider(FakeServerError("Service unavailable"))
    backup = FakeProvider(backup_result)

    router = TriageRouter([
        ("primary", primary),
        ("backup", backup),
    ])

    assert router.triage(finding=finding) == backup_result
    assert backup.calls == 1


def test_router_rejects_result_for_different_finding():
    finding = make_finding()
    wrong_finding = make_finding()

    primary = FakeProvider(make_result(wrong_finding))
    backup_result = make_result(finding)
    backup = FakeProvider(backup_result)

    router = TriageRouter([
        ("primary", primary),
        ("backup", backup),
    ])

    assert router.triage(finding=finding) == backup_result
    assert backup.calls == 1


def test_router_raises_when_all_providers_fail():
    finding = make_finding()

    router = TriageRouter([
        ("primary", FakeProvider(TimeoutError("Timed out"))),
        ("backup", FakeProvider(TimeoutError("Timed out"))),
    ])

    with pytest.raises(TriageRoutingError, match="All configured"):
        router.triage(finding=finding)


def test_router_requires_at_least_one_provider():
    with pytest.raises(ValueError, match="At least one"):
        TriageRouter([])