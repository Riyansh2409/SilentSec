
from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.triage.sanitization import (
    prepare_context_for_triage,
    prepare_finding_for_triage,
    redact_sensitive_text,
)


def make_finding(
    category: FindingCategory = FindingCategory.SECURITY,
) -> Finding:
    return Finding(
        fingerprint="sanitization-test",
        tool="semgrep",
        rule_id="test.secret",
        file_path="src/app.py",
        start_line=1,
        end_line=1,
        category=category,
        severity=Severity.HIGH,
        message="Unsafe operation using api_key='test-secret-value'",
        confidence=0.9,
    )


def test_redacts_secret_assignments():
    text = (
        "api_key='alpha-secret' "
        "password='beta-secret' "
        "client_secret='gamma-secret'"
    )

    result = redact_sensitive_text(text)

    assert "alpha-secret" not in result
    assert "beta-secret" not in result
    assert "gamma-secret" not in result
    assert result.count("[REDACTED]") == 3


def test_redacts_bearer_tokens():
    result = redact_sensitive_text(
        "Authorization: Bearer abcdefghijklmnop"
    )

    assert "abcdefghijklmnop" not in result
    assert "Bearer [REDACTED]" in result


def test_redacts_private_key_blocks():
    text = (
        "-----BEGIN PRIVATE KEY-----\n"
        "private-key-material\n"
        "-----END PRIVATE KEY-----"
    )

    result = redact_sensitive_text(text)

    assert "private-key-material" not in result
    assert "[REDACTED PRIVATE KEY]" in result


def test_sanitizes_finding_without_mutating_original():
    finding = make_finding()

    safe_finding = prepare_finding_for_triage(finding)

    assert "test-secret-value" not in safe_finding.message
    assert "test-secret-value" in finding.message


def test_sanitizes_context_for_security_finding():
    finding = make_finding()

    result = prepare_context_for_triage(
        finding,
        "api_key='context-secret-value'",
    )

    assert "context-secret-value" not in result
    assert "[REDACTED]" in result


def test_withholds_context_for_secret_finding():
    finding = make_finding(FindingCategory.SECRET)

    result = prepare_context_for_triage(
        finding,
        "token='sensitive-token-value'",
    )

    assert "sensitive-token-value" not in result
    assert "withheld" in result.lower()


def test_redacts_environment_variable_credentials():
    text = (
        "AWS_SECRET_ACCESS_KEY=example_aws_secret_value "
        "DATABASE_URL=postgresql://app:db_password_value@localhost:5432/app"
    )

    result = redact_sensitive_text(text)

    assert "example_aws_secret_value" not in result
    assert "db_password_value" not in result
