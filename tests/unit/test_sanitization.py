
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


def test_python_expressions_are_not_redacted():
    # Regression: `token=path.startswith(...)` was shown as `token=[REDACTED]`.
    for code in (
        'token=path.startswith("ghp")',
        "secret = get_secret()",
        "token = self.token",
        'api_key = os.environ["API_KEY"]',
        'auth_token=request.headers.get("Authorization")',
        "github_token = settings.github_token",
        "token=path.startswith(x)",
        'password = request.form["p"]',
        'token=os.getenv("T")',
    ):
        assert redact_sensitive_text(code) == code, code


def test_bare_words_are_redacted_whatever_the_name_case():
    # Regression: lowercase name + bare word reached cloud LLMs unredacted.
    for text, value in (
        ("password=hunter2", "hunter2"),
        ("secret: s3cr3tValue", "s3cr3tValue"),
        ("passwd=admin", "admin"),
        ("password = password", "= password"),
        ("PASSWORD=admin", "admin"),
    ):
        result = redact_sensitive_text(text)
        assert value not in result, text
        assert "[REDACTED]" in result, text


def test_literal_secret_values_are_still_redacted():
    for text, value in (
        ('password="hunter2"', "hunter2"),
        ("api_key=f'abc{suffix}'", "abc{suffix}"),
        ("TOKEN=abc123def456ghi789jkl", "abc123def456ghi789jkl"),
        ("token=12345678", "12345678"),
        ("PASSWORD=pa$$word!", "pa$$word!"),
        ("AWS_SECRET_ACCESS_KEY=example_aws_secret_value", "example_aws_secret_value"),
        ("GROQ_API_KEY=gsk_abcdefghij1234567890", "gsk_abcdefghij1234567890"),
        ("DB_PASSWORD=hunter2!", "hunter2!"),
    ):
        result = redact_sensitive_text(text)
        assert value not in result, text
        assert "[REDACTED" in result, text


def test_known_prefixes_are_redacted_anywhere():
    text = "call(gsk_abcdefghijklmnopqrstuv123, AIzaSyA1234567890abcdefghij)"
    result = redact_sensitive_text(text)
    assert "gsk_" not in result
    assert "AIza" not in result
