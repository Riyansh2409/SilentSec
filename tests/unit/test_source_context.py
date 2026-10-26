
from pathlib import Path

from silentsec.context import build_source_context
from silentsec.schemas.finding import Finding, FindingCategory, Severity


def make_finding(
    file_path: str = "src/app.py",
    *,
    category: FindingCategory = FindingCategory.SECURITY,
    start_line: int = 2,
    end_line: int = 2,
) -> Finding:
    return Finding(
        fingerprint="context-test-fingerprint",
        tool="semgrep",
        rule_id="test.rule",
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        category=category,
        severity=Severity.HIGH,
        message="Potential security issue.",
        confidence=0.9,
    )


def test_extracts_numbered_source_context(tmp_path: Path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "first = 1\nsecond = 2\nthird = 3\n",
        encoding="utf-8",
    )

    context = build_source_context(
        tmp_path,
        make_finding(start_line=2),
    )

    assert "1: first = 1" in context
    assert "2: second = 2" in context
    assert "3: third = 3" in context


def test_redacts_secret_assignments(tmp_path: Path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        'api_key = "super-secret-value"\n',
        encoding="utf-8",
    )

    context = build_source_context(
        tmp_path,
        make_finding(start_line=1),
    )

    assert "super-secret-value" not in context
    assert "[REDACTED]" in context


def test_withholds_context_for_secret_finding(tmp_path: Path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        'token = "sensitive-value"\n',
        encoding="utf-8",
    )

    context = build_source_context(
        tmp_path,
        make_finding(category=FindingCategory.SECRET),
    )

    assert "sensitive-value" not in context
    assert "withheld" in context.lower()


def test_rejects_path_traversal(tmp_path: Path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("private_data = True\n", encoding="utf-8")

    context = build_source_context(
        tmp_path,
        make_finding("../outside.py"),
    )

    assert "outside the repository" in context
    assert "private_data" not in context


def test_handles_missing_file(tmp_path: Path):
    context = build_source_context(
        tmp_path,
        make_finding(),
    )

    assert "unavailable" in context.lower()


def test_enforces_file_size_limit(tmp_path: Path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("x = 123456789\n", encoding="utf-8")

    context = build_source_context(
        tmp_path,
        make_finding(),
        max_file_bytes=4,
    )

    assert "size limit" in context.lower()
    assert "123456789" not in context

def test_rejects_symlink_resolving_outside_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    outside = tmp_path / "outside.py"
    outside.write_text(
        "private_data = 'must not be exposed'\n",
        encoding="utf-8",
    )

    link = repo / "linked.py"

    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        import pytest

        pytest.skip("Symlink creation is not permitted on this system.")

    context = build_source_context(
        repo,
        make_finding("linked.py"),
    )

    assert "outside the repository" in context
    assert "must not be exposed" not in context


def test_handles_line_range_beyond_end_of_file(tmp_path: Path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "first = 1\nsecond = 2\n",
        encoding="utf-8",
    )

    context = build_source_context(
        tmp_path,
        make_finding(start_line=100, end_line=120),
    )

    assert "unavailable" in context.lower()
    assert "first = 1" not in context
    assert "second = 2" not in context
