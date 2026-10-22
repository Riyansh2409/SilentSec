
from pathlib import Path

from silentsec.scanners.common import (
    create_fingerprint,
    extract_cwe,
    normalize_confidence,
    normalize_file_path,
    normalize_severity,
)
from silentsec.schemas import Severity


def test_normalize_severity_handles_common_values():
    assert normalize_severity("critical") == Severity.CRITICAL
    assert normalize_severity("ERROR") == Severity.HIGH
    assert normalize_severity("warning") == Severity.MEDIUM
    assert normalize_severity("unknown") == Severity.MEDIUM


def test_normalize_confidence_handles_numeric_and_text_values():
    assert normalize_confidence(0.8) == 0.8
    assert normalize_confidence("HIGH") == 0.9
    assert normalize_confidence("medium") == 0.6
    assert normalize_confidence(2) is None
    assert normalize_confidence(True) is None


def test_extract_cwe_handles_supported_formats():
    assert extract_cwe(78) == "CWE-78"
    assert extract_cwe("95") == "CWE-95"
    assert extract_cwe("cwe-89") == "CWE-89"
    assert extract_cwe({"id": 22}) == "CWE-22"
    assert extract_cwe(["unknown", "CWE-79"]) == "CWE-79"
    assert extract_cwe(None) is None


def test_normalize_file_path_returns_repository_relative_path(tmp_path: Path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "src").mkdir()

    assert normalize_file_path(root, "src/app.py") == "src/app.py"
    assert normalize_file_path(root, "./src/app.py") == "src/app.py"
    assert normalize_file_path(root, f"{root.name}/src/app.py") == "src/app.py"


def test_normalize_file_path_normalizes_windows_separators(tmp_path: Path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "src").mkdir()

    assert normalize_file_path(root, r"src\app.py") == "src/app.py"


def test_create_fingerprint_is_deterministic():
    first = create_fingerprint("bandit", "B602", "src/app.py", 10)
    second = create_fingerprint("bandit", "B602", "src/app.py", 10)

    assert first == second
    assert len(first) == 64


def test_create_fingerprint_changes_when_location_changes():
    original = create_fingerprint("bandit", "B602", "src/app.py", 10)
    changed_line = create_fingerprint("bandit", "B602", "src/app.py", 11)
    changed_file = create_fingerprint("bandit", "B602", "src/other.py", 10)

    assert original != changed_line
    assert original != changed_file
