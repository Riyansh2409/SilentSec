"""SSEC-ARCH-006: Radon maintainability index."""

from pathlib import Path

import pytest

from silentsec.architecture import analyzer
from silentsec.architecture.analyzer import run_architecture_analyzer
from silentsec.scanners.results import ScannerStatus
from silentsec.schemas import FindingCategory, Severity
from silentsec.scoring import score_findings

pytest.importorskip("radon")


def tangled_module(functions: int = 40) -> str:
    """A long module of branchy, uncommented functions: a low maintainability index."""
    body = []
    for index in range(functions):
        body.append(
            f"def handler_{index}(a, b, c, d):\n"
            f"    total = a * {index} + b - c / (d or 1)\n"
            "    for item in range(a):\n"
            "        if item % 2 and b > c or d < a:\n"
            "            total += item * b - c\n"
            "        elif item % 3 and c:\n"
            "            total -= item ** 2 + d\n"
            "        else:\n"
            "            total ^= item << 2\n"
            "    while total > 1000 and a:\n"
            "        total = total // 3 + a * b\n"
            "    return total if total > 0 else -total\n"
        )
    return "\n\n".join(body)


def arch_006(result):
    return [finding for finding in result.findings if finding.rule_id == "SSEC-ARCH-006"]


def test_hard_to_maintain_module_is_reported(tmp_path: Path):
    (tmp_path / "tangled.py").write_text(tangled_module(), encoding="utf-8")

    result = run_architecture_analyzer(tmp_path)

    [finding] = arch_006(result)
    assert finding.file_path == "tangled.py"
    assert finding.start_line == 1 and finding.end_line > 100
    assert finding.category == FindingCategory.MAINTAINABILITY
    assert finding.severity == Severity.LOW
    assert "maintainability index" in finding.message and "Radon rank C" in finding.message
    assert result.status == ScannerStatus.SUCCESS


def test_small_clean_module_is_not_reported(tmp_path: Path):
    (tmp_path / "clean.py").write_text(
        '"""Add numbers."""\n\n\ndef add(a, b):\n    """Return the sum."""\n    return a + b\n',
        encoding="utf-8",
    )

    assert arch_006(run_architecture_analyzer(tmp_path)) == []


def test_fingerprint_is_stable_across_edits_inside_the_module(tmp_path: Path):
    path = tmp_path / "tangled.py"
    path.write_text(tangled_module(40), encoding="utf-8")
    first = arch_006(run_architecture_analyzer(tmp_path))[0].fingerprint
    path.write_text(tangled_module(45), encoding="utf-8")

    assert arch_006(run_architecture_analyzer(tmp_path))[0].fingerprint == first


def test_missing_radon_is_informational(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(analyzer, "mi_visit", None)
    (tmp_path / "tangled.py").write_text(tangled_module(), encoding="utf-8")

    result = run_architecture_analyzer(tmp_path)

    assert arch_006(result) == []
    assert result.status == ScannerStatus.SUCCESS
    assert any(error.startswith("Informational: Radon") for error in result.errors)


def test_maintainability_counts_as_architecture_debt_with_high_effort(tmp_path: Path):
    (tmp_path / "tangled.py").write_text(tangled_module(), encoding="utf-8")

    report = score_findings(arch_006(run_architecture_analyzer(tmp_path)))

    assert report.architecture_debt_points > 0
    assert report.security_points == 0
    assert report.scored_findings[0].remediation_effort == "high"
