import json
import os
import sys
from pathlib import Path

import pytest

from silentsec.scanners import osv_runner
from silentsec.scanners.osv_runner import (
    find_dependency_files,
    parse_osv_report,
    run_osv_scanner,
)
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.schemas import FindingCategory, Severity

REQUIREMENTS = "flask==2.0.0\n# web\nJinja2==2.4.1\nrequests==2.31.0\n"


def report(root: Path) -> dict:
    """An OSV-Scanner v2 JSON report: one package with two advisories in one group."""
    return {
        "results": [
            {
                "source": {"path": str(root / "requirements.txt"), "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "jinja2", "version": "2.4.1", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "PYSEC-2014-8",
                                "summary": "Jinja2 sandbox escape",
                                "aliases": ["CVE-2014-1402"],
                                "affected": [
                                    {
                                        "package": {"name": "jinja2", "ecosystem": "PyPI"},
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [{"introduced": "0"}, {"fixed": "2.7.2"}],
                                            }
                                        ],
                                    }
                                ],
                            },
                            {
                                "id": "GHSA-xxxx-yyyy-zzzz",
                                "summary": "Jinja2 sandbox escape via format",
                                "aliases": ["CVE-2014-1402"],
                                "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1336"]},
                                "affected": [
                                    {
                                        "package": {"name": "Jinja2", "ecosystem": "PyPI"},
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "2.10.1"},
                                                    {"fixed": "2.7.2"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            },
                        ],
                        "groups": [
                            {
                                "ids": ["PYSEC-2014-8", "GHSA-xxxx-yyyy-zzzz"],
                                "aliases": ["CVE-2014-1402"],
                                "max_severity": "7.5",
                            }
                        ],
                    },
                    {
                        "package": {"name": "flask", "version": "2.0.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Session cookie issue."}
                        ],
                        "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "max_severity": ""}],
                    },
                ],
            }
        ]
    }


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    return tmp_path


def test_one_finding_per_package(project: Path):
    findings, errors = parse_osv_report(report(project), project)

    assert errors == []
    assert [finding.rule_id for finding in findings] == [
        "vulnerable-dependency",
        "vulnerable-dependency",
    ]
    assert [finding.advisory_ids for finding in findings] == [
        ["GHSA-xxxx-yyyy-zzzz"],
        ["GHSA-aaaa-bbbb-cccc"],
    ]
    jinja = findings[0]
    assert jinja.tool == "osv-scanner"
    assert jinja.file_path == "requirements.txt"
    assert jinja.start_line == 3  # the line that declares Jinja2 (case-insensitive)
    assert jinja.severity == Severity.HIGH  # CVSS 7.5
    assert jinja.category == FindingCategory.SECURITY
    assert jinja.cwe_id == "CWE-1336"
    assert "jinja2 2.4.1 (PyPI)" in jinja.message
    assert "Upgrade to 2.7.2 or later." in jinja.message
    assert "1 known vulnerability, highest HIGH: GHSA-xxxx-yyyy-zzzz" in jinja.message


def test_missing_cvss_falls_back_to_medium_and_no_fixed_version(project: Path):
    findings, _ = parse_osv_report(report(project), project)

    flask = findings[1]
    assert flask.start_line == 1
    assert flask.severity == Severity.MEDIUM
    assert "No fixed version is listed yet." in flask.message


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        ("9.8", Severity.CRITICAL),
        ("7.0", Severity.HIGH),
        ("5.3", Severity.MEDIUM),
        ("2.1", Severity.LOW),
    ],
)
def test_cvss_scores_map_to_severity(project: Path, score: str, severity: Severity):
    data = report(project)
    data["results"][0]["packages"][0]["groups"][0]["max_severity"] = score

    findings, _ = parse_osv_report(data, project)

    assert findings[0].severity == severity


def test_withdrawn_advisories_are_ignored(project: Path):
    data = report(project)
    for vulnerability in data["results"][0]["packages"][1]["vulnerabilities"]:
        vulnerability["withdrawn"] = "2024-01-01T00:00:00Z"

    findings, _ = parse_osv_report(data, project)

    assert [finding.advisory_ids for finding in findings] == [["GHSA-xxxx-yyyy-zzzz"]]


def test_fingerprints_differ_per_package_on_the_same_line(project: Path):
    data = report(project)
    data["results"][0]["packages"][1]["package"]["name"] = "unknown-pkg"  # both on line 1
    data["results"][0]["packages"][0]["package"]["name"] = "also-unknown"

    findings, _ = parse_osv_report(data, project)

    assert len({finding.fingerprint for finding in findings}) == 2


def test_empty_report_has_no_findings(project: Path):
    assert parse_osv_report({"results": []}, project) == ([], [])
    assert parse_osv_report({}, project) == ([], [])


def test_dependency_files_are_found_outside_virtualenvs(tmp_path: Path):
    (tmp_path / "requirements-dev.txt").write_text("pytest\n", encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text("{}", encoding="utf-8")
    for skipped in (".venv", "node_modules"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "requirements.txt").write_text("x\n", encoding="utf-8")

    found = [path.relative_to(tmp_path).as_posix() for path in find_dependency_files(tmp_path)]

    assert found == ["requirements-dev.txt", "web/package-lock.json"]


def test_not_installed_is_skipped(project: Path, monkeypatch):
    monkeypatch.setattr(osv_runner.shutil, "which", lambda name: None)

    result = run_osv_scanner(project)

    assert result.status == ScannerStatus.SKIPPED
    assert result.errors[0].startswith("Informational: osv-scanner is not installed")


def test_no_dependency_files_is_skipped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(osv_runner.shutil, "which", lambda name: "/usr/bin/osv-scanner")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = run_osv_scanner(tmp_path)

    assert result.status == ScannerStatus.SKIPPED
    assert "no dependency files" in result.errors[0]


def test_unreachable_database_fails_with_a_clear_message(project: Path, monkeypatch):
    monkeypatch.setattr(osv_runner.shutil, "which", lambda name: "/usr/bin/osv-scanner")
    monkeypatch.setattr(
        osv_runner,
        "run_json_command",
        lambda *args, **kwargs: ScannerRunResult(
            scanner="osv",
            status=ScannerStatus.FAILED,
            duration_seconds=1,
            errors=[
                "Scanner did not produce valid JSON.",
                'request failed: Post "https://api.osv.dev/v1/querybatch": Forbidden',
            ],
        ),
    )

    result = run_osv_scanner(project)

    assert result.status == ScannerStatus.FAILED
    expected = (
        "OSV-Scanner could not reach the OSV vulnerability database (api.osv.dev); "
        "dependency checks need network access."
    )
    assert result.errors == [expected]


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shebang script as a fake binary")
def test_end_to_end_with_a_fake_osv_scanner(project: Path, tmp_path_factory, monkeypatch):
    bin_dir = tmp_path_factory.mktemp("bin")
    fake = bin_dir / "osv-scanner"
    payload = json.dumps(report(project))
    fake.write_text(
        f"#!{sys.executable}\n"
        "import sys, pathlib\n"
        "pathlib.Path(sys.argv[0]).with_name('args.txt').write_text(' '.join(sys.argv[1:]))\n"
        f"print({payload!r})\n"
        "sys.exit(1)\n",  # 1 = vulnerabilities found
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    result = run_osv_scanner(project)

    assert result.status == ScannerStatus.SUCCESS, result.errors
    assert len(result.findings) == 2
    args = (bin_dir / "args.txt").read_text()
    assert args.startswith("scan source --format=json --recursive")
    assert args.endswith(" .")


def test_many_advisories_for_one_package_are_one_issue(project: Path):
    def advisory(number: int, cvss: str, fixed: str | None) -> tuple[dict, dict]:
        events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
        vulnerability = {
            "id": f"GHSA-{number:04d}-aaaa-bbbb",
            "summary": f"Problem {number}",
            "affected": [
                {
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": events}],
                }
            ],
        }
        return vulnerability, {"ids": [vulnerability["id"]], "max_severity": cvss}

    pairs = [
        advisory(1, "5.0", "1.0"),
        advisory(2, "7.5", "2.2.5"),
        advisory(3, "4.0", "0.12.3"),
        advisory(4, "6.1", None),
    ]
    data = {
        "results": [
            {
                "source": {"path": str(project / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": "flask", "version": "0.12.2", "ecosystem": "PyPI"},
                        "vulnerabilities": [v for v, _ in pairs],
                        "groups": [g for _, g in pairs],
                    }
                ],
            }
        ]
    }

    findings, _ = parse_osv_report(data, project)

    assert len(findings) == 1
    flask = findings[0]
    assert flask.severity == Severity.HIGH  # the highest advisory
    assert flask.advisory_ids[0] == "GHSA-0002-aaaa-bbbb"
    assert sorted(flask.advisory_ids) == [f"GHSA-{n:04d}-aaaa-bbbb" for n in range(1, 5)]
    assert "4 known vulnerabilities, highest HIGH" in flask.message
    assert "Upgrade to 2.2.5 or later. 1 advisory(ies) have no fixed version yet." in flask.message


def test_advisory_count_adds_a_capped_bump_to_the_score():
    from silentsec.schemas import Finding
    from silentsec.scoring import score_findings

    def dependency(count: int) -> Finding:
        return Finding(
            fingerprint=f"dep-{count}",
            tool="osv-scanner",
            rule_id="vulnerable-dependency",
            file_path="requirements.txt",
            start_line=1,
            category=FindingCategory.SECURITY,
            severity=Severity.HIGH,
            message="Dependency x",
            confidence=0.9,
            advisory_ids=[f"GHSA-{n}" for n in range(count)],
        )

    one, three, many = (
        score_findings([dependency(n)]).scored_findings[0] for n in (1, 3, 25)
    )
    assert one.score == pytest.approx(15 * 0.95)
    assert three.score == pytest.approx(15 * 0.95 * 1.2)
    assert many.score == pytest.approx(15 * 0.95 * 1.5)  # capped
    assert "25 advisories" in many.explanation
