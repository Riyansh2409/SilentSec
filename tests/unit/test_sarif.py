"""SARIF export, validated against the official SARIF 2.1.0 schema.

tests/schemas/sarif-schema-2.1.0.json is the OASIS schema from
https://github.com/oasis-tcs/sarif-spec (sarif-2.1/schema).
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.gate import GateFinding, GatePolicy, GateReport, GateVerdict
from silentsec.report.sarif import gate_to_sarif, scan_to_sarif
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)


def validate(document: dict) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(document, SCHEMA)


def finding(
    tool,
    rule,
    line,
    *,
    severity=Severity.HIGH,
    category=FindingCategory.SECURITY,
    cwe="CWE-78",
    path="app/db.py",
) -> Finding:
    return Finding(
        fingerprint=f"{tool}|{rule}|{path}|{line}",
        tool=tool,
        rule_id=rule,
        file_path=path,
        start_line=line,
        category=category,
        severity=severity,
        message=f"{rule} message",
        cwe_id=cwe,
        confidence=0.9,
    )


def scan_result(findings: list[Finding], *, complete: bool = True) -> RepositoryScanResult:
    status = ScannerStatus.SUCCESS if complete else ScannerStatus.FAILED
    return RepositoryScanResult(
        repo_path="/repo",
        status=status,
        scanners=[
            ScannerRunResult(
                scanner="semgrep",
                status=status,
                duration_seconds=1,
                errors=[] if complete else ["Scanner timed out after 180 seconds."],
            )
        ],
        findings=findings,
        duration_seconds=1,
        security_debt=score_findings(findings),
        security_debt_complete=complete,
    )


def test_scan_exports_one_result_per_unique_issue():
    findings = [
        # Bandit and Semgrep report the same os.system call: one issue.
        finding("bandit", "B605", 7),
        finding("semgrep", "os-system", 7),
        finding("gitleaks", "generic-api-key", 3, category=FindingCategory.SECRET, cwe=None),
        finding(
            "silentsec-arch",
            "SSEC-ARCH-005",
            12,
            severity=Severity.LOW,
            category=FindingCategory.MAINTAINABILITY,
            cwe=None,
        ),
    ]
    findings[0] = findings[0].model_copy(update={"message": "Starting a process with a shell"})
    findings[1] = findings[1].model_copy(update={"message": "os.system starts a shell process"})

    document = scan_to_sarif(scan_result(findings))

    validate(document)
    run = document["runs"][0]
    results = run["results"]
    assert len(results) == 3
    command = next(
        r for r in results if r["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    )
    assert command["level"] == "error"
    assert "Also reported by" in command["message"]["text"]
    assert command["partialFingerprints"]["silentsec/v1"]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules[command["ruleId"]]["properties"]["security-severity"] == "8.0"
    assert "external/cwe/cwe-78" in rules[command["ruleId"]]["properties"]["tags"]
    arch = next(r for r in results if r["ruleId"] == "silentsec-arch/SSEC-ARCH-005")
    assert arch["level"] == "note"
    assert "security-severity" not in rules["silentsec-arch/SSEC-ARCH-005"]["properties"]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_rule_tags_are_unique():
    document = scan_to_sarif(scan_result([finding("semgrep", "os-system", 7)]))

    tags = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert tags == ["security", "external/cwe/cwe-78"]


def test_incomplete_scan_is_marked_unsuccessful():
    document = scan_to_sarif(scan_result([], complete=False))

    validate(document)
    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert "timed out" in invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_paths_are_relative_with_forward_slashes():
    document = scan_to_sarif(scan_result([finding("bandit", "B605", 7, path=".\\app\\db.py")]))

    location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"}


def gate_report(verdict=GateVerdict.FAIL) -> GateReport:
    new = GateFinding(
        tool="bandit",
        rule_id="B605",
        file_path="app/db.py",
        start_line=21,
        severity=Severity.HIGH,
        category=FindingCategory.SECURITY,
        message="shell",
        fingerprint="fp-new",
    )
    warning = GateFinding(
        tool="silentsec-arch",
        rule_id="SSEC-ARCH-002",
        file_path="app/db.py",
        start_line=30,
        severity=Severity.MEDIUM,
        category=FindingCategory.ARCHITECTURE,
        message="swallowed",
    )
    resolved = new.model_copy(update={"rule_id": "B608", "start_line": 19})
    return GateReport(
        verdict=verdict,
        policy=GatePolicy(),
        base_ref="main",
        head_ref="HEAD",
        base_sha="a" * 40,
        head_sha="b" * 40,
        blocking=[new],
        warnings=[warning],
        resolved=[resolved],
    )


def test_gate_exports_only_new_findings():
    document = gate_to_sarif(gate_report())

    validate(document)
    results = document["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["bandit/B605", "silentsec-arch/SSEC-ARCH-002"]
    assert results[0]["partialFingerprints"]["silentsec/v1"] == "fp-new"
    assert results[1]["partialFingerprints"]["silentsec/v1"]  # computed when missing


def test_cli_writes_sarif_for_scan_and_gate(tmp_path: Path):
    scan_out = tmp_path / "scan.sarif"
    gate_out = tmp_path / "gate.sarif"

    with patch.object(
        cli, "scan_repository", return_value=scan_result([finding("bandit", "B605", 7)])
    ):
        cli.main(["scan", str(tmp_path), "--sarif", str(scan_out)])
    with patch.object(cli, "run_gate", return_value=gate_report()):
        cli.main(["gate", str(tmp_path), "--sarif", str(gate_out)])

    assert json.loads(scan_out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert len(json.loads(gate_out.read_text(encoding="utf-8"))["runs"][0]["results"]) == 2


def test_grouped_dependency_is_one_sarif_result_listing_all_advisories():
    from silentsec.scanners.osv_runner import parse_osv_report

    vulnerabilities = [{"id": f"GHSA-{n:04d}-x"} for n in range(3)]
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "flask", "version": "0.12.2", "ecosystem": "PyPI"},
                        "vulnerabilities": vulnerabilities,
                    }
                ],
            }
        ]
    }
    findings, _ = parse_osv_report(payload, Path("."))
    result = RepositoryScanResult(
        repo_path=".",
        status=ScannerStatus.SUCCESS,
        findings=findings,
        duration_seconds=0,
        security_debt=score_findings(findings),
        security_debt_complete=True,
    )

    document = scan_to_sarif(result)
    validate(document)
    results = document["runs"][0]["results"]
    assert len(results) == 1
    text = results[0]["message"]["text"]
    assert all(f"GHSA-{n:04d}-x" in text for n in range(3))
