
from pathlib import Path

import pytest

from silentsec.scanners.gitleaks_runner import parse_gitleaks_payload
from silentsec.schemas import FindingCategory, Severity


def test_parses_gitleaks_finding_without_exposing_secret(tmp_path: Path):
    secret_value = "example-sensitive-token-123456"

    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API key detected",
            "File": "app/config.py",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": secret_value,
            "Match": f"API_KEY={secret_value}",
            "Fingerprint": "example-fingerprint",
        }
    ]

    findings, errors = parse_gitleaks_payload(payload, tmp_path)

    assert errors == []
    assert len(findings) == 1

    finding = findings[0]

    assert finding.tool == "gitleaks"
    assert finding.rule_id == "generic-api-key"
    assert finding.file_path == "app/config.py"
    assert finding.start_line == 12
    assert finding.category == FindingCategory.SECRET
    assert finding.severity == Severity.HIGH
    assert secret_value not in finding.message
    assert secret_value not in finding.model_dump_json()


def test_skips_invalid_gitleaks_records(tmp_path: Path):
    payload = [
        {
            "RuleID": "missing-path",
            "StartLine": 5,
        }
    ]

    findings, errors = parse_gitleaks_payload(payload, tmp_path)

    assert findings == []
    assert errors


def test_rejects_invalid_report_structure(tmp_path: Path):
    with pytest.raises(TypeError):
        parse_gitleaks_payload({"results": []}, tmp_path)
