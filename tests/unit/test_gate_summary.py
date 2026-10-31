import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "gate_summary.py"
spec = importlib.util.spec_from_file_location("gate_summary", SCRIPT)
gate_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate_summary)


def report(**overrides) -> dict:
    data = {
        "verdict": "fail",
        "reasons": ["The change introduces 1 issue(s) at or above the policy threshold (high)."],
        "base_ref": "main",
        "head_ref": "HEAD",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "blocking": [
            {
                "severity": "high",
                "file_path": "app/db.py",
                "start_line": 21,
                "tool": "bandit",
                "rule_id": "B605",
            }
        ],
        "warnings": [],
        "other_new": [],
        "resolved": [],
        "scanner_problems": [],
    }
    data.update(overrides)
    return data


def test_summary_shows_verdict_and_tables():
    text = gate_summary.summary(report())

    assert text.startswith("## ❌ SilentSec gate: FAIL")
    assert "### Blocking: new findings (1)" in text
    assert "app/db.py:21" in text
    assert "evidence, not proof" in text


def test_repository_content_cannot_inject_markdown_or_html():
    evil = report(
        blocking=[
            {
                "severity": "high",
                "file_path": "x|<img src=x onerror=alert(1)>](http://evil)",
                "start_line": 1,
                "tool": "t",
                "rule_id": "r\n# heading",
            }
        ]
    )

    text = gate_summary.summary(evil)

    assert "<img" not in text
    assert "&lt;img" in text
    assert "\n# heading" not in text
    row = next(line for line in text.splitlines() if "onerror" in line)
    assert row.count("|") - row.count("\\|") == 4  # still exactly three columns


def test_main_reads_a_json_file(tmp_path: Path, capsys, monkeypatch):
    path = tmp_path / "gate.json"
    path.write_text(json.dumps(report(verdict="pass", blocking=[])), encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["gate_summary.py", str(path)])
    gate_summary.main()
    assert "✅ SilentSec gate: PASS" in capsys.readouterr().out
