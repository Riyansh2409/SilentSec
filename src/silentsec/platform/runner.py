"""Credential-free scan subprocess. Inputs are written by the trusted worker only."""

import html
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from silentsec.api.sources import clone_github, extract_upload
from silentsec.scanners.scanner_service import scan_repository

from .analysis import graph, patterns, safe_text


def highest_severities(findings):
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    result = {}
    for finding in findings:
        path, severity = finding["file_path"], finding["severity"]
        if path not in result or rank.get(severity, 0) > rank.get(result[path], 0):
            result[path] = severity
    return result


def scan_payload(root, limits, name, *, result=None):
    if result is None:
        result = scan_repository(
            root, timeout_seconds=limits["scan_timeout"], enable_ai_triage=False
        )
    debt = result.security_debt
    findings = []
    if debt:
        for item in debt.scored_findings[:5000]:
            f = item.finding
            findings.append(
                {
                    "fingerprint": f.fingerprint,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "title": "Potential secret; value and context withheld."
                    if f.category.value == "secret"
                    else safe_text(f.message),
                    "file_path": safe_text(f.file_path),
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "tool": f.tool,
                    "rule_id": safe_text(f.rule_id),
                    "points": item.score,
                    "exposure": item.exposure,
                    "exposure_path": [safe_text(p) for p in item.exposure_path],
                    "evidence": "Source snippets are withheld in the SaaS interface. Review the reported location in your own checkout.",
                }
            )
    summary = {
        "version": "1",
        "source_name": safe_text(name),
        "score": debt.score if debt else None,
        "raw_score": debt.raw_score if debt and hasattr(debt, "raw_score") else None,
        "complete": result.security_debt_complete,
        "issues": len(findings),
        "scanners": [
            {"name": s.scanner, "status": s.status.value, "findings": len(s.findings)}
            for s in result.scanners
        ],
        "duration_seconds": result.duration_seconds,
        "ai": {
            "requested": False,
            "reason": "Cloud AI is opt-in and not enabled for standard platform scans.",
        },
    }
    architecture = graph(root, detail=limits["graph_detail"])
    severities = highest_severities(findings)
    for node in architecture["nodes"]:
        node["severity"] = severities.get(node.get("file_path"))
    pattern_result = patterns(root, rules=limits.get("pattern_rules"))
    pattern_result["pack_version"] = limits.get("pattern_version", 0)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    policy = limits.get("policy") or {}
    threshold = policy.get("minimum_severity", "high")
    summary["policy"] = {
        "version": policy.get("version", 0),
        "minimum_severity": threshold,
        "matching_findings": sum(
            severity_order.get(f["severity"], 0) >= severity_order[threshold] for f in findings
        ),
        "complete": summary["complete"],
        "changes_score": False,
    }
    rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(f[k])) + "</td>"
            for k in ("severity", "title", "file_path", "start_line")
        )
        + "</tr>"
        for f in findings
    )
    report = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>SilentSec report</title><style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:1rem;background:#0b0b18;color:#eee}td,th{text-align:left;padding:12px;border-bottom:1px solid #444}h1{color:#8ce5ef}</style><h1>SilentSec scan report</h1><p>'
        + html.escape(safe_text(name))
        + "</p><p>Security debt: "
        + html.escape(str(summary["score"]))
        + "; higher means more debt. Coverage complete: "
        + str(summary["complete"])
        + "</p><p>Static observations are not proof of exploitability. Source snippets and secret values are withheld.</p><table><thead><tr><th>Severity</th><th>Finding</th><th>File</th><th>Line</th></tr></thead><tbody>"
        + rows
        + "</tbody></table></html>"
    )
    return {
        "summary": summary,
        "findings": findings,
        "graph": architecture,
        "patterns": pattern_result,
        "report": report,
        "analysis_version": "platform-v1",
    }


def main():
    request_file, result_file, started_file = map(Path, sys.argv[1:4])
    request = json.loads(request_file.read_text())
    if not scanners_ready():
        result_file.write_text(json.dumps({"error_code": "scanner_unavailable"}))
        return 2
    with tempfile.TemporaryDirectory(prefix="ssec-source-") as temp:
        workspace = Path(temp)
        os.environ["SEMGREP_SETTINGS_FILE"] = str(workspace / "semgrep.yml")
        os.environ["SEMGREP_LOG_FILE"] = str(workspace / "semgrep.log")
        os.environ["SEMGREP_SEND_METRICS"] = "off"
        os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        os.environ.pop("SILENTSEC_SEMGREP_CONFIG", None)
        if request["kind"] == "github":
            prepared = clone_github(request["reference"], workspace / "source")
        elif request["kind"] == "upload":
            prepared = extract_upload(
                request["name"], Path(request["reference"]).read_bytes(), workspace / "source"
            )
        else:
            raise ValueError("Unsupported source kind")
        started_file.write_text("started")
        payload = scan_payload(prepared.root, request["limits"], request["name"])
        encoded = json.dumps(payload, ensure_ascii=True)
        if len(encoded.encode()) > 12 * 1024 * 1024:
            raise ValueError("Result limit exceeded")
        result_file.write_text(encoded, encoding="utf-8")


def scanners_ready():
    return all(shutil.which(name) for name in ("semgrep", "bandit", "gitleaks"))


if __name__ == "__main__":
    raise SystemExit(main())
