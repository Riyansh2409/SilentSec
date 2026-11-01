"""Run the existing frontend adapter in the platform's bounded child process."""

import html
import json
import os
import sys
from html.parser import HTMLParser
from pathlib import Path

from .analysis import safe_text
from .runner import scan_payload, scanners_ready


class SafeReport(HTMLParser):
    """Keep the offline template while redacting source-derived text nodes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output, self.trusted = [], None

    def handle_starttag(self, tag, attrs):
        if tag in {"style", "script"}:
            self.trusted = tag
        self.output.append(
            "<"
            + tag
            + "".join(
                " "
                + name
                + (
                    '="'
                    + html.escape(
                        value if name in {"class", "id", "type"} else safe_text(value), quote=True
                    )
                    + '"'
                    if value is not None
                    else ""
                )
                for name, value in attrs
            )
            + ">"
        )

    def handle_endtag(self, tag):
        self.output.append("</" + tag + ">")
        if tag == self.trusted:
            self.trusted = None

    def handle_data(self, data):
        self.output.append(data if self.trusted else html.escape(safe_text(data)))

    def handle_decl(self, decl):
        self.output.append("<!" + decl + ">")


def sanitize(value, key=""):
    if key in {"code", "snippet", "context", "raw_output", "stdout", "stderr"}:
        return "Source content withheld; review the recorded location in your checkout."
    if isinstance(value, dict):
        secret = value.get("category") == "secret"
        return {
            k: (
                "Potential secret; value withheld."
                if secret and k in {"message", "title", "evidence"}
                else sanitize(v, k)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(v, key) for v in value]
    if isinstance(value, str):
        # Stable machine identifiers must survive transport unchanged.
        if key in {
            "fingerprint",
            "id",
            "analysis_version",
            "sha",
            "commit_sha",
            "base_sha",
            "head_sha",
        }:
            return value
        return safe_text(value)
    return value


def main():
    from .workstation import adapter_modules

    adapter, _ = adapter_modules()
    request_file, result_file, started_file = map(Path, sys.argv[1:4])
    request = json.loads(request_file.read_text(encoding="utf-8"))
    if not scanners_ready():
        result_file.write_text(json.dumps({"error_code": "scanner_unavailable"}))
        return 2
    args, operation, limits = request["args"], request["operation"], request["limits"]
    if args.get("run_tests"):
        raise ValueError("Repository code execution is forbidden")
    if args.get("repo_path"):
        from silentsec.api.sources import _check_size

        _check_size(Path(args["repo_path"]))
    workspace = request_file.parent
    os.environ["SEMGREP_SETTINGS_FILE"] = str(workspace / "semgrep.yml")
    os.environ["SEMGREP_LOG_FILE"] = str(workspace / "semgrep.log")
    os.environ["SEMGREP_SEND_METRICS"] = "off"
    os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    # The original report template stays intact; excerpts are never persisted
    # by the account service. These bindings exist only inside this subprocess.
    import silentsec.api.app as native
    import silentsec.report as reports

    native._snippets = reports._snippets = lambda *a, **kw: {}
    payload, raw = {}, {}

    def captured(root, scan):
        if not payload:
            payload.update(scan_payload(Path(root), limits, request["name"], result=scan))
            raw.update(scan.model_dump(mode="json"))
            raw["repo_path"] = request["name"]

    for index, fix in enumerate(request.get("fixes", [])):
        path = workspace / f"fix-{index}.json"
        path.write_text(json.dumps(fix), encoding="utf-8")
        args.setdefault("fix_paths", []).append(str(path))
    result = adapter.run(
        operation,
        args,
        workspace,
        Path(request["cache"]),
        on_start=lambda: started_file.write_text("started"),
        on_scan=captured,
    )
    if operation == "scan" and not (workspace / "report.html").exists():
        from datetime import UTC, datetime

        from silentsec.report.html import render_report
        from silentsec.scanners.scanner_service import RepositoryScanResult

        (workspace / "report.html").write_text(
            render_report(
                RepositoryScanResult.model_validate(sanitize(result)),
                snippets={},
                repo_name=request["name"],
                generated_at=datetime.now(UTC),
            ),
            encoding="utf-8",
        )
    if operation in {"github", "upload"} and "summary" in payload:
        # Share native scan findings with the original Findings screen.
        result["raw_scan"] = raw
    report = workspace / "report.html"
    sarif = workspace / "silentsec.sarif"
    # HTML contains no snippets; recognized and high-entropy secrets are still
    # removed from remaining source-derived descriptions and remediation text.
    report_text = report.read_text(encoding="utf-8") if report.exists() else None
    if report_text:
        document = SafeReport()
        document.feed(report_text)
        report_text = "".join(document.output)
    payload["operation_result"] = {
        "payload": sanitize(result),
        "contexts": {},
        "sarif": sanitize(json.loads(sarif.read_text(encoding="utf-8")))
        if sarif.exists()
        else None,
        "report": report_text,
    }
    encoded = json.dumps(payload, ensure_ascii=True)
    if len(encoded.encode()) > 12 * 1024 * 1024:
        raise ValueError("Result limit exceeded")
    result_file.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
