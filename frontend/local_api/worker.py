"""Run one request in a separate Python process, with no shell command input."""

import json
import os
import sys
import tempfile
from pathlib import Path

from .adapter import configure_backend, run


def execute(request, result_path, temporary):
    configure_backend(request["backend_path"])
    data_root = Path(request["data_root"])
    os.environ["TEMP"] = os.environ["TMP"] = str(temporary)
    tempfile.tempdir = str(temporary)
    os.environ["SILENTSEC_TRIAGE_CACHE_DIR"] = str(data_root / "triage-cache")
    # This local interface always uses the backend's bundled offline rules.
    os.environ.pop("SILENTSEC_SEMGREP_CONFIG", None)
    os.environ["SEMGREP_SEND_METRICS"] = "off"
    os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    config_path = data_root / "config.json"
    config = (
        json.loads(config_path.read_text(encoding="utf-8-sig")) if config_path.is_file() else {}
    )
    if config.get("semgrep_local_files", True):
        os.environ["SEMGREP_LOG_FILE"] = str(data_root / "semgrep.log")
        os.environ["SEMGREP_SETTINGS_FILE"] = str(data_root / "semgrep-settings.yml")
    else:
        os.environ.pop("SEMGREP_LOG_FILE", None)
        os.environ.pop("SEMGREP_SETTINGS_FILE", None)
    return run(request["operation"], request.get("args", {}), result_path.parent, data_root)


def main():
    request_path, result_path = map(Path, sys.argv[1:3])
    request = json.loads(request_path.read_text(encoding="utf-8"))
    try:
        # Use the OS temporary root: deeply nested checkout paths can make
        # Semgrep's Windows runtime fail before producing its JSON output.
        with tempfile.TemporaryDirectory(
            prefix="silentsec-", ignore_cleanup_errors=True
        ) as temporary:
            data = execute(request, result_path, temporary)
        response = {"ok": True, "data": data}
    except Exception as exc:  # noqa: BLE001 - operation boundary preserves safe failure
        try:
            from silentsec.triage.sanitization import redact_sensitive_text

            detail = redact_sensitive_text(str(exc))[:1200]
        except Exception:  # noqa: BLE001 - preserve failure when backend import fails
            detail = "Install the backend dependencies with setup.ps1."
        response = {"ok": False, "error": f"{type(exc).__name__}: {detail}"}
    result_path.write_text(json.dumps(response, ensure_ascii=True), encoding="utf-8")
    return 0 if response["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
