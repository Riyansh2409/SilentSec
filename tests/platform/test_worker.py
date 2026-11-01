import io
import os
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from silentsec.platform import worker


def test_real_worker_does_not_execute_source_and_cleans_upload(platform, tmp_path):
    tools = Path(__file__).resolve().parents[2] / "frontend" / ".tools"
    scanner_path = os.pathsep.join(
        [str(Path(sys.executable).parent), str(tools), os.environ.get("PATH", "")]
    )
    if not all(shutil.which(name, path=scanner_path) for name in ("semgrep", "bandit")) or not (
        shutil.which("gitleaks", path=scanner_path) or (tools / "gitleaks.exe").is_file()
    ):
        pytest.skip("Real scanner integration requires installed scanner executables")
    _, factory, account, settings = platform
    client, _, _ = account("worker@example.test")
    marker = tmp_path / "repository-code-was-executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\nimport os\ndef shell(value):\n os.system(value)\n"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("app.py", source)
        zipped.writestr(".env", "API_KEY=ghp_abcdefghijklmnopqrstuv")
    response = client.post(
        "/api/v1/scan/upload",
        headers={"Idempotency-Key": "worker-scan-test"},
        files={"file": ("source.zip", archive.getvalue(), "application/zip")},
    )
    assert response.status_code == 202
    assert worker.tick(factory, settings)
    assert not marker.exists()
    assert list((settings.data_dir / "inbox").iterdir()) == []
    job_id = response.json()["id"]
    result = client.get("/api/v1/scans/" + job_id)
    assert result.json()["status"] == "succeeded", result.text
    findings = client.get("/api/v1/scans/" + job_id + "/findings")
    report = client.get("/api/v1/scans/" + job_id + "/report")
    assert "ghp_abcdefghijklmnopqrstuv" not in findings.text + report.text
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29


def test_missing_scanners_fail_before_execution(monkeypatch, tmp_path):
    import json
    import sys

    from silentsec.platform import runner

    request, result, started = (tmp_path / p for p in ("request.json", "result.json", "started"))
    request.write_text(json.dumps({"kind": "github", "reference": "https://github.com/owner/repo"}))
    monkeypatch.setattr(sys, "argv", ["runner", str(request), str(result), str(started)])
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    assert runner.main() == 2
    assert not started.exists()
    assert json.loads(result.read_text())["error_code"] == "scanner_unavailable"


def test_cancelled_upload_is_cleaned_by_maintenance(platform):
    from silentsec.platform.__main__ import maintenance

    _, factory, account, settings = platform
    client, _, _ = account("cleanup@example.test")
    response = client.post(
        "/api/v1/scan/upload",
        headers={"Idempotency-Key": "cleanup-upload"},
        files={"file": ("app.py", b"print('hello')", "text/plain")},
    )
    assert response.status_code == 202
    assert (
        client.post(
            "/api/v1/scans/" + response.json()["id"] + "/cancel",
            headers={"Idempotency-Key": "cleanup-cancel"},
        ).status_code
        == 200
    )
    maintenance(factory, settings)
    assert list((settings.data_dir / "inbox").iterdir()) == []
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_cleanup_handles_a_file_removed_by_another_worker(platform, monkeypatch):
    from silentsec.platform.__main__ import maintenance

    _, factory, _, settings = platform
    inbox = settings.data_dir / "inbox"
    inbox.mkdir()
    orphan = inbox / "orphan.payload"
    orphan.write_bytes(b"test-only")
    original_stat = Path.stat

    def disappearing_stat(path, *args, **kwargs):
        if path == orphan:
            orphan.unlink(missing_ok=True)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", disappearing_stat)
    maintenance(factory, settings)
    assert not orphan.exists()
