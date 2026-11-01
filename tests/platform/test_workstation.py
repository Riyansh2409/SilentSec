import json
import uuid

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from sqlalchemy import select

from silentsec.platform import jobs, worker
from silentsec.platform.__main__ import maintenance
from silentsec.platform.models import (
    OperationQuota,
    OperationRequest,
    ScanJob,
    WorkstationRepository,
)


def registered(platform, tmp_path):
    _app, factory, account, settings = platform
    settings.workstation_enabled = True
    client, _, org = account("original-ui@example.test")
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("import os\ndef unsafe(value):\n    os.system(value)\n")
    with factory.begin() as db:
        db.add(
            WorkstationRepository(organization_id=org, root_path=str(root.resolve()), name="source")
        )
    return client, root, org


def submit(client, operation, args, key=None):
    return client.post(
        "/api/v1/workstation/jobs",
        json={"operation": operation, "args": args},
        headers={"Idempotency-Key": key or str(uuid.uuid4())},
    )


def test_original_routes_and_login_preserve_navigation(platform):
    _app, _, account, _ = platform
    client, _, _ = account("navigation@example.test")
    response = client.get("/app")
    assert response.status_code == 200
    for name in [
        "overview",
        "sources",
        "findings",
        "fixes",
        "gate",
        "history",
        "reports",
        "usage",
        "account",
    ]:
        assert f"#{name}" in response.text
    assert 'data-platform="true"' in response.text
    for asset in ["app.js", "api.js", "data.js", "debt-views.js", "account.js", "account.css"]:
        assert client.get("/original/" + asset).status_code == 200
    assert "nonce=" in client.get("/").text
    client.cookies.clear()
    assert client.get("/app", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/v1/workstation/jobs").status_code == 401


def test_registered_repositories_are_tenant_scoped(platform, tmp_path):
    client, root, _ = registered(platform, tmp_path)
    _, _, account, _ = platform
    other, _, _ = account("other-workspace@example.test")
    assert submit(other, "scan", {"repo_path": str(root)}).status_code == 403
    assert submit(client, "scan", {"repo_path": str(root.parent)}).status_code == 403
    assert (
        submit(
            client, "verify", {"repo_path": str(root), "patch": "diff", "run_tests": True}
        ).status_code
        == 400
    )
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_quoted_registered_path_is_accepted(platform, tmp_path):
    # Windows "Copy as path" wraps the folder in quotes; the registered root
    # must still match (other tenants and other folders stay refused).
    client, root, _ = registered(platform, tmp_path)
    response = submit(client, "scan", {"repo_path": f'"{root}"'}, "quoted-path-001")
    assert response.status_code == 202, response.text
    assert submit(client, "scan", {"repo_path": f'"{root.parent}"'}).status_code == 403


def test_original_scan_reservation_idempotency_cancel_and_idor(platform, tmp_path):
    client, root, _ = registered(platform, tmp_path)
    _, factory, account, settings = platform
    args = {"repo_path": str(root), "ai_triage": False}
    response = submit(client, "scan", args, "original-scan-001")
    assert response.status_code == 202, response.text
    id_ = response.json()["id"]
    assert submit(client, "scan", args, "original-scan-001").json()["id"] == id_
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29
    other, _, _ = account("idor@example.test")
    for suffix in ["", "/result", "/report", "/sarif"]:
        assert other.get("/api/v1/workstation/jobs/" + id_ + suffix).status_code == 404
    response = client.post(
        "/api/v1/scans/" + id_ + "/cancel", headers={"Idempotency-Key": "cancel-original-001"}
    )
    assert response.status_code == 200
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    maintenance(factory, settings)


def test_non_scan_operations_use_separate_units(platform, tmp_path):
    client, root, _ = registered(platform, tmp_path)
    _, factory, _, _ = platform
    response = submit(client, "gate", {"repo_path": str(root), "base": "main", "head": "HEAD"})
    assert response.status_code == 202, response.text
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    claim = jobs.claim(factory)
    assert jobs.mark_started(factory, *claim)
    jobs.finish(factory, *claim, error="fixture-failure-after-start")
    with factory() as db:
        quota = db.scalar(select(OperationQuota))
        assert quota.operation == "pr_gate" and quota.state == "committed"
        assert db.get(ScanJob, response.json()["id"]).reservation_id is None
    assert submit(client, "history", {"repo_path": str(root), "commits": 5}).status_code == 403


def test_expired_operation_reservations_cancel_before_execution(platform, tmp_path):
    from silentsec.platform.models import now

    client, root, _ = registered(platform, tmp_path)
    _, factory, _, settings = platform
    response = submit(client, "gate", {"repo_path": str(root)})
    with factory.begin() as db:
        quota = db.scalar(select(OperationQuota))
        quota.expires_at = now() - 1
    maintenance(factory, settings)
    assert not jobs.claim(factory)
    assert (
        client.get("/api/v1/workstation/jobs/" + response.json()["id"]).json()["status"]
        == "cancelled"
    )
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_original_transport_enforces_api_key_scopes(platform):
    _, _, account, _ = platform
    client, _, _ = account("key-scope@example.test")
    key = "ssec_12345678_" + "a" * 64
    registered_key = client.post(
        "/api/v1/api-keys",
        headers={"Idempotency-Key": "workstation-key-001"},
        json={"key": key, "scopes": ["scans:read"], "reason": "Local scope regression test"},
    )
    assert registered_key.status_code == 201
    headers = {"Authorization": "Bearer " + key}
    assert client.get("/api/v1/workstation/jobs", headers=headers).status_code == 200
    health = client.get("/api/v1/workstation/health", headers=headers)
    assert health.status_code == 200 and health.json()["platform"]["usage"] is None
    assert (
        client.post(
            "/api/v1/workstation/jobs",
            headers=headers,
            json={"operation": "github", "args": {"url": "https://github.com/example/repo"}},
        ).status_code
        == 403
    )


def test_concurrent_named_quota_reservations_are_atomic(platform):
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import HTTPException

    from silentsec.platform import billing
    from silentsec.platform.db import lock_org
    from silentsec.platform.models import Plan, uid
    from silentsec.platform.workstation import reserve_quotas

    _, factory, account, _ = platform
    _, user, org_id = account("named-concurrency@example.test")
    with factory.begin() as db:
        plan = db.get(Plan, "free")
        plan.entitlements = {**plan.entitlements, "monthly_verifications": 1}

    def reserve(index):
        try:
            with factory.begin() as db:
                org = lock_org(db, org_id)
                job = jobs.submit(
                    db,
                    org,
                    user,
                    "workstation",
                    "private",
                    "fixture",
                    f"named-{index}",
                    str(index),
                    uid(),
                    standard=False,
                )
                db.flush()
                reserve_quotas(db, org, job, {"verification": 1}, billing.entitlements(db, org_id))
            return True
        except HTTPException as exc:
            assert exc.status_code == 403
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(reserve, range(8))) == 1


def test_validation_does_not_charge_and_uploads_are_private(platform):
    _, factory, account, settings = platform
    client, _, _ = account("uploads@example.test")
    assert submit(client, "github", {"url": "https://evil.test/repository"}).status_code == 400
    response = client.post(
        "/api/v1/workstation/upload",
        headers={"Idempotency-Key": "original-upload-001"},
        files={"file": ("app.py", b"import os\nos.system('echo example')")},
        data={"metadata": json.dumps({"operation": "upload", "args": {}})},
    )
    assert response.status_code == 202, response.text
    with factory() as db:
        op = db.get(OperationRequest, response.json()["id"])
        assert "content" not in op.arguments and op.input_ref
    client.post(
        "/api/v1/scans/" + response.json()["id"] + "/cancel",
        headers={"Idempotency-Key": "cancel-upload-001"},
    )
    maintenance(factory, settings)
    assert not list((settings.data_dir / "inbox").glob("*.payload"))
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_real_original_scan_keeps_core_result_and_exports(platform, tmp_path):
    import shutil

    if not all(
        shutil.which(tool, path=worker.scanner_path()) for tool in ["semgrep", "bandit", "gitleaks"]
    ):
        pytest.skip("Native scanners not installed")
    client, root, _ = registered(platform, tmp_path)
    _, factory, _, settings = platform
    marker = tmp_path / "executed"
    (root / "never_execute.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
    )
    (root / ".env").write_text("API_KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890")
    response = submit(client, "scan", {"repo_path": str(root), "ai_triage": False, "timeout": 60})
    assert response.status_code == 202, response.text
    assert worker.tick(factory, settings)
    job = client.get("/api/v1/workstation/jobs/" + response.json()["id"]).json()
    assert job["status"] == "succeeded", job
    assert not marker.exists()
    path = "/api/v1/workstation/jobs/" + job["id"]
    result = client.get(path + "/result")
    assert "security_debt" in result.json() and "scanners" in result.json()
    for suffix in ["/report", "/sarif"]:
        exported = client.get(path + suffix)
        assert exported.status_code == 200, exported.text
        assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in exported.text
    assert client.get("/api/v1/scans/" + job["id"] + "/architecture-graph").status_code == 200
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29


def test_real_history_gate_verification_reports_and_native_upload(platform, tmp_path):
    import base64
    import shutil
    import subprocess

    from silentsec.platform.models import Subscription

    if not all(
        shutil.which(tool, path=worker.scanner_path())
        for tool in ["semgrep", "bandit", "gitleaks", "git"]
    ):
        pytest.skip("Native scanners not installed")
    client, root, org = registered(platform, tmp_path)
    _, factory, _, settings = platform
    with factory.begin() as db:
        db.scalar(select(Subscription).where(Subscription.organization_id == org)).plan_key = "pro"

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True, capture_output=True
        ).stdout.decode()

    git("init", "-b", "main")
    git("config", "user.name", "SilentSec fixture")
    git("config", "user.email", "fixture@example.test")
    git("add", "app.py")
    git("commit", "-m", "baseline")
    git("checkout", "-b", "change")
    (root / "README.md").write_text("Fixture only\n")
    git("add", "README.md")
    git("commit", "-m", "documentation")
    patch = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n import os\n def unsafe(value):\n-    os.system(value)\n+    print(value)\n"
    original = (root / "app.py").read_bytes()
    for operation, options in [
        ("history", {"repo_path": str(root), "commits": 2}),
        ("gate", {"repo_path": str(root), "base": "main", "head": "HEAD"}),
        ("verify", {"repo_path": str(root), "patch": patch, "run_tests": False}),
        ("report", {"repo_path": str(root), "include_history": True, "commits": 2}),
        ("upload", {"filename": "app.py", "content": base64.b64encode(original).decode()}),
        (
            "verify_upload",
            {"filename": "app.py", "content": base64.b64encode(original).decode(), "patch": patch},
        ),
    ]:
        response = submit(client, operation, options)
        assert response.status_code == 202, (operation, response.text)
        assert worker.tick(factory, settings)
        path = "/api/v1/workstation/jobs/" + response.json()["id"]
        job = client.get(path).json()
        assert job["status"] == "succeeded", (operation, job)
        result = client.get(path + "/result")
        assert result.status_code == 200 and result.json(), (operation, result.text)
        if operation in {"report", "upload"}:
            assert client.get(path + "/report").status_code == 200
        if operation == "upload":
            assert result.json()["raw_scan"]["security_debt"]
        assert (root / "app.py").read_bytes() == original
    assert not list((settings.data_dir / "inbox").glob("*.payload"))
