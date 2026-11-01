import io
import zipfile

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from sqlalchemy import select

from silentsec.platform import jobs
from silentsec.platform.models import (
    EntitlementSnapshot,
    ScanJob,
    ScanResult,
    Subscription,
    now,
)


def zip_source(name="app.py", content="print('hello')"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


def test_upload_validation_refunds_and_never_executes(platform, tmp_path):
    _, _, account, _ = platform
    client, _, _ = account("upload@example.test")
    response = client.post(
        "/api/v1/scan/upload",
        headers={"Idempotency-Key": "unsafe-zip"},
        files={"file": ("bad.zip", zip_source("../outside.py"), "application/zip")},
    )
    assert response.status_code == 400
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    response = client.post(
        "/api/v1/scan/upload",
        headers={"Idempotency-Key": "safe-zip"},
        files={"file": ("safe.zip", zip_source(), "application/zip")},
    )
    assert response.status_code == 202
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29
    assert not (tmp_path / "outside.py").exists()


@pytest.mark.parametrize(
    "suffix", ["", "/findings", "/report", "/architecture-graph", "/patterns", "/cancel"]
)
def test_scan_idor_all_routes(platform, suffix):
    _, _, account, _ = platform
    first, _, _ = account("first@example.test")
    second, _, _ = account("second@example.test")
    job = first.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "private-job"},
        json={"url": "https://github.com/example/repo"},
    ).json()
    path = "/api/v1/scans/" + job["id"] + suffix
    result = (
        second.post(path, headers={"Idempotency-Key": "cancel-other"})
        if suffix == "/cancel"
        else second.get(path)
    )
    assert result.status_code == 404
    assert second.get("/api/v1/scans").json()["items"] == []


def test_claim_concurrency_and_snapshot_stability(platform):
    _, factory, account, _ = platform
    client, _, org_id = account("claims@example.test")
    for key in ("first-claim", "second-claim"):
        assert (
            client.post(
                "/api/v1/scan/github",
                headers={"Idempotency-Key": key},
                json={"url": "https://github.com/example/repo"},
            ).status_code
            == 202
        )
    first = jobs.claim(factory)
    assert first and jobs.claim(factory) is None
    with factory.begin() as db:
        db.scalar(
            select(Subscription).where(Subscription.organization_id == org_id)
        ).plan_key = "pro"
        snapshot = db.get(EntitlementSnapshot, db.get(ScanJob, first[0]).snapshot_id)
        assert snapshot.limits["concurrency"] == 1
    assert jobs.claim(factory) is None
    jobs.finish(factory, *first, error="before_execution")
    assert jobs.claim(factory)


def test_result_retention_and_reports_are_private(platform):
    _, factory, account, _ = platform
    client, _, _org_id = account("reports@example.test")
    job = client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "report-test"},
        json={"url": "https://github.com/example/repo"},
    ).json()
    claim = jobs.claim(factory)
    jobs.mark_started(factory, *claim)
    jobs.finish(
        factory,
        *claim,
        result={
            "summary": {"complete": True},
            "findings": [],
            "graph": {"nodes": [], "edges": []},
            "patterns": {},
            "report": "<!doctype html><html><p>safe report</p></html>",
            "analysis_version": "test",
        },
    )
    response = client.get("/api/v1/scans/" + job["id"] + "/report")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "sandbox" in response.headers["content-security-policy"]
    with factory.begin() as db:
        db.get(ScanResult, job["id"]).expires_at = now() - 1
    assert client.get("/api/v1/scans/" + job["id"] + "/report").status_code == 404


def test_lease_expiry_and_late_worker_cannot_overwrite(platform):
    _, factory, account, _ = platform
    client, _, _ = account("lease@example.test")
    client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "lease-job"},
        json={"url": "https://github.com/example/repo"},
    )
    claim = jobs.claim(factory)
    with factory.begin() as db:
        db.get(ScanJob, claim[0]).lease_expires_at = now() - 1
    jobs.recover(factory)
    assert jobs.finish(factory, *claim, result={}) is False
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_idempotency_input_mismatch_and_unsupported_source(platform):
    _, _, account, _ = platform
    client, _, _ = account("idempotent@example.test")
    headers = {"Idempotency-Key": "repeat-scan"}
    assert (
        client.post(
            "/api/v1/scan/github", headers=headers, json={"url": "https://github.com/example/one"}
        ).status_code
        == 202
    )
    assert (
        client.post(
            "/api/v1/scan/github", headers=headers, json={"url": "https://github.com/example/two"}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/v1/scan/github", headers=headers, json={"url": "file:///etc/passwd"}
        ).status_code
        == 400
    )
