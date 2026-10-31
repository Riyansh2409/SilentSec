import io
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

from silentsec.api import sources
from silentsec.api.sources import (
    PreparedSource,
    SourceError,
    extract_upload,
    parse_github_url,
    safe_file_name,
)
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings


def make_client(**kwargs):
    """A test client; the HTTP tests are skipped without the [api] extra."""
    testclient = pytest.importorskip("fastapi.testclient")
    pytest.importorskip("multipart")
    from silentsec.api.app import create_app

    return testclient.TestClient(create_app(**kwargs))


# --- GitHub links ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/Riyansh2409/SilentSec", ("Riyansh2409", "SilentSec")),
        ("https://github.com/owner/repo.git", ("owner", "repo")),
        ("https://github.com/owner/my.repo-1/", ("owner", "my.repo-1")),
        ("  https://github.com/owner/repo  ", ("owner", "repo")),
    ],
)
def test_github_links_are_parsed(url, expected):
    assert parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "/home/user/repo",
        "C:\\Users\\me\\repo",
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com.evil.com/owner/repo",
        "https://user:pass@github.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/../repo",
        "https://github.com/owner/..",
        "git@github.com:owner/repo.git",
        "https://github.com/owner/repo?x=--upload-pack=evil",
    ],
)
def test_other_links_are_rejected(url):
    with pytest.raises(SourceError):
        parse_github_url(url)


def test_clone_uses_a_safe_git_command(tmp_path: Path, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        Path(command[-1]).mkdir()
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setenv("GITHUB_TOKEN", "secret-value")
    monkeypatch.setattr(sources, "run_bounded", fake_run)

    prepared = sources.clone_github("https://github.com/owner/repo", tmp_path / "src", depth=5)

    command, kwargs = calls[0]
    assert prepared.name == "owner/repo" and prepared.is_git
    assert kwargs["timeout"] > 0
    assert "credential.helper=" in command
    assert "--depth=5" in command and "--no-recurse-submodules" in command
    assert command[-3:] == ["--", "https://github.com/owner/repo.git", str(tmp_path / "src")]
    assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert "GITHUB_TOKEN" not in kwargs["env"]


def test_missing_or_private_repository_has_a_clear_message(tmp_path: Path, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 128, "", "remote: Repository not found.")

    monkeypatch.setattr(sources, "run_bounded", fake_run)

    with pytest.raises(SourceError, match="not found or is private"):
        sources.clone_github("https://github.com/owner/repo", tmp_path / "src")


# --- uploads --------------------------------------------------------------------


def make_zip(entries: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, target)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("app.py", "app.py"),
        ("../../evil.py", "evil.py"),
        ("C:\\x\\a b.py", "a_b.py"),
        ("", "upload"),
    ],
)
def test_upload_file_names_are_made_safe(name, expected):
    assert safe_file_name(name) == expected


def test_single_file_upload(tmp_path: Path):
    prepared = extract_upload("../app.py", b"print(1)\n", tmp_path / "src")

    assert prepared.name == "app.py"
    assert (prepared.root / "app.py").read_bytes() == b"print(1)\n"
    assert not (tmp_path / "app.py").exists()


def test_zip_with_one_folder_is_scanned_from_inside_it(tmp_path: Path):
    data = make_zip({"project/app.py": b"x = 1\n", "project/lib/util.py": b"y = 2\n"})

    prepared = extract_upload("project.zip", data, tmp_path / "src")

    assert prepared.root == tmp_path / "src" / "project"
    assert (prepared.root / "lib" / "util.py").exists()
    assert prepared.name == "project" and not prepared.is_git


@pytest.mark.parametrize("bad_name", ["../escape.py", "/abs.py", "a/../../escape.py", "C:/x.py"])
def test_zip_paths_leaving_the_folder_are_rejected(tmp_path: Path, bad_name):
    data = make_zip({"ok.py": b"", bad_name: b"x"})

    with pytest.raises(SourceError):
        extract_upload("x.zip", data, tmp_path / "src")
    assert not (tmp_path / "escape.py").exists()


def test_zip_git_folders_and_symlinks_are_dropped(tmp_path: Path):
    data = make_zip(
        {"app.py": b"x = 1\n", ".git/config": b"[core]\nfsmonitor = evil\n", "sub/.git/HEAD": b"x"},
        symlinks={"link.py": "/etc/passwd"},
    )

    prepared = extract_upload("x.zip", data, tmp_path / "src")

    files = sorted(p.relative_to(prepared.root).as_posix() for p in prepared.root.rglob("*"))
    assert files == ["app.py"]


def test_zip_bomb_is_stopped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(sources, "MAX_EXTRACTED_BYTES", 1000)
    data = make_zip({"big.txt": b"0" * 5000})

    with pytest.raises(SourceError, match="expands to more than"):
        extract_upload("x.zip", data, tmp_path / "src")


@pytest.mark.parametrize(
    ("name", "data", "message"),
    [
        ("a.py", b"", "empty"),
        ("a.zip", b"not a zip", "not a valid zip"),
        ("a.zip", make_zip({}), "no files"),
    ],
)
def test_bad_uploads_have_clear_errors(tmp_path: Path, name, data, message):
    with pytest.raises(SourceError, match=message):
        extract_upload(name, data, tmp_path / "src")


# --- HTTP API -------------------------------------------------------------------


def fake_scan(root: Path, **kwargs) -> RepositoryScanResult:
    findings = [
        Finding(
            fingerprint=f"fp-{path.name}",
            tool="semgrep",
            rule_id="eval-exec",
            file_path=path.relative_to(root).as_posix(),
            start_line=1,
            category=FindingCategory.SECURITY,
            severity=Severity.HIGH,
            message="eval is called with user input",
            cwe_id="CWE-95",
            confidence=0.9,
        )
        for path in sorted(root.rglob("*.py"))
    ]
    return RepositoryScanResult(
        repo_path=str(root),
        languages=["Python"],
        status=ScannerStatus.SUCCESS,
        scanners=[
            ScannerRunResult(
                scanner="semgrep",
                status=ScannerStatus.SUCCESS,
                findings=findings,
                duration_seconds=0.1,
            )
        ],
        findings=findings,
        duration_seconds=0.1,
        security_debt=score_findings(findings),
        security_debt_complete=True,
    )


@pytest.fixture
def client():
    def fake_clone(url, destination, *, depth=1):
        sources.parse_github_url(url)
        destination.mkdir(parents=True)
        (destination / "app.py").write_text("eval(input())\n", encoding="utf-8")
        return PreparedSource(root=destination, name="owner/repo", is_git=False)

    return make_client(scan=fake_scan, clone=fake_clone)


def test_health(client):
    body = client.get("/api/health").json()

    assert body["status"] == "ok"
    assert set(body["tools"]) == {"git", "semgrep", "bandit", "gitleaks"}


def test_upload_scan_returns_summary_issues_and_report(client):
    response = client.post(
        "/api/scan/upload", files={"file": ("app.py", b"eval(input())\n", "text/x-python")}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == {"type": "upload", "name": "app.py", "url": None}
    assert body["summary"]["unique_issues"] == 1
    assert body["summary"]["security_risk"] in {"low", "moderate", "high", "critical"}
    issue = body["issues"][0]
    assert issue["file_path"] == "app.py" and issue["severity"] == "high"
    assert issue["sources"] == [{"tool": "semgrep", "rule_id": "eval-exec"}]
    assert "eval(input())" in issue["code"]
    assert body["timeline"] is None and "GitHub" in body["timeline_note"]

    report = client.get(body["report_url"])
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/html")
    assert "Content-Security-Policy" in report.text
    assert "silentsec-api-" not in report.text  # no server temp paths

    listed = client.get("/api/scans").json()
    assert listed[0]["id"] == body["id"]
    assert client.get(f"/api/scans/{body['id']}").json()["id"] == body["id"]


def test_github_scan(client):
    body = client.post(
        "/api/scan/github", json={"url": "https://github.com/owner/repo", "history_commits": 0}
    ).json()

    assert body["source"]["type"] == "github"
    assert body["source"]["name"] == "owner/repo"
    assert body["summary"]["unique_issues"] == 1


def test_invalid_github_link_is_a_400(client):
    response = client.post("/api/scan/github", json={"url": "file:///etc/passwd"})

    assert response.status_code == 400
    assert "github.com/owner/repo" in response.json()["detail"]


def test_request_validation(client):
    assert client.post("/api/scan/github", json={}).status_code == 422
    too_many = {"url": "https://github.com/o/r", "history_commits": 999}
    assert client.post("/api/scan/github", json=too_many).status_code == 422


def test_unknown_scan_is_a_404(client):
    assert client.get("/api/scans/nope").status_code == 404
    assert client.get("/api/scans/nope/report").status_code == 404


def test_temporary_folders_are_removed(client, tmp_path: Path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    client.post("/api/scan/upload", files={"file": ("app.py", b"x = 1\n", "text/plain")})

    assert list(tmp_path.iterdir()) == []


def test_cors_allows_only_configured_origins():
    app_client = make_client(scan=fake_scan, cors_origins=["http://localhost:5173"])

    allowed = app_client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    other = app_client.options(
        "/api/health",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in other.headers


# --- verify endpoints ---------------------------------------------------------------

PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-eval(input())\n+print(input())\n"


class FakeVerify:
    def __init__(self):
        self.calls = []

    def __call__(self, root, diff_text, **kwargs):
        from silentsec.remediation import FixVerdict, FixVerificationReport

        self.calls.append((root, diff_text, kwargs, sorted(p.name for p in root.iterdir())))
        return FixVerificationReport(
            verdict=FixVerdict.VERIFIED_FIX,
            reasons=["All 1 targeted finding(s) are resolved."],
            patch_files=["app.py"],
            score_before=12.0,
            score_after=0.0,
            checks_run=["semgrep (success)"],
            diff_text=diff_text,
            limitations=["Repository tests were not run (run_tests=False)."],
        )


@pytest.fixture
def verify_client():
    fake = FakeVerify()

    def fake_clone(url, destination, *, depth=1):
        sources.parse_github_url(url)
        destination.mkdir(parents=True)
        (destination / "app.py").write_text("eval(input())\n", encoding="utf-8")
        return PreparedSource(root=destination, name="owner/repo", is_git=True)

    return make_client(scan=fake_scan, clone=fake_clone, verify=fake), fake


def test_verify_upload_never_runs_repository_tests(verify_client):
    client, fake = verify_client

    response = client.post(
        "/api/verify/upload",
        files={
            "file": ("app.py", b"eval(input())\n", "text/x-python"),
            "patch": ("fix.diff", PATCH.encode(), "text/plain"),
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "verified_fix"
    assert body["score_before"] == 12.0 and body["score_after"] == 0.0
    assert body["source"] == {"type": "upload", "name": "app.py", "url": None}
    _root, diff_text, kwargs, files = fake.calls[0]
    assert diff_text == PATCH and files == ["app.py"]
    assert kwargs["run_tests"] is False
    assert "diff_text" not in body


@pytest.mark.parametrize(
    "data", [PATCH.encode("utf-16"), b"\xef\xbb\xbf" + PATCH.encode()], ids=["utf16", "bom"]
)
def test_verify_upload_accepts_windows_patch_encodings(verify_client, data):
    client, fake = verify_client

    response = client.post(
        "/api/verify/upload",
        files={"file": ("app.py", b"x\n", "text/plain"), "patch": ("fix.diff", data, "text/plain")},
    )

    assert response.status_code == 200
    assert fake.calls[0][1] == PATCH


def test_verify_github_passes_targets(verify_client):
    client, fake = verify_client

    body = client.post(
        "/api/verify/github",
        json={"url": "https://github.com/owner/repo", "patch": PATCH, "targets": ["fp1"]},
    ).json()

    assert body["verdict"] == "verified_fix"
    assert body["source"]["name"] == "owner/repo"
    assert fake.calls[0][2]["target_fingerprints"] == ["fp1"]
    assert fake.calls[0][2]["run_tests"] is False


def test_verify_rejects_bad_input(verify_client):
    client, fake = verify_client

    empty = client.post(
        "/api/verify/github", json={"url": "https://github.com/owner/repo", "patch": "  "}
    )
    bad_link = client.post("/api/verify/github", json={"url": "file:///etc", "patch": PATCH})
    not_text = client.post(
        "/api/verify/upload",
        files={"file": ("a.py", b"x", "text/plain"), "patch": ("p.diff", b"\xff\x00\xfe", "x")},
    )

    assert empty.status_code == 400 and "empty" in empty.json()["detail"]
    assert bad_link.status_code == 400
    assert not_text.status_code == 400
    assert fake.calls == []
