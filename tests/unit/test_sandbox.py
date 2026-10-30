import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from silentsec.remediation import sandbox
from silentsec.remediation.sandbox import apply_patch, create_isolated_copy, sanitized_environment

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

FIX_PATCH = """\
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 import os
-os.system(cmd)
+print("safe")
"""


def tree_digest(root: Path) -> str:
    """Hash every path and file content under root."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def make_repo(root: Path) -> Path:
    root.mkdir()
    (root / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    (root / "pkg").mkdir()
    (root / "pkg" / "util.py").write_text("x = 1\n", encoding="utf-8")
    for excluded in (".git", ".venv", "node_modules", "__pycache__"):
        (root / excluded).mkdir()
        (root / excluded / "file.txt").write_text("excluded\n", encoding="utf-8")
    (root / ".env").write_text("API_KEY=real-secret\n", encoding="utf-8")
    (root / ".env.local").write_text("API_KEY=real-secret\n", encoding="utf-8")
    (root / ".env.example").write_text("API_KEY=\n", encoding="utf-8")
    return root


def test_copy_contains_source_but_not_excluded_files(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")

    with create_isolated_copy(repo) as copy:
        copied = sorted(p.relative_to(copy.root).as_posix() for p in copy.root.rglob("*"))

    assert "app.py" in copied
    assert "pkg/util.py" in copied
    assert ".env.example" in copied
    for name in (".git", ".venv", "node_modules", "__pycache__", ".env", ".env.local"):
        assert name not in copied


def test_copy_lives_outside_the_repository(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")

    with create_isolated_copy(repo) as copy:
        assert not copy.root.is_relative_to(repo)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinks_are_never_copied(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")
    outside = tmp_path / "outside.txt"
    outside.write_text("private\n", encoding="utf-8")
    (repo / "link.txt").symlink_to(outside)
    (repo / "linked_dir").symlink_to(tmp_path)

    with create_isolated_copy(repo) as copy:
        assert not (copy.root / "link.txt").exists()
        assert not (copy.root / "linked_dir").exists()
        assert copy.skipped_symlinks == 2


def test_workspace_is_removed_after_use_and_on_error(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")

    with create_isolated_copy(repo) as copy:
        workspace = copy.workspace
        assert workspace.is_dir()
    assert not workspace.exists()

    with pytest.raises(RuntimeError), create_isolated_copy(repo) as copy:
        workspace = copy.workspace
        raise RuntimeError("boom")
    assert not workspace.exists()


def test_missing_repository_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        create_isolated_copy(tmp_path / "missing")


@requires_git
def test_patch_changes_copy_and_never_the_original(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")
    before = tree_digest(repo)

    with create_isolated_copy(repo) as copy:
        result = apply_patch(copy, FIX_PATCH)
        patched = (copy.root / "app.py").read_text(encoding="utf-8")

    assert result.ok, result.errors
    assert 'print("safe")' in patched
    assert tree_digest(repo) == before


@requires_git
def test_patch_that_does_not_apply_reports_error(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")
    stale = FIX_PATCH.replace("-os.system(cmd)", "-os.system(other)")

    with create_isolated_copy(repo) as copy:
        result = apply_patch(copy, stale)

    assert not result.ok
    assert "does not apply" in result.errors[0]


@requires_git
def test_crlf_patch_from_powershell_is_retried_with_lf(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")

    with create_isolated_copy(repo) as copy:
        result = apply_patch(copy, FIX_PATCH.replace("\n", "\r\n"))
        patched = (copy.root / "app.py").read_bytes()

    assert result.ok, result.errors
    assert result.line_endings_normalized
    assert b"\r\n" not in patched


@requires_git
def test_git_refuses_paths_outside_copy_even_if_validation_is_bypassed(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")
    escape = "--- a/../escape.py\n+++ b/../escape.py\n@@ -0,0 +1 @@\n+x = 1\n"

    with create_isolated_copy(repo) as copy:
        result = apply_patch(copy, escape)
        escaped = (copy.workspace / "escape.py").exists()

    assert not result.ok
    assert not escaped


def test_missing_git_is_reported(tmp_path: Path, monkeypatch):
    repo = make_repo(tmp_path / "repo")

    def no_git(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(sandbox.subprocess, "run", no_git)

    with create_isolated_copy(repo) as copy:
        result = apply_patch(copy, FIX_PATCH)

    assert not result.ok
    assert "Git was not found" in result.errors[0]


def test_git_runs_without_credentials_and_cannot_see_parent_repository(
    tmp_path: Path, monkeypatch
):
    repo = make_repo(tmp_path / "repo")
    seen: dict = {}

    def fake_run(command, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_example")
    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    with create_isolated_copy(repo) as copy:
        apply_patch(copy, FIX_PATCH)
        workspace = str(copy.workspace)

    assert "GITHUB_TOKEN" not in seen["env"]
    assert seen["env"]["GIT_CEILING_DIRECTORIES"] == workspace
    assert seen["shell"] is False


def test_sanitized_environment_removes_credentials():
    env = sanitized_environment(
        {
            "PATH": "/usr/bin",
            "HOME": "/home/dev",
            "GEMINI_API_KEY": "x",
            "GROQ_API_KEY": "x",
            "GITHUB_TOKEN": "x",
            "AWS_ACCESS_KEY_ID": "x",
            "AWS_REGION": "x",
            "DB_PASSWORD": "x",
            "my_secret": "x",
            "OPENAI_ORG": "x",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraheader",
            "GIT_CONFIG_VALUE_0": "AUTHORIZATION: bearer x",
        }
    )

    assert env == {"PATH": "/usr/bin", "HOME": "/home/dev"}
