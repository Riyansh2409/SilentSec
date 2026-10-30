"""Isolated working copies for applying and checking a proposed patch.

The original repository is only ever read. Patches are applied to a copy in
a private temporary directory, which is removed afterwards.

This is file-level isolation, not a security sandbox: commands run in the
copy (git apply, optional repository tests) run as the current user, with
network access, but with credentials removed from their environment.
"""

import os
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from types import TracebackType
from typing import Self

from pydantic import BaseModel, Field

from silentsec.architecture.analyzer import EXCLUDED_DIRECTORIES as _ANALYZER_EXCLUDED

COPY_EXCLUDED_DIRECTORIES = frozenset(
    {*_ANALYZER_EXCLUDED, ".pytest_cache", ".ruff_cache"}
)
_KEPT_ENV_FILES = {".env.example", ".env.sample", ".env.template"}

# Environment variables removed before running anything in the copy.
_SECRET_NAME_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")
_SECRET_NAME_PREFIXES = (
    "GEMINI_",
    "GROQ_",
    "AWS_",
    "GITHUB_",
    "OPENAI_",
    "ANTHROPIC_",
    "AZURE_",
    "GOOGLE_",
)

GIT_TIMEOUT_SECONDS = 60


def sanitized_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """Copy the environment without variables that look like credentials."""
    source = dict(os.environ if base is None else base)
    return {
        name: value
        for name, value in source.items()
        if not any(marker in name.upper() for marker in _SECRET_NAME_MARKERS)
        and not name.upper().startswith(_SECRET_NAME_PREFIXES)
        # GIT_CONFIG_COUNT/KEY_n/VALUE_n only work as a set and can carry
        # auth headers, so drop them together rather than half of them.
        and not name.upper().startswith("GIT_CONFIG_")
    }


def _is_excluded_file(name: str) -> bool:
    if name in _KEPT_ENV_FILES:
        return False
    return name == ".env" or name.startswith(".env.")


class IsolatedCopy:
    """A temporary copy of a repository. Use as a context manager."""

    def __init__(self, workspace: Path, root: Path, skipped_symlinks: int) -> None:
        self.workspace = workspace
        self.root = root
        self.skipped_symlinks = skipped_symlinks

    def cleanup(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.cleanup()


def create_isolated_copy(repo_root: str | Path) -> IsolatedCopy:
    """Copy regular files of a repository into a new temporary directory.

    Skips VCS, virtual-environment, build and cache folders, local .env files,
    and every symlink, so nothing in the copy can point back outside it.
    """
    source = Path(repo_root).expanduser().resolve()
    if not source.is_dir():
        raise ValueError("Repository directory does not exist.")

    workspace = Path(tempfile.mkdtemp(prefix="silentsec-verify-"))
    destination = workspace / "repo"
    destination.mkdir()
    skipped_symlinks = 0

    try:
        for current, directories, filenames in os.walk(source, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for name in sorted(directories):
                if name in COPY_EXCLUDED_DIRECTORIES:
                    continue
                if (current_path / name).is_symlink():
                    skipped_symlinks += 1
                    continue
                kept.append(name)
            directories[:] = kept

            target_dir = destination / current_path.relative_to(source)
            target_dir.mkdir(parents=True, exist_ok=True)

            for name in sorted(filenames):
                file_path = current_path / name
                if file_path.is_symlink():
                    skipped_symlinks += 1
                    continue
                if _is_excluded_file(name) or not file_path.is_file():
                    continue
                shutil.copy2(file_path, target_dir / name)
    except BaseException:
        shutil.rmtree(workspace, ignore_errors=True)
        raise

    return IsolatedCopy(workspace, destination, skipped_symlinks)


class PatchApplyResult(BaseModel):
    """Outcome of applying a patch inside an isolated copy."""

    ok: bool
    errors: list[str] = Field(default_factory=list)
    line_endings_normalized: bool = False


def _run_git_apply(
    copy: IsolatedCopy,
    patch_file: Path,
    strip_level: int,
    *,
    check_only: bool,
) -> subprocess.CompletedProcess[str]:
    command = ["git", "apply", f"-p{strip_level}"]
    if check_only:
        command.append("--check")
    command.append(str(patch_file))

    environment = sanitized_environment()
    # Stop Git from treating a parent folder as the repository, so paths are
    # always resolved relative to the copy.
    environment["GIT_CEILING_DIRECTORIES"] = str(copy.workspace)

    # A fixed argument list without a shell; --unsafe-paths is never passed,
    # so Git refuses paths outside the copy as a second line of defence.
    return subprocess.run(  # nosec B603
        command,
        cwd=copy.root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
        shell=False,
        env=environment,
    )


def apply_patch(copy: IsolatedCopy, diff_text: str, *, strip_level: int = 1) -> PatchApplyResult:
    """Apply a validated diff to the copy with ``git apply``.

    If the patch fails and has Windows (CRLF) line endings, it is retried
    once with LF endings, because redirecting ``git diff`` output in
    PowerShell converts line endings.
    """
    attempts = [(diff_text, False)]
    if "\r\n" in diff_text:
        attempts.append((diff_text.replace("\r\n", "\n"), True))

    errors: list[str] = []

    for text, normalized in attempts:
        patch_file = copy.workspace / "proposed.patch"
        patch_file.write_bytes(text.encode("utf-8"))

        try:
            checked = _run_git_apply(copy, patch_file, strip_level, check_only=True)
            if checked.returncode != 0:
                errors.append(_git_error("Patch does not apply", checked))
                continue

            applied = _run_git_apply(copy, patch_file, strip_level, check_only=False)
            if applied.returncode != 0:
                errors.append(_git_error("Patch could not be applied", applied))
                continue
        except FileNotFoundError:
            return PatchApplyResult(
                ok=False,
                errors=["Git was not found. Install Git and make sure 'git' is on PATH."],
            )
        except subprocess.TimeoutExpired:
            return PatchApplyResult(
                ok=False,
                errors=[f"git apply timed out after {GIT_TIMEOUT_SECONDS} seconds."],
            )
        finally:
            patch_file.unlink(missing_ok=True)

        return PatchApplyResult(ok=True, line_endings_normalized=normalized)

    return PatchApplyResult(ok=False, errors=errors)


def _git_error(prefix: str, completed: subprocess.CompletedProcess[str]) -> str:
    detail = (completed.stderr or completed.stdout or "").strip()
    return f"{prefix}: {detail[-400:]}" if detail else f"{prefix}."
