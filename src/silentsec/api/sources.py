"""Turn API input (a GitHub link or an uploaded file) into a folder to scan.

Everything here handles untrusted input, so it is deliberately strict:

* Only public ``https://github.com/<owner>/<repo>`` links are accepted. No
  other hosts, protocols or local paths, so the API cannot be used to read
  files on this machine or reach internal services.
* ``git clone`` runs without a shell, without stored credentials (callers
  cannot make it fetch the server owner's private repositories), without
  prompts, submodules, LFS downloads or symlinks, and with a timeout.
* Uploads are size-limited. Zip archives are extracted entry by entry,
  refusing absolute paths, ``..``, symlinks and zip bombs. Any ``.git``
  folder inside an upload is dropped: Git configuration from an untrusted
  upload could run commands when a scanner calls ``git``.
* No uploaded or cloned code is ever executed; it is only read by scanners.
"""

import io
import re
import stat
import subprocess  # nosec B404
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from silentsec.process import run_bounded
from silentsec.remediation.sandbox import sanitized_environment

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)

CLONE_TIMEOUT_SECONDS = 120
MAX_REPOSITORY_BYTES = 200 * 1024 * 1024
MAX_REPOSITORY_FILES = 20_000

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5_000
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class SourceError(ValueError):
    """The input cannot be turned into a scannable folder; safe to show to the caller."""


@dataclass(frozen=True)
class PreparedSource:
    root: Path  # the folder to scan
    name: str  # what to call it in results ("owner/repo" or the file name)
    is_git: bool  # whether history can be read


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) for a public GitHub repository link."""
    match = GITHUB_URL_RE.match(url.strip())
    if match is None:
        raise SourceError(
            "Only GitHub repository links like https://github.com/owner/repo are supported."
        )
    owner, repo = match.group("owner"), match.group("repo")
    if repo in {".", ".."} or owner.endswith("-"):
        raise SourceError("That is not a valid GitHub repository link.")
    return owner, repo


def _clone_environment() -> dict[str, str]:
    environment = sanitized_environment()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",  # fail instead of asking for a password
            "GCM_INTERACTIVE": "never",  # no Git Credential Manager pop-up on Windows
            "GIT_LFS_SKIP_SMUDGE": "1",  # do not download large LFS files
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    return environment


def _check_size(root: Path) -> None:
    total = 0
    files = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        files += 1
        total += path.stat().st_size
        if files > MAX_REPOSITORY_FILES or total > MAX_REPOSITORY_BYTES:
            raise SourceError(
                f"The repository is too large to scan here (limit {MAX_REPOSITORY_FILES} files, "
                f"{MAX_REPOSITORY_BYTES // (1024 * 1024)} MB)."
            )


def clone_github(url: str, destination: Path, *, depth: int = 1) -> PreparedSource:
    """Clone a public GitHub repository into ``destination`` (which must not exist)."""
    owner, repo = parse_github_url(url)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    command = [
        "git",
        "-c",
        "credential.helper=",  # never use the server owner's stored credentials
        "-c",
        "core.symlinks=false",  # symlinks become plain text files
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "clone",
        "--quiet",
        f"--depth={max(1, depth)}",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        clone_url,
        str(destination),
    ]
    try:
        # Fixed argument list without a shell; the URL was validated above.
        completed = run_bounded(
            command, timeout=CLONE_TIMEOUT_SECONDS, env=_clone_environment()
        )
    except FileNotFoundError as exc:
        raise SourceError("Git is not installed on the server.") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"Cloning took longer than {CLONE_TIMEOUT_SECONDS} seconds.") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or "").lower()
        if "not found" in detail or "could not read username" in detail or "403" in detail:
            raise SourceError(
                f"Repository {owner}/{repo} was not found or is private. "
                "Only public repositories can be scanned by link."
            )
        raise SourceError(f"Could not clone {owner}/{repo}.")

    _check_size(destination)
    return PreparedSource(root=destination, name=f"{owner}/{repo}", is_git=True)


def safe_file_name(name: str) -> str:
    """A plain file name with no folders and only safe characters."""
    base = PurePosixPath(name.replace("\\", "/")).name
    cleaned = SAFE_NAME_RE.sub("_", base).lstrip(".")
    return cleaned[:100] or "upload"


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def _safe_member_path(name: str) -> PurePosixPath | None:
    """The relative path to extract a zip entry to, or None to skip it."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or not path.parts or ":" in path.parts[0]:
        raise SourceError("The zip file contains an absolute path and was rejected.")
    if ".." in path.parts:
        raise SourceError("The zip file contains a '..' path and was rejected.")
    if ".git" in path.parts or "__MACOSX" in path.parts:
        return None
    return path


def extract_upload(file_name: str, data: bytes, destination: Path) -> PreparedSource:
    """Write an uploaded source file, or the contents of a zip archive, into ``destination``."""
    if not data:
        raise SourceError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise SourceError(f"Uploads are limited to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")

    name = safe_file_name(file_name)
    destination.mkdir(parents=True, exist_ok=True)

    if not name.lower().endswith(".zip"):
        (destination / name).write_bytes(data)
        return PreparedSource(root=destination, name=name, is_git=False)

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SourceError("The uploaded file is not a valid zip archive.") from exc

    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise SourceError(f"The zip file has more than {MAX_ARCHIVE_ENTRIES} entries.")

        written = 0
        for info in entries:
            if info.is_dir() or _is_symlink(info):
                continue
            relative = _safe_member_path(info.filename)
            if relative is None:
                continue
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Count real bytes while copying: the sizes in the zip header can lie.
            with archive.open(info) as source, target.open("wb") as sink:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_EXTRACTED_BYTES:
                        raise SourceError(
                            "The zip file expands to more than "
                            f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB."
                        )
                    sink.write(chunk)

    children = [child for child in destination.iterdir()]
    if not children:
        raise SourceError("The zip file contains no files to scan.")
    # A zip of one folder ("project/...") is scanned from inside that folder.
    root = children[0] if len(children) == 1 and children[0].is_dir() else destination
    return PreparedSource(root=root, name=name.removesuffix(".zip"), is_git=False)
