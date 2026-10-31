"""SQLite storage for per-commit scan results.

The database lives outside the scanned repository (by default under
~/.cache/silentsec/history), so history never writes into the user's repo.
A scan is reused only when the commit AND the analysis version match: the
analysis version changes whenever SilentSec or its bundled rules change.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from importlib import metadata
from pathlib import Path

from pydantic import BaseModel, Field

from silentsec.schemas import Finding

SCHEMA_VERSION = 1
_PACKAGE_DIR = Path(__file__).resolve().parent.parent
_RULES_DIR = _PACKAGE_DIR / "rules"


class StoredScan(BaseModel):
    """One commit's scan, as stored."""

    commit_sha: str
    committed_at: int  # Unix timestamp of the commit
    subject: str
    score: float
    raw_score: float
    security_points: float
    architecture_points: float
    unique_issues: int
    complete: bool
    scanner_statuses: dict[str, str] = Field(default_factory=dict)
    # Why a scanner did not succeed, e.g. "semgrep (partial): timed out".
    scanner_problems: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


def analysis_version() -> str:
    """Identify the SilentSec version and bundled rules a scan was made with."""
    try:
        package_version = metadata.version("silentsec")
    except metadata.PackageNotFoundError:
        package_version = "unknown"

    digest = sha256(f"schema={SCHEMA_VERSION};silentsec={package_version}".encode())
    # The bundled rules and the analysis code itself: a new analyzer rule or a
    # change in how findings are merged and scored must not reuse old scans,
    # even while the package version number stays the same during development.
    roots = [(_RULES_DIR, "*"), (_PACKAGE_DIR, "*.py")]
    for root, pattern in roots:
        for path in sorted(root.rglob(pattern)):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            digest.update(f"{root.name}/{path.relative_to(root).as_posix()}".encode())
            # Normalize line endings so a Windows checkout gives the same value.
            digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()[:16]


def default_database_path(repo_root: Path) -> Path:
    """One database per repository location, outside the repository."""
    repo_key = sha256(str(repo_root.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path.home() / ".cache" / "silentsec" / "history" / f"{repo_key}.db"


class HistoryStore:
    """Read and write per-commit scans."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    commit_sha TEXT NOT NULL,
                    analysis_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (commit_sha, analysis_version)
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def get(self, commit_sha: str, version: str) -> StoredScan | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM scans WHERE commit_sha = ? AND analysis_version = ?",
                (commit_sha, version),
            ).fetchone()
        if row is None:
            return None
        try:
            return StoredScan.model_validate(json.loads(row[0]))
        except ValueError:
            return None

    def put(self, scan: StoredScan, version: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO scans (commit_sha, analysis_version, payload) "
                "VALUES (?, ?, ?)",
                (scan.commit_sha, version, scan.model_dump_json()),
            )
