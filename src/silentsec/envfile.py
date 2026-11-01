"""Load SilentSec settings from a local .env file without extra dependencies.

Only trusted locations are read: the file named by SILENTSEC_ENV_FILE, or the
.env in the SilentSec checkout (editable install). The current directory is
never read, because it is often the repository being scanned, which is
untrusted and could otherwise redirect AI calls (e.g. OLLAMA_HOST).

Variables that are already set are never overridden, empty values are
skipped, and values are never printed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ENV_FILE_VARIABLE = "SILENTSEC_ENV_FILE"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_BYTES = 64 * 1024


def checkout_env_file() -> Path | None:
    """The .env next to pyproject.toml when SilentSec runs from a source checkout."""
    root = Path(__file__).resolve().parents[2]
    if (root / "pyproject.toml").is_file() and (root / "src" / "silentsec").is_dir():
        return root / ".env"
    return None


def parse_env_text(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines; supports comments, `export`, and simple quoting."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _NAME.fullmatch(name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        values[name] = value
    return values


def load_env_file(path: Path | None = None) -> list[str]:
    """Set missing variables from the .env file. Returns the names (never values) set."""
    if path is None:
        explicit = os.environ.get(ENV_FILE_VARIABLE, "").strip()
        path = Path(explicit).expanduser() if explicit else checkout_env_file()
    if path is None:
        return []
    try:
        if not path.is_file() or path.stat().st_size > _MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []
    loaded = []
    for name, value in parse_env_text(text).items():
        if value and name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded
