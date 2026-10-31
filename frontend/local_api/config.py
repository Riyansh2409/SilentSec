"""Find the sibling backend in this checkout, with an explicit override option."""

import json
from pathlib import Path


def resolve_backend(frontend_root: Path, explicit: Path | None = None) -> Path:
    config_path = frontend_root / ".data/config.json"
    config = (
        json.loads(config_path.read_text(encoding="utf-8-sig")) if config_path.is_file() else {}
    )
    candidate = explicit or Path(config.get("backend_path", frontend_root.parent))
    candidate = candidate.expanduser().resolve()
    if not (candidate / "src/silentsec/scanners/scanner_service.py").is_file():
        raise ValueError("Backend not found. Run setup.ps1 -Backend <SilentSec repository folder>.")
    return candidate
