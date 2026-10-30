from .bandit_runner import run_bandit
from .gitleaks_runner import run_gitleaks
from .results import ScannerRunResult, ScannerStatus
from .semgrep_runner import run_semgrep

__all__ = [
    "RepositoryScanResult",
    "ScannerRunResult",
    "ScannerStatus",
    "run_bandit",
    "run_gitleaks",
    "run_semgrep",
    "scan_repository",
]


def __getattr__(name: str):
    if name in {"RepositoryScanResult", "scan_repository"}:
        from .scanner_service import RepositoryScanResult, scan_repository

        globals()["RepositoryScanResult"] = RepositoryScanResult
        globals()["scan_repository"] = scan_repository
        return globals()[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
