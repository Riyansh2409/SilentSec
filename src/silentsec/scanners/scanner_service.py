"""Orchestrate repository scanners, security-debt scoring, and AI triage."""

from collections.abc import Callable, Iterable
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, Field

from silentsec.architecture.analyzer import run_architecture_analyzer
from silentsec.context import build_source_context
from silentsec.languages import detect_languages
from silentsec.schemas import Finding
from silentsec.scoring import SecurityDebtReport, score_findings
from silentsec.triage import (
    TriageEngine,
    TriageResult,
    build_default_router,
)
from silentsec.triage.providers import AIProviderConfigError
from silentsec.triage.router import TriageBudgetExceededError
from silentsec.triage.schemas import TriageAttribution
from silentsec.verification import (
    VerificationHistory,
    VerificationReport,
    compare_findings,
)

from .bandit_runner import run_bandit
from .gitleaks_runner import run_gitleaks
from .osv_runner import run_osv_scanner
from .results import ScannerRunResult, ScannerStatus
from .semgrep_runner import run_semgrep


def _build_verification_report(
    baseline: list[Finding] | None,
    current: Iterable[Finding],
    history: VerificationHistory | None,
    *,
    scan_complete: bool = False,
) -> VerificationReport | None:
    """Compare findings; resolution is only claimed when scan_complete is True."""
    if baseline is None:
        return None

    if history is not None:
        return history.compare(
            baseline,
            current,
            scan_complete=scan_complete,
        )

    return compare_findings(
        baseline,
        current,
        scan_complete=scan_complete,
    )


class RepositoryScanResult(BaseModel):
    """Combined result of scanner runs for one repository."""

    repo_path: str
    languages: list[str] = Field(default_factory=list)
    status: ScannerStatus
    scanners: list[ScannerRunResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0)
    errors: list[str] = Field(default_factory=list)
    security_debt: SecurityDebtReport | None = None
    security_debt_complete: bool = False
    triage_results: list[TriageResult] = Field(default_factory=list)
    triage_attempted: bool = False
    triage_complete: bool = False
    triage_errors: list[str] = Field(default_factory=list)
    # Finding fingerprint -> provider and model that produced its triage, also
    # for cache hits (cached=True; provider None for older cache entries).
    triage_providers: dict[str, TriageAttribution] = Field(default_factory=dict)
    triage_cache_hits: int = Field(default=0, ge=0)
    triage_provider_calls: int = Field(default=0, ge=0)
    verification_report: VerificationReport | None = None
    verification_attempted: bool = False


ScannerRunner = Callable[..., ScannerRunResult]

OPTIONAL_SCANNERS = frozenset({"osv"})


def _run_safely(
    scanner_name: str,
    runner: ScannerRunner,
    root: Path,
    timeout_seconds: int,
) -> ScannerRunResult:
    """Run a scanner without allowing its exception to abort other scanners."""

    started = perf_counter()

    try:
        return runner(
            root,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        # Avoid exposing raw exception text, which may contain sensitive data.
        return ScannerRunResult(
            scanner=scanner_name,
            status=ScannerStatus.FAILED,
            duration_seconds=round(perf_counter() - started, 3),
            errors=[f"{scanner_name} runner raised {type(exc).__name__}."],
        )


def _overall_status(
    results: list[ScannerRunResult],
) -> ScannerStatus:
    """Calculate overall status without treating skipped tools as failures."""

    if not results:
        return ScannerStatus.SKIPPED

    successful = [
        result
        for result in results
        if result.status
        in {
            ScannerStatus.SUCCESS,
            ScannerStatus.PARTIAL,
        }
    ]

    failed = [result for result in results if result.status == ScannerStatus.FAILED]

    partial = [result for result in results if result.status == ScannerStatus.PARTIAL]

    if not successful:
        if failed:
            return ScannerStatus.FAILED
        return ScannerStatus.SKIPPED

    if failed or partial:
        return ScannerStatus.PARTIAL

    return ScannerStatus.SUCCESS


def scan_repository(
    repo_path: str | Path,
    timeout_seconds: int = 180,
    *,
    enable_ai_triage: bool = False,
    max_ai_triage_findings: int = 20,
    use_triage_cache: bool = True,
    verification_baseline: Iterable[Finding] | None = None,
    verification_history: VerificationHistory | None = None,
) -> RepositoryScanResult:
    """Scan a repository, score security debt, and optionally triage findings."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if max_ai_triage_findings <= 0:
        raise ValueError("max_ai_triage_findings must be positive")

    root = Path(repo_path).expanduser().resolve()
    started = perf_counter()
    baseline_findings = list(verification_baseline) if verification_baseline is not None else None
    if not root.is_dir():
        verification_report = _build_verification_report(
            baseline_findings,
            [],
            verification_history,
        )
        return RepositoryScanResult(
            repo_path=str(root),
            status=ScannerStatus.FAILED,
            duration_seconds=0,
            errors=["Repository directory does not exist."],
            verification_report=verification_report,
            verification_attempted=baseline_findings is not None,
        )
    try:
        language_report = detect_languages(root)
    except (OSError, ValueError):
        verification_report = _build_verification_report(
            baseline_findings,
            [],
            verification_history,
        )
        return RepositoryScanResult(
            repo_path=str(root),
            status=ScannerStatus.FAILED,
            duration_seconds=round(perf_counter() - started, 3),
            errors=["Could not inspect repository languages."],
            verification_report=verification_report,
            verification_attempted=baseline_findings is not None,
        )

    scanner_specs: list[tuple[str, ScannerRunner]] = [
        ("semgrep", run_semgrep),
        ("bandit", run_bandit),
        ("gitleaks", run_gitleaks),
        ("architecture", run_architecture_analyzer),
        ("osv", run_osv_scanner),
    ]

    results = [
        _run_safely(
            scanner_name=name,
            runner=runner,
            root=root,
            timeout_seconds=timeout_seconds,
        )
        for name, runner in scanner_specs
    ]

    # Preserve findings from every scanner. Scoring deduplicates independently.
    findings = [finding for result in results for finding in result.findings]

    errors = [f"{result.scanner}: {error}" for result in results for error in result.errors]

    overall_status = _overall_status(results)
    debt_report = score_findings(findings, repo_root=str(root))

    # Optional scanners (dependency checks) may be skipped, e.g. when the tool is
    # not installed or there is nothing to check, without making the result
    # incomplete. A core code scanner that was skipped still means "incomplete".
    security_debt_complete = all(
        result.status == ScannerStatus.SUCCESS
        or (result.scanner in OPTIONAL_SCANNERS and result.status == ScannerStatus.SKIPPED)
        for result in results
    )

    verification_attempted = baseline_findings is not None
    verification_report = _build_verification_report(
        baseline_findings,
        findings,
        verification_history,
        scan_complete=security_debt_complete,
    )

    triage_results: list[TriageResult] = []
    triage_errors: list[str] = []
    triage_providers: dict[str, TriageAttribution] = {}
    triage_cache_hits = 0
    triage_provider_calls = 0
    triage_attempted = enable_ai_triage
    triage_complete = False

    if enable_ai_triage:
        try:
            # Budget: enough for every selected finding to use a retry and a
            # fallback, but bounded so one scan cannot drain API quota.
            router_options: dict = {"max_provider_calls": max_ai_triage_findings * 3}
            if not use_triage_cache:
                router_options["cache"] = None
            router = build_default_router(**router_options)
        except AIProviderConfigError as exc:
            router = None
            triage_errors.append(f"Could not initialize AI triage: {exc}")
        except Exception as exc:  # noqa: BLE001
            router = None
            triage_errors.append(f"Could not initialize AI triage ({type(exc).__name__}).")

        if router is None:
            if not triage_errors:
                triage_errors.append(
                    "AI triage requested, but no provider is configured. Set GEMINI_API_KEY "
                    "or GROQ_API_KEY, or add ollama to SILENTSEC_AI_PROVIDERS."
                )

        elif not findings:
            # No findings means there was nothing to send to an AI provider.
            triage_complete = True

        else:
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }

            ordered_findings = sorted(
                findings,
                key=lambda finding: (
                    severity_order.get(finding.severity.value, 5),
                    finding.file_path,
                    finding.start_line,
                    finding.finding_id,
                ),
            )

            selected_findings = ordered_findings[:max_ai_triage_findings]

            if len(ordered_findings) > len(selected_findings):
                skipped = len(ordered_findings) - len(selected_findings)
                triage_errors.append(f"AI triage limit reached: {skipped} findings were skipped.")

            triage_engine = TriageEngine(router)

            for finding in selected_findings:
                try:
                    context = build_source_context(root, finding)

                    result = triage_engine.triage_finding(
                        finding,
                        context=context,
                    )
                    triage_results.append(result)
                    attribution = getattr(router, "last_attribution", None)
                    if isinstance(attribution, TriageAttribution):
                        triage_providers[finding.fingerprint] = attribution

                except TriageBudgetExceededError:
                    triage_errors.append(
                        "AI triage call budget reached; remaining findings were not triaged."
                    )
                    break

                except Exception as exc:  # noqa: BLE001
                    # One failed finding must not stop the remaining triage work.
                    triage_errors.append(
                        f"AI triage failed for finding {finding.finding_id} ({type(exc).__name__})."
                    )

            triage_complete = len(triage_results) == len(findings) and not triage_errors
            # E.g. "Ollama is not running at ...": shown even when a later
            # provider answered, so the user knows Ollama was skipped.
            # First, because the CLI shows only the first few errors.
            notes = getattr(router, "provider_notes", {})
            if isinstance(notes, dict):
                triage_errors[:0] = [str(note) for note in notes.values()]

            cache = getattr(router, "cache", None)
            triage_cache_hits = getattr(cache, "hits", 0) if cache is not None else 0
            triage_provider_calls = getattr(router, "provider_calls", 0)

    return RepositoryScanResult(
        repo_path=str(root),
        languages=language_report.languages,
        status=overall_status,
        scanners=results,
        findings=findings,
        duration_seconds=round(perf_counter() - started, 3),
        errors=errors,
        security_debt=debt_report,
        security_debt_complete=security_debt_complete,
        triage_results=triage_results,
        triage_attempted=triage_attempted,
        triage_complete=triage_complete,
        triage_errors=triage_errors,
        triage_providers=triage_providers,
        triage_cache_hits=triage_cache_hits if isinstance(triage_cache_hits, int) else 0,
        triage_provider_calls=(
            triage_provider_calls if isinstance(triage_provider_calls, int) else 0
        ),
        verification_report=verification_report,
        verification_attempted=verification_attempted,
    )
