"""Compare security findings and track verified scan history."""

from collections import Counter
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, Field

from silentsec.schemas import Finding


class VerificationStatus(str, Enum):
    """Outcome of comparing a baseline finding with a current scan."""

    STILL_OPEN = "still_open"
    RESOLVED = "resolved"
    REINTRODUCED = "reintroduced"
    INCOMPLETE = "incomplete"


class FindingVerification(BaseModel):
    """Verification outcome for one finding."""

    baseline_finding: Finding
    current_finding: Finding | None = None
    status: VerificationStatus
    reason: str


class VerificationReport(BaseModel):
    """Summary of a baseline-to-current scan comparison."""

    results: list[FindingVerification] = Field(default_factory=list)
    baseline_count: int = Field(ge=0)
    current_count: int = Field(ge=0)
    scan_complete: bool

    @property
    def resolved_count(self) -> int:
        return sum(result.status == VerificationStatus.RESOLVED for result in self.results)

    @property
    def still_open_count(self) -> int:
        return sum(result.status == VerificationStatus.STILL_OPEN for result in self.results)

    @property
    def reintroduced_count(self) -> int:
        return sum(result.status == VerificationStatus.REINTRODUCED for result in self.results)

    @property
    def incomplete_count(self) -> int:
        return sum(result.status == VerificationStatus.INCOMPLETE for result in self.results)


class VerificationHistory(BaseModel):
    """In-memory history of complete scan comparisons."""

    resolved_identities: set[tuple[str, str, str]] = Field(default_factory=set)
    resolved_findings: dict[tuple[str, str, str], Finding] = Field(default_factory=dict)

    def compare(
        self,
        baseline_findings: Iterable[Finding],
        current_findings: Iterable[Finding],
        *,
        scan_complete: bool,
    ) -> VerificationReport:
        """Compare scans and record only verified resolutions."""
        baseline = list(baseline_findings)
        current = list(current_findings)

        report = compare_findings(
            baseline,
            current,
            scan_complete=scan_complete,
        )

        if not scan_complete:
            return report

        results = list(report.results)
        baseline_counts = Counter(_identity(finding) for finding in baseline)
        current_counts = Counter(_identity(finding) for finding in current)

        for index, result in enumerate(results):
            identity = _identity(result.baseline_finding)

            if result.status == VerificationStatus.RESOLVED:
                self.resolved_identities.add(identity)
                self.resolved_findings[identity] = result.baseline_finding

            elif result.status == VerificationStatus.STILL_OPEN:
                if identity in self.resolved_identities:
                    results[index] = result.model_copy(
                        update={
                            "status": VerificationStatus.REINTRODUCED,
                            "reason": (
                                "This finding was previously resolved and is present again."
                            ),
                        }
                    )

                self.resolved_identities.discard(identity)
                self.resolved_findings.pop(identity, None)

        # Detect previously resolved findings even when the baseline is empty.
        reported = {_identity(result.baseline_finding) for result in results}

        for identity, previous_finding in list(self.resolved_findings.items()):
            if identity in reported or baseline_counts[identity] > 0:
                continue

            # Only a single current match is sufficient evidence.
            if current_counts[identity] != 1:
                continue

            returned_finding = next(
                finding for finding in current if _identity(finding) == identity
            )

            results.append(
                FindingVerification(
                    baseline_finding=previous_finding,
                    current_finding=returned_finding,
                    status=VerificationStatus.REINTRODUCED,
                    reason=(
                        "This finding was previously resolved and has "
                        "appeared again in a complete scan."
                    ),
                )
            )

            self.resolved_identities.discard(identity)
            self.resolved_findings.pop(identity, None)
        return report.model_copy(update={"results": results})


def _normalized_path(path: str) -> str:
    """Normalize separators and case for path comparisons."""
    return path.replace("\\", "/").removeprefix("./").casefold()


def _identity(finding: Finding) -> tuple[str, str, str]:
    """Return the scanner rule identity and normalized file path."""
    return (
        finding.tool.casefold(),
        finding.rule_id.casefold(),
        _normalized_path(finding.file_path),
    )


def compare_findings(
    baseline_findings: Iterable[Finding],
    current_findings: Iterable[Finding],
    *,
    scan_complete: bool,
) -> VerificationReport:
    """Compare findings without guessing about fixes."""
    baseline = list(baseline_findings)
    current = list(current_findings)

    baseline_counts = Counter(_identity(finding) for finding in baseline)
    current_counts = Counter(_identity(finding) for finding in current)

    current_by_identity = {
        _identity(finding): finding
        for finding in current
        if current_counts[_identity(finding)] == 1
    }

    results: list[FindingVerification] = []

    for old_finding in baseline:
        identity = _identity(old_finding)

        if not scan_complete:
            results.append(
                FindingVerification(
                    baseline_finding=old_finding,
                    status=VerificationStatus.INCOMPLETE,
                    reason=("The current scan is incomplete; resolution cannot be confirmed."),
                )
            )
            continue

        if baseline_counts[identity] == 1 and current_counts[identity] == 0:
            results.append(
                FindingVerification(
                    baseline_finding=old_finding,
                    status=VerificationStatus.RESOLVED,
                    reason=(
                        "No finding with this tool, rule, and file "
                        "was reported by the complete scan."
                    ),
                )
            )
            continue

        if baseline_counts[identity] == 1 and current_counts[identity] == 1:
            results.append(
                FindingVerification(
                    baseline_finding=old_finding,
                    current_finding=current_by_identity[identity],
                    status=VerificationStatus.STILL_OPEN,
                    reason=(
                        "A finding with the same tool, rule, and file "
                        "remains; line changes do not affect this match."
                    ),
                )
            )
            continue

        results.append(
            FindingVerification(
                baseline_finding=old_finding,
                status=VerificationStatus.INCOMPLETE,
                reason=(
                    "Multiple findings share this tool, rule, and file "
                    "identity; the comparison is ambiguous."
                ),
            )
        )

    return VerificationReport(
        results=results,
        baseline_count=len(baseline),
        current_count=len(current),
        scan_complete=scan_complete,
    )
