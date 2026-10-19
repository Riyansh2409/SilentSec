"""Verify router fallback using a live Groq request."""

import logging
import os

from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    Severity,
)
from silentsec.triage.engine import TriageEngine
from silentsec.triage.groq_provider import GroqTriageProvider
from silentsec.triage.router import TriageRouter
from silentsec.triage.schemas import TriageResult

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)


class SimulatedGeminiOutage:
    """Simulate a temporary primary-provider outage without calling Gemini."""

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        raise TimeoutError("Simulated Gemini timeout for fallback testing.")


def main() -> None:
    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY is missing.")

    router = TriageRouter(
        [
            ("gemini-simulated-outage", SimulatedGeminiOutage()),
            ("groq-live", GroqTriageProvider()),
        ]
    )

    engine = TriageEngine(router)

    finding = Finding(
        fingerprint="router-fallback-test-001",
        tool="semgrep",
        rule_id="DEMO001",
        file_path="src/demo.py",
        start_line=10,
        end_line=10,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message=(
            "Synthetic test: subprocess.run may use shell=True "
            "with user-controlled input."
        ),
    )

    result = engine.triage_finding(
        finding=finding,
        context="Synthetic test only; no real repository code.",
    )

    assert result.finding_id == finding.finding_id
    assert result.fingerprint == finding.fingerprint
    assert result.requires_human_review is True

    print("\nGroq fallback smoke test: PASSED")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()