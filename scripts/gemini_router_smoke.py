"""Live smoke test for Gemini model fallback routing."""

import logging
import os

from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    Severity,
)
from silentsec.triage.engine import TriageEngine
from silentsec.triage.gemini_provider import GeminiTriageProvider
from silentsec.triage.router import TriageRouter

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)


def main() -> None:
    if not os.getenv("GEMINI_API_KEY"):
        raise SystemExit(
            "GEMINI_API_KEY is missing from this PowerShell session."
        )

    router = TriageRouter(
        [
            (
                "gemini-3.6-flash",
                GeminiTriageProvider(model="gemini-3.6-flash"),
            ),
            (
                "gemini-2.5-flash",
                GeminiTriageProvider(model="gemini-2.5-flash"),
            ),
        ]
    )

    engine = TriageEngine(router)

    finding = Finding(
        fingerprint="router-live-test-001",
        tool="semgrep",
        rule_id="DEMO001",
        file_path="src/demo.py",
        start_line=10,
        end_line=10,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message=(
            "Synthetic finding: subprocess.run may execute "
            "user-controlled input with shell=True."
        ),
    )

    result = engine.triage_finding(
        finding=finding,
        context="Synthetic test data only; no real repository code.",
    )

    print("\nGemini router smoke test: PASSED")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()