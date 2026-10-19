import os

from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    Severity,
)
from silentsec.triage.engine import TriageEngine
from silentsec.triage.gemini_provider import GeminiTriageProvider


def main() -> None:
    if not os.getenv("GEMINI_API_KEY"):
        raise SystemExit(
            "GEMINI_API_KEY is missing. Set it in this PowerShell session."
        )

    finding = Finding(
        fingerprint="manual-smoke-test-001",
        tool="semgrep",
        rule_id="DEMO001",
        file_path="src/demo.py",
        start_line=10,
        end_line=10,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message=(
            "Potential command injection: "
            "subprocess.run uses shell=True with user-controlled input."
        ),
    )

    provider = GeminiTriageProvider()
    engine = TriageEngine(provider)

    result = engine.triage_finding(
        finding=finding,
        context=(
            "Synthetic test finding, not an actual repository vulnerability. "
            "Explain the potential risk and recommend safe remediation."
        ),
    )

    print("\nGemini API smoke test: PASSED")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()