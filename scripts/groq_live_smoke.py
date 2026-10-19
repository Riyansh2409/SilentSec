import os

from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    Severity,
)
from silentsec.triage.groq_provider import GroqTriageProvider


def main() -> None:
    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY is missing.")

    finding = Finding(
        fingerprint="groq-live-test-001",
        tool="semgrep",
        rule_id="DEMO001",
        file_path="src/demo.py",
        start_line=10,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message=(
            "Synthetic test finding: subprocess.run may use "
            "shell=True with user-controlled input."
        ),
    )

    result = GroqTriageProvider().triage(
        finding=finding,
        context="Synthetic test only; no real repository code.",
    )

    print("Groq API smoke test: PASSED")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()