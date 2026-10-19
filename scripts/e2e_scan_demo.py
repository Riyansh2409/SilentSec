
import sys
from pathlib import Path

from silentsec.scanners.scanner_service import scan_repository

if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: python scripts/e2e_scan_demo.py <repository-path>"
    )

repo = Path(sys.argv[1]).resolve()

result = scan_repository(
    repo,
    timeout_seconds=180,
    enable_ai_triage=False,
)

print(f"\nRepository: {result.repo_path}")
print(f"Languages: {result.languages}")
print(f"Overall status: {result.status.value}")
print(f"Duration: {result.duration_seconds:.2f}s")
print(f"Total findings: {len(result.findings)}")
print(f"Security debt complete: {result.security_debt_complete}")

print("\n--- Scanner results ---")
for scanner in result.scanners:
    print(
        f"{scanner.scanner}: {scanner.status.value}, "
        f"{len(scanner.findings)} findings"
    )
    for error in scanner.errors:
        print(f"  Error: {error}")

print("\n--- Security debt report ---")
if result.security_debt:
    print(result.security_debt.model_dump_json(indent=2))

print("\n--- Findings ---")
for finding in result.findings:
    print(
        f"[{finding.severity.value}] {finding.tool} | "
        f"{finding.file_path}:{finding.start_line} | "
        f"{finding.rule_id} | {finding.message}"
    )

print("\n--- General errors ---")
for error in result.errors:
    print(error)

print("\n--- AI triage ---")
print(f"Attempted: {result.triage_attempted}")
print(f"Complete: {result.triage_complete}")
print(f"Results: {len(result.triage_results)}")
print(f"Errors: {result.triage_errors}")

if result.status.value in {"failed", "skipped"}:
    raise SystemExit(1)
