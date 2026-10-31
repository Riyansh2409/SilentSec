"""Turn 'silentsec gate --json' output into a Markdown job summary.

Used by the GitHub Action (action.yml): python gate_summary.py gate.json
Every value from the report is escaped, because file paths and messages come
from the scanned repository.
"""

import json
import sys

ICONS = {"pass": "✅", "fail": "❌", "incomplete": "⚠️"}


def escape(text: object) -> str:
    """Neutralize Markdown/HTML so repository content cannot format the summary."""
    value = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for char in "\\`*_{}[]()#+!|~":
        value = value.replace(char, "\\" + char)
    return value.replace("\n", " ").replace("\r", " ")


def table(title: str, items: list[dict]) -> list[str]:
    if not items:
        return []
    lines = [f"### {title} ({len(items)})", "", "| Severity | Location | Rule |", "|---|---|---|"]
    for item in items[:50]:
        lines.append(
            f"| {escape(item['severity'])} | {escape(item['file_path'])}:{item['start_line']} "
            f"| {escape(item['tool'])} {escape(item['rule_id'])} |"
        )
    if len(items) > 50:
        lines.append(f"| | and {len(items) - 50} more | |")
    return [*lines, ""]


def summary(report: dict) -> str:
    verdict = str(report.get("verdict", "unknown"))
    lines = [
        f"## {ICONS.get(verdict, '')} SilentSec gate: {verdict.upper()}",
        "",
        (
            f"**{escape(report['head_ref'])}** ({escape(report['head_sha'][:8])}) compared with "
            f"**{escape(report['base_ref'])}** ({escape(report['base_sha'][:8])})."
        ),
        "",
    ]
    lines += [f"- {escape(reason)}" for reason in report.get("reasons", [])]
    lines.append("")
    lines += table("Blocking: new findings", report.get("blocking", []))
    lines += table("Warnings: new architecture debt", report.get("warnings", []))
    lines += table("New, below the threshold", report.get("other_new", []))
    lines += table("Resolved by this change", report.get("resolved", []))
    problems = report.get("scanner_problems", [])
    if problems:
        lines += ["### Scanner problems", ""] + [f"- {escape(p)}" for p in problems] + [""]
    lines.append(
        "<sub>Scanners find known patterns; passing the gate is evidence, not proof, "
        "that a change is secure.</sub>"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as handle:
        sys.stdout.write(summary(json.load(handle)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
