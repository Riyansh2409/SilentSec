"""Render a self-contained, offline HTML report.

Everything shown comes from the scanned repository (paths, messages, code,
commit subjects) and is therefore untrusted. Every value goes through
``_e`` (HTML escaping), the only script is a fixed constant allowed by a
Content-Security-Policy hash, and nothing is loaded from the network.
"""

import base64
import html
import math
from collections.abc import Sequence
from datetime import datetime
from hashlib import sha256

from silentsec.history import TimelineReport
from silentsec.remediation.ai_fix import AIFixReport, AIFixStatus
from silentsec.remediation.verify import FindingSummary, FixVerdict, FixVerificationReport
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import FindingCategory, Severity
from silentsec.scoring.engine import MAX_REPOSITORY_SCORE
from silentsec.triage.providers import is_local_provider

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
MAX_MESSAGE_CHARS = 600


def _e(value: object) -> str:
    """Escape any value for HTML text or a quoted attribute."""
    return html.escape(str(value), quote=True)


SCRIPT = """
document.querySelectorAll('[data-filter]').forEach(function (box) {
  box.addEventListener('change', function () {
    var level = box.getAttribute('data-filter');
    document.querySelectorAll('tbody[data-severity="' + level + '"]').forEach(function (row) {
      row.hidden = !box.checked;
    });
  });
});
var toggle = document.getElementById('expand-all');
if (toggle) {
  toggle.addEventListener('click', function () {
    var open = toggle.getAttribute('aria-pressed') !== 'true';
    document.querySelectorAll('details.evidence').forEach(function (item) { item.open = open; });
    toggle.setAttribute('aria-pressed', String(open));
    toggle.textContent = open ? 'Collapse all evidence' : 'Expand all evidence';
  });
}
""".strip()

SCRIPT_HASH = base64.b64encode(sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")

STYLE = """
:root {
  --paper: #f6f5fb;
  --surface: #ffffff;
  --ink: #1b1640;
  --muted: #5d5a78;
  --rule: #dcd8ee;
  --violet: #5b3fd6;
  --blue: #2f6feb;
  --sev-critical: #b4235a;
  --sev-high: #c2501a;
  --sev-medium: #946f00;
  --sev-low: #50677a;
  --sev-info: #7a7f95;
  --good: #1f7a4d;
  --code-bg: #efedf8;
  --serif: Charter, "Bitstream Charter", "Sitka Text", Cambria, Georgia, serif;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", Consolas, "Liberation Mono", monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #14112b;
    --surface: #1d1940;
    --ink: #ebe8fb;
    --muted: #a9a4c9;
    --rule: #34305c;
    --violet: #a596ff;
    --blue: #79a8ff;
    --sev-critical: #ff7aa8;
    --sev-high: #ff9d6b;
    --sev-medium: #e6c35c;
    --sev-low: #9fb4c6;
    --sev-info: #a3a7ba;
    --good: #5fd39a;
    --code-bg: #262150;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 16px/1.55 var(--sans);
}
main { max-width: 1080px; margin: 0 auto; padding: 40px 24px 80px; }
h1, h2, h3 { font-family: var(--serif); font-weight: 600; line-height: 1.2; }
h1 { font-size: clamp(1.9rem, 4vw, 2.8rem); margin: 0 0 12px; max-width: 26ch; letter-spacing: -0.01em; }
h2 { font-size: 1.5rem; margin: 56px 0 6px; }
h2 + .lede { margin-top: 0; }
.lede { color: var(--muted); max-width: 70ch; }
.masthead { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap;
  color: var(--muted); font-size: 0.9rem; border-bottom: 2px solid var(--violet); padding-bottom: 10px; }
.masthead strong { color: var(--violet); font-family: var(--serif); font-size: 1.1rem; }
.verdict { margin-top: 36px; }
.risk-critical { color: var(--sev-critical); }
.risk-high { color: var(--sev-high); }
.risk-moderate { color: var(--sev-medium); }
.risk-low, .risk-none { color: var(--good); }
.composition { margin: 28px 0 8px; }
.bar { position: relative; display: flex; height: 44px; background: var(--surface);
  border: 1px solid var(--rule); border-radius: 6px; overflow: hidden; }
.bar span { display: block; height: 100%; }
.seg-security { background: var(--violet); }
.seg-architecture { background: var(--blue); opacity: 0.85; }
.seg-other { background: var(--sev-info); }
.cap-note { font-size: 0.85rem; color: var(--muted); margin-top: 6px; }
.legend { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 14px 0 0; padding: 0; list-style: none; }
.legend li { display: flex; gap: 8px; align-items: baseline; }
.swatch { width: 12px; height: 12px; border-radius: 3px; display: inline-block; flex: none; }
.legend b { font-variant-numeric: tabular-nums; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0;
  margin: 28px 0 0; border-top: 1px solid var(--rule); }
.facts div { padding: 12px 16px 12px 0; border-bottom: 1px solid var(--rule); }
.facts dt { color: var(--muted); font-size: 0.85rem; }
.facts dd { margin: 2px 0 0; font-size: 1.15rem; font-variant-numeric: tabular-nums; }
.scanners { display: flex; flex-wrap: wrap; gap: 8px; margin: 18px 0 0; padding: 0; list-style: none; }
.scanners li { border: 1px solid var(--rule); border-radius: 999px; padding: 3px 12px; font-size: 0.85rem;
  background: var(--surface); }
.scanners .failed, .scanners .partial { border-color: var(--sev-high); color: var(--sev-high); }
.notice { border-left: 4px solid var(--sev-high); background: var(--surface); padding: 10px 14px; margin: 18px 0; }
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th { text-align: left; font-weight: 600; color: var(--muted); font-size: 0.85rem; padding: 8px 10px;
  border-bottom: 2px solid var(--rule); }
td { padding: 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.sev { font-weight: 600; white-space: nowrap; }
.sev::before { content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 7px; background: currentColor; vertical-align: 1px; }
.sev-critical { color: var(--sev-critical); }
.sev-high { color: var(--sev-high); }
.sev-medium { color: var(--sev-medium); }
.sev-low { color: var(--sev-low); }
.sev-info { color: var(--sev-info); }
.loc { font-family: var(--mono); font-size: 0.85rem; white-space: nowrap; }
.tools { color: var(--muted); font-size: 0.85rem; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; }
th { white-space: nowrap; }
.finding-title { font-weight: 600; }
tr.detail td { padding-top: 0; border-bottom: 1px solid var(--rule); }
details.evidence summary { cursor: pointer; color: var(--violet); font-size: 0.9rem; width: fit-content; }
details.evidence[open] summary { margin-bottom: 8px; }
pre { background: var(--code-bg); border-radius: 6px; padding: 12px 14px; overflow-x: auto;
  font: 0.82rem/1.5 var(--mono); margin: 8px 0; }
.explain { color: var(--muted); font-size: 0.88rem; }
.controls { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; margin: 14px 0; font-size: 0.9rem; }
.controls label { display: flex; gap: 6px; align-items: center; }
button { font: inherit; color: var(--violet); background: var(--surface); border: 1px solid var(--violet);
  border-radius: 6px; padding: 5px 12px; cursor: pointer; }
:focus-visible { outline: 3px solid var(--blue); outline-offset: 2px; }
.chart { width: 100%; height: auto; background: var(--surface); border: 1px solid var(--rule); border-radius: 6px; }
.chart text { font: 12px var(--sans); fill: var(--muted); }
.chart .axis { stroke: var(--rule); }
.chart .line { fill: none; stroke: var(--blue); stroke-width: 2.5; }
.chart .cap { stroke: var(--sev-info); stroke-dasharray: 4 4; }
.chart .dot { fill: var(--surface); stroke: var(--blue); stroke-width: 2.5; }
.chart .dot.peak { fill: var(--sev-critical); stroke: var(--sev-critical); }
.chart .dot.incomplete { stroke: var(--sev-info); stroke-dasharray: 2 2; }
.chart .back-ring { fill: none; stroke: var(--sev-high); stroke-width: 2; }
.changes li.back { color: var(--sev-high); font-weight: 600; }
.changes.incomplete { color: var(--sev-high); }
.chart .label { fill: var(--ink); font-weight: 600; }
.up { color: var(--sev-critical); }
.down { color: var(--good); }
.changes { margin: 4px 0 0; padding-left: 18px; font-size: 0.85rem; overflow-wrap: anywhere; }
.fix { background: var(--surface); border: 1px solid var(--rule); border-left: 5px solid var(--violet);
  border-radius: 6px; padding: 18px 20px; margin: 18px 0; }
.fix.verified_fix { border-left-color: var(--good); }
.fix.regression { border-left-color: var(--sev-critical); }
.fix.not_verified, .fix.partial, .fix.unresolved { border-left-color: var(--sev-medium); }
.fix h3 { margin: 0 0 6px; font-size: 1.25rem; }
.verdict-word { font-family: var(--serif); }
.small { font-size: 0.85rem; color: var(--muted); }
ul.plain { padding-left: 18px; }
footer { margin-top: 64px; padding-top: 14px; border-top: 1px solid var(--rule); color: var(--muted); font-size: 0.85rem; }
@media (max-width: 640px) {
  main { padding: 24px 14px 60px; }
  .hide-narrow { display: none; }
  td, th { padding: 8px 6px; }
  .loc { white-space: normal; overflow-wrap: anywhere; }
}
@media print {
  details.evidence > *:not(summary) { display: block; }
  .controls { display: none; }
}
""".strip()


def _severity_class(severity: Severity) -> str:
    return f"sev sev-{severity.value}"


def _severity_label(severity: Severity) -> str:
    return severity.value.capitalize()


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _verdict_sentence(result: RepositoryScanResult) -> tuple[str, str]:
    """A plain-language headline and its CSS class."""
    debt = result.security_debt
    if debt is None:
        return "No score: the scan did not produce a report.", "risk-none"

    risk = debt.risk_level.value
    issues = debt.unique_open_findings_count
    secrets = sum(
        1 for item in debt.scored_findings if item.finding.category == FindingCategory.SECRET
    )
    if issues == 0:
        return "No open security debt was found.", "risk-none"

    headline = f"Security risk is {risk}: {_plural(issues, 'open issue')}"
    if secrets:
        headline += f", including {_plural(secrets, 'possible leaked secret')}"
    return headline + ".", f"risk-{risk}"


def _composition(result: RepositoryScanResult) -> str:
    debt = result.security_debt
    if debt is None:
        return ""

    other = max(0.0, debt.raw_score - debt.security_points - debt.architecture_debt_points)
    total = debt.raw_score
    scale = max(total, MAX_REPOSITORY_SCORE)
    parts = [
        ("Security", debt.security_points, "seg-security", "var(--violet)"),
        ("Architecture (capped at 25)", debt.architecture_debt_points, "seg-architecture", "var(--blue)"),
        ("Other", other, "seg-other", "var(--sev-info)"),
    ]
    segments = "".join(
        f'<span class="{css}" style="width:{value / scale * 100:.3f}%" title="{_e(label)}"></span>'
        for label, value, css, _ in parts
        if value > 0
    )
    legend = "".join(
        f'<li><span class="swatch" style="background:{color}"></span>{_e(label)} <b>{value:.1f}</b></li>'
        for label, value, _, color in parts
        if value > 0 or label == "Security"
    )
    cap_note = (
        f"The score is capped at 100; the uncapped total is {total:.1f}."
        if total > MAX_REPOSITORY_SCORE
        else f"Total {total:.1f} of a 100-point scale."
    )
    return (
        '<section class="composition" aria-label="How the score is made up">'
        f'<div class="bar" role="img" aria-label="Score composition: {_e(cap_note)}">{segments}</div>'
        f'<p class="cap-note">{_e(cap_note)}</p>'
        f'<ul class="legend">{legend}</ul></section>'
    )


def _facts(result: RepositoryScanResult) -> str:
    debt = result.security_debt
    if debt is None:
        return ""
    density = (
        f"{debt.debt_density_per_kloc:.1f} per 1,000 lines"
        if debt.debt_density_per_kloc is not None
        else "Not shown for small repositories"
    )
    items = [
        ("Score", f"{debt.score:.1f} / 100"),
        ("Architecture debt", debt.architecture_risk_level.value.capitalize()),
        ("Duplicates merged", str(debt.duplicate_findings_removed)),
        ("Lines analyzed", f"{debt.analyzed_lines:,}" if debt.analyzed_lines is not None else "Unknown"),
        ("Issue density", density),
    ]
    body = "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>" for k, v in items)
    return f'<dl class="facts">{body}</dl>'


def _scanners(result: RepositoryScanResult) -> str:
    chips = "".join(
        f'<li class="{_e(s.scanner_status_class)}">{_e(s.name)}: {_e(s.status)}</li>'
        for s in (
            _ScannerChip(scanner.scanner, scanner.status, len(scanner.findings))
            for scanner in result.scanners
        )
    )
    warning = ""
    if not result.security_debt_complete:
        warning = (
            '<p class="notice">At least one scanner did not finish successfully, so this score '
            "may be missing issues. Install the missing scanner and run the report again.</p>"
        )
    return f'<ul class="scanners" aria-label="Scanners">{chips}</ul>{warning}'


class _ScannerChip:
    def __init__(self, name: str, status: ScannerStatus, count: int) -> None:
        self.name = name
        self.status = f"{status.value}, {_plural(count, 'finding')}"
        self.scanner_status_class = status.value


def _findings(result: RepositoryScanResult, snippets: dict[str, str]) -> str:
    debt = result.security_debt
    if debt is None or not debt.scored_findings:
        return (
            "<h2>Issues</h2><p class=\"lede\">No open issues. This covers what the listed "
            "scanners can detect, not every possible weakness.</p>"
        )

    groups = {group.representative.fingerprint: group for group in debt.correlation_groups}
    triage = {item.fingerprint: item for item in result.triage_results}
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in debt.scored_findings:
        counts[item.finding.severity] += 1

    filters = "".join(
        f'<label><input type="checkbox" checked data-filter="{severity.value}"> '
        f"{_severity_label(severity)} ({counts[severity]})</label>"
        for severity in SEVERITY_ORDER
        if counts[severity]
    )

    rows: list[str] = []
    for item in debt.scored_findings:
        finding = item.finding
        group = groups.get(finding.fingerprint)
        members = group.findings if group is not None else [finding]
        tools = sorted({f"{member.tool} {member.rule_id}" for member in members})
        merged = (
            f'<p class="explain">Merged {len(members)} reports: {_e(group.reason)}</p>'
            if group is not None and len(members) > 1
            else ""
        )
        message = finding.message
        if len(message) > MAX_MESSAGE_CHARS:
            message = message[: MAX_MESSAGE_CHARS - 1] + "…"
        title = message.split(". ")[0][:140]

        snippet = snippets.get(finding.fingerprint)
        snippet_html = f"<pre><code>{_e(snippet)}</code></pre>" if snippet else ""
        triage_item = triage.get(finding.fingerprint)
        triage_html = ""
        if triage_item is not None:
            steps = "".join(f"<li>{_e(step)}</li>" for step in triage_item.remediation_steps)
            label = result.triage_providers.get(finding.fingerprint)
            by = ""
            if label:
                by = f" by {_e(label)}" + (", local" if is_local_provider(label) else "")
            triage_html = (
                f'<p><b>AI triage</b>{by} (suggested priority {_e(triage_item.priority.value)}, '
                f"needs human review): {_e(triage_item.summary)}</p>"
                f'<ol class="plain">{steps}</ol>'
            )

        cwe = f" {finding.cwe_id}" if finding.cwe_id else ""
        rows.append(
            f'<tbody data-severity="{_e(finding.severity.value)}">'
            "<tr>"
            f'<td><span class="{_severity_class(finding.severity)}">'
            f"{_severity_label(finding.severity)}</span></td>"
            f'<td><div class="finding-title">{_e(title)}</div>'
            f'<div class="tools">{_e(", ".join(tools))}{_e(cwe)}</div></td>'
            f'<td class="loc">{_e(finding.file_path)}:{finding.start_line}</td>'
            f'<td class="num hide-narrow">{item.score:.1f}</td>'
            f'<td class="hide-narrow">{_e(item.remediation_effort.capitalize())}</td>'
            "</tr>"
            '<tr class="detail"><td></td><td colspan="4">'
            '<details class="evidence"><summary>Evidence and score</summary>'
            f"<p>{_e(message)}</p>{merged}{snippet_html}{triage_html}"
            f'<p class="explain">{_e(item.explanation)}</p>'
            "</details></td></tr></tbody>"
        )

    return (
        "<h2>Issues</h2>"
        f'<p class="lede">{_plural(len(debt.scored_findings), "unique issue")}, most serious first. '
        "Reports of the same problem from different scanners are merged.</p>"
        f'<div class="controls">{filters}'
        '<button type="button" id="expand-all" aria-pressed="false">Expand all evidence</button></div>'
        '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Issue</th><th>Location</th>'
        '<th class="num hide-narrow">Points</th><th class="hide-narrow">Fix effort</th></tr></thead>'
        f"{''.join(rows)}</table></div>"
    )


def _patterns(result: RepositoryScanResult) -> str:
    debt = result.security_debt
    if debt is None or not debt.recurring_patterns:
        return ""
    rows = "".join(
        "<tr>"
        f'<td><span class="{_severity_class(pattern.highest_severity)}">'
        f"{_severity_label(pattern.highest_severity)}</span></td>"
        f"<td>{_e(pattern.representative_message[:160])}"
        f'<div class="tools">{_e(", ".join(pattern.rule_ids))}</div></td>'
        f'<td class="num">{pattern.occurrence_count}</td><td class="num">{pattern.file_count}</td>'
        "</tr>"
        for pattern in debt.recurring_patterns[:12]
    )
    return (
        "<h2>Recurring patterns</h2>"
        '<p class="lede">The same mistake in several places is a habit, not a typo. '
        "These are the patterns worth fixing at the source.</p>"
        '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Pattern</th>'
        '<th class="num">Times</th><th class="num">Files</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
    )


def _nice_step(raw: float) -> float:
    """Round a tick step to 1, 2, 2.5 or 5 times a power of ten."""
    magnitude = 10 ** math.floor(math.log10(raw))
    for factor in (1, 2, 2.5, 5, 10):
        if raw <= factor * magnitude:
            return factor * magnitude
    return 10 * magnitude


def _timeline_chart(report: TimelineReport) -> str:
    points = report.points
    width, height = 960, 300
    left, right, top, bottom = 56, 56, 28, 54
    plot_w, plot_h = width - left - right, height - top - bottom
    peak_value = max([point.raw_score for point in points] + [10.0])
    step = _nice_step(peak_value * 1.1 / 4)
    y_max = step * math.ceil(peak_value * 1.1 / step)

    def x(index: int) -> float:
        return left + (plot_w / 2 if len(points) == 1 else plot_w * index / (len(points) - 1))

    def y(value: float) -> float:
        return top + plot_h - (value / y_max) * plot_h

    biggest = report.biggest_increase
    parts = [
        f'<line class="axis" x1="{left}" y1="{top + plot_h}" x2="{width - right}" y2="{top + plot_h}"/>'
    ]
    tick = 0.0
    while tick <= y_max + 1e-9:
        parts.append(
            f'<line class="axis" x1="{left}" y1="{y(tick):.1f}" x2="{width - right}" '
            f'y2="{y(tick):.1f}" opacity="0.5"/>'
        )
        parts.append(
            f'<text x="{left - 8}" y="{y(tick) + 4:.1f}" text-anchor="end">{tick:g}</text>'
        )
        tick += step
    if y_max > MAX_REPOSITORY_SCORE:
        parts.append(
            f'<line class="cap" x1="{left}" y1="{y(100):.1f}" x2="{width - right}" y2="{y(100):.1f}"/>'
            f'<text x="{width - right}" y="{y(100) - 6:.1f}" text-anchor="end">Score cap (100)</text>'
        )
    path = " ".join(
        f"{'M' if index == 0 else 'L'}{x(index):.1f},{y(point.raw_score):.1f}"
        for index, point in enumerate(points)
    )
    parts.append(f'<path class="line" d="{path}"/>')
    for index, point in enumerate(points):
        if point.reintroduced:
            parts.append(
                f'<circle class="back-ring" cx="{x(index):.1f}" cy="{y(point.raw_score):.1f}" r="10">'
                f"<title>{_e(point.short_sha)}: {_plural(len(point.reintroduced), 'issue')} "
                "came back after being fixed</title></circle>"
            )
        peak = biggest is not None and point.commit_sha == biggest.commit_sha
        state = " peak" if peak else "" if point.complete else " incomplete"
        parts.append(
            f'<circle class="dot{state}" cx="{x(index):.1f}" '
            f'cy="{y(point.raw_score):.1f}" r="{6 if peak else 4.5}">'
            f"<title>{_e(point.short_sha)} {_e(point.subject)}: {point.raw_score:.1f}</title></circle>"
        )
        parts.append(
            f'<text class="label" x="{x(index):.1f}" y="{y(point.raw_score) - 10:.1f}" '
            f'text-anchor="middle">{point.raw_score:.1f}</text>'
        )
        parts.append(
            f'<text x="{x(index):.1f}" y="{height - 30}" text-anchor="middle">{_e(point.short_sha)}</text>'
            f'<text x="{x(index):.1f}" y="{height - 14}" text-anchor="middle">'
            f"{_e(point.committed_at[:10])}</text>"
        )
    summary = (
        f"Uncapped score across {_plural(len(points), 'commit')}"
        + (f"; biggest increase at {biggest.short_sha}" if biggest else "")
    )
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{_e(summary)}">'
        f"{''.join(parts)}</svg>"
    )


def _change_item(change, sign: str) -> str:
    location = f'<span class="loc">{_e(change.file_path)}:{change.start_line}</span>'
    if getattr(change, "reintroduced", False):
        return (
            f'<li class="back">Came back: {_e(change.tool)} {_e(change.rule_id)} at {location} '
            f"(fixed in {_e(change.previously_fixed_in or 'an earlier commit')})</li>"
        )
    return f"<li>{sign} {_e(change.tool)} {_e(change.rule_id)} at {location}</li>"


def _change_list(changes: Sequence, sign: str) -> str:
    if not changes:
        return ""
    # Issues that came back are listed first: they are the most telling.
    ordered = sorted(changes, key=lambda change: not getattr(change, "reintroduced", False))
    items = "".join(_change_item(change, sign) for change in ordered[:6])
    more = f"<li>and {len(changes) - 6} more</li>" if len(changes) > 6 else ""
    return f'<ul class="changes">{items}{more}</ul>'


def _timeline(report: TimelineReport | None, note: str | None) -> str:
    if report is None:
        return (
            "<h2>Over time</h2>"
            f'<p class="lede">{_e(note or "History was not included in this report.")}</p>'
        )
    if not report.points:
        return "<h2>Over time</h2><p class=\"lede\">This branch has no commits yet.</p>"

    rows: list[str] = []
    previous = None
    for point in report.points:
        if previous is None:
            change = '<span class="small">Baseline</span>'
        elif not (previous.complete and point.complete):
            change = '<span class="small" title="A scanner did not finish, so the change is unknown">?</span>'
        else:
            delta = point.raw_score - previous.raw_score
            css = "up" if delta > 0 else "down" if delta < 0 else ""
            change = f'<span class="{css}">{delta:+.1f}</span>'
        if point.attribution == "unknown":
            changes = '<p class="small">Not attributed: a scan around this commit was incomplete.</p>'
        else:
            changes = _change_list(point.introduced, "Added") + _change_list(point.fixed, "Fixed")
        if point.scanner_problems:
            problems = "".join(f"<li>{_e(problem)}</li>" for problem in point.scanner_problems)
            changes += f'<ul class="changes incomplete">{problems}</ul>'
        rows.append(
            "<tr>"
            f'<td class="loc">{_e(point.short_sha)}</td>'
            f'<td class="hide-narrow">{_e(point.committed_at[:10])}</td>'
            f"<td>{_e(point.subject)}{changes}</td>"
            f'<td class="num">{point.raw_score:.1f}</td><td class="num">{change}</td>'
            "</tr>"
        )
        previous = point

    biggest = report.biggest_increase
    lede = (
        f"Debt rose most at {biggest.short_sha}, “{biggest.subject}”."
        if biggest is not None
        else "Debt did not rise in this window."
    )
    came_back = report.reintroduced
    if came_back:
        lede += (
            f" {_plural(len(came_back), 'issue')} came back after being fixed "
            "(ringed in the chart)."
        )
    limits = "".join(f"<li>{_e(item)}</li>" for item in report.limitations)
    return (
        "<h2>Over time</h2>"
        f'<p class="lede">{_e(lede)} The last {_plural(len(report.points), "commit")} on '
        f"{_e(report.branch)}, oldest first. Scores are uncapped so changes stay visible.</p>"
        f"{_timeline_chart(report)}"
        '<div class="table-wrap"><table><thead><tr><th>Commit</th>'
        '<th class="hide-narrow">Date</th><th>Change</th>'
        '<th class="num">Score</th><th class="num">Δ</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        f'<ul class="plain small">{limits}</ul>'
    )


VERDICT_WORDS = {
    FixVerdict.VERIFIED_FIX: "Verified fix",
    FixVerdict.PARTIAL: "Partial fix",
    FixVerdict.UNRESOLVED: "Did not fix the issue",
    FixVerdict.REGRESSION: "Regression",
    FixVerdict.NOT_VERIFIED: "Not verified",
}


def _summary_items(items: Sequence[FindingSummary]) -> str:
    return "".join(
        f'<li><span class="{_severity_class(item.severity)}">{_severity_label(item.severity)}</span> '
        f"{_e(item.tool)} {_e(item.rule_id)} at "
        f'<span class="loc">{_e(item.file_path)}:{item.start_line}</span></li>'
        for item in items
    )


def _fix_card(report: FixVerificationReport, *, title: str, ai: AIFixReport | None = None) -> str:
    score = ""
    if report.score_before is not None and report.score_after is not None:
        before = report.raw_score_before if report.raw_score_before is not None else report.score_before
        after = report.raw_score_after if report.raw_score_after is not None else report.score_after
        score = f"<p>Score {before:.1f} to {after:.1f} (uncapped).</p>"
    reasons = "".join(f"<li>{_e(reason)}</li>" for reason in report.reasons)
    sections = ""
    for label, items in (("Resolved", report.resolved), ("Still open", report.remaining), ("New", report.new)):
        if items:
            sections += f"<p><b>{label}</b></p><ul class=\"plain\">{_summary_items(items)}</ul>"
    checks = ", ".join(report.checks_run) or "none"
    ai_html = ""
    if ai is not None and ai.proposal is not None:
        ai_html = (
            f'<p class="small">Proposed by {_e(ai.proposal.provider)}. '
            "AI changes always need human review.</p>"
            f"<p>{_e(ai.proposal.explanation)}</p>"
        )
    limits = "".join(f"<li>{_e(item)}</li>" for item in report.limitations)
    return (
        f'<article class="fix {_e(report.verdict.value)}">'
        f'<h3><span class="verdict-word">{_e(VERDICT_WORDS[report.verdict])}</span>: {_e(title)}</h3>'
        f"{ai_html}{score}<ul class=\"plain\">{reasons}</ul>{sections}"
        f'<details class="evidence"><summary>Patch and checks</summary>'
        f"<pre><code>{_e(report.diff_text)}</code></pre>"
        f'<p class="small">Checks run on the patched copy: {_e(checks)}</p>'
        f'<ul class="plain small">{limits}</ul></details>'
        "</article>"
    )


def _fixes(fixes: Sequence[FixVerificationReport | AIFixReport]) -> str:
    if not fixes:
        return ""
    cards: list[str] = []
    for item in fixes:
        if isinstance(item, AIFixReport):
            target = item.finding_location or "unknown location"
            if item.status == AIFixStatus.PROPOSED and item.verification is not None:
                cards.append(
                    _fix_card(item.verification, title=f"AI fix for {target}", ai=item)
                )
            else:
                errors = "".join(f"<li>{_e(error)}</li>" for error in item.errors)
                cards.append(
                    f'<article class="fix not_verified"><h3>No AI fix: {_e(target)}</h3>'
                    f'<ul class="plain">{errors}</ul></article>'
                )
        else:
            files = ", ".join(item.patch_files) or "patch"
            cards.append(_fix_card(item, title=files))
    return (
        "<h2>Fixes checked</h2>"
        '<p class="lede">Each patch was applied to an isolated copy and scanned again. '
        "The repository itself was not changed.</p>" + "".join(cards)
    )


def render_report(
    scan: RepositoryScanResult,
    *,
    repo_name: str,
    generated_at: datetime,
    snippets: dict[str, str] | None = None,
    timeline: TimelineReport | None = None,
    timeline_note: str | None = None,
    fixes: Sequence[FixVerificationReport | AIFixReport] = (),
) -> str:
    """Build the complete HTML document."""
    headline, risk_class = _verdict_sentence(scan)
    languages = ", ".join(scan.languages) or "no supported languages detected"
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'sha256-{SCRIPT_HASH}'; img-src data:; base-uri 'none'; form-action 'none'"
    )
    body = (
        '<header class="masthead">'
        f"<span><strong>SilentSec</strong> security debt report for {_e(repo_name)}</span>"
        f"<span>{_e(generated_at.strftime('%d %b %Y, %H:%M'))}</span></header>"
        '<section class="verdict">'
        f'<h1 class="{risk_class}">{_e(headline)}</h1>'
        f'<p class="lede">Scanned {_e(languages)} code in {_e(scan.repo_path)}. '
        "The score adds up each issue's severity and confidence, so every point can be traced "
        "to a finding below.</p>"
        f"{_composition(scan)}{_facts(scan)}{_scanners(scan)}</section>"
        f"{_findings(scan, snippets or {})}"
        f"{_patterns(scan)}"
        f"{_timeline(timeline, timeline_note)}"
        f"{_fixes(fixes)}"
        "<footer><p>Generated by SilentSec. Scanners find known patterns; a clean report is "
        "evidence, not proof, that code is secure. AI output is advisory and needs human "
        "review. Secret values are never shown.</p></footer>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>SilentSec report: {_e(repo_name)}</title>"
        f"<style>{STYLE}</style></head>"
        f"<body><main>{body}</main><script>{SCRIPT}</script></body></html>\n"
    )
