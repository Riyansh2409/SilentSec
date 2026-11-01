"""Offline, escaped visual summaries, also readable without JavaScript."""

from html import escape

from silentsec.architecture.debt_views import DebtViews

COLOURS = {
    'critical': '#9f1239', 'high': '#b91c1c', 'medium': '#a16207',
    'low': '#1d4ed8', 'info': '#475569', 'none': '#475569',
}


def _dependency_svg(selected: str, incoming: list[str], outgoing: list[str], nodes) -> str:
    """A bounded neighbourhood diagram with the full edge lists below it."""
    height = max(150, max(min(10, len(incoming)), min(10, len(outgoing))) * 55 + 40)
    middle = height / 2
    parts = [(f'<svg viewBox="0 0 1000 {height}" role="img" '
              f'aria-label="Imports around {escape(selected, quote=True)}">')]

    def node(name, x, y):
        severity = next((n.severity for n in nodes if n.id == name), 'none')
        label = name if len(name) < 33 else name[:29] + '…'
        return (
            f'<g><title>{escape(name)}</title><rect x="{x}" y="{y-20}" '
            f'width="280" height="40" rx="6" fill="white" '
            f'stroke="{COLOURS[severity]}" stroke-width="3"/>'
            f'<text x="{x+8}" y="{y+4}" font-size="12" fill="#172033">'
            f'{escape(label)}</text></g>'
        )

    for i, name in enumerate(incoming[:10]):
        y = 40 + i * 55
        parts.append(f'<path d="M290 {y} L360 {middle} l-9 -5 m9 5 l-9 5" '
                     'stroke="#64748b" fill="none"/>')
        parts.append(node(name, 10, y))
    for i, name in enumerate(outgoing[:10]):
        y = 40 + i * 55
        parts.append(f'<path d="M640 {middle} L710 {y} l-9 -5 m9 5 l-9 5" '
                     'stroke="#64748b" fill="none"/>')
        parts.append(node(name, 710, y))
    parts.append(node(selected, 360, middle))
    return ''.join(parts) + '</svg>'


def render_debt_views(data: DebtViews | None) -> str:
    if data is None:
        return ''
    parts = ['<section><h2>Debt and dependencies</h2>', f'<p>{escape(data.note)}</p>',
             '<h3>Top 10 files by debt</h3>']
    maximum = max((r.points for r in data.files), default=1) or 1
    for row in data.files[:10]:
        parts.append(
            f'<div><code>{escape(row.path)}</code> — {row.points:g} pts · '
            f'{row.issues} issues · {escape(row.severity)}'
            f'<svg viewBox="0 0 600 18" role="img" '
            f'aria-label="{escape(row.path, quote=True)}: {row.points:g} debt points">'
            f'<rect width="{row.points / maximum * 600:.2f}" height="16" '
            f'fill="{COLOURS[row.severity]}"/></svg></div>'
        )
    if not data.files:
        parts.append('<p>No scored open findings. Check scanner completeness.</p>')
    parts.append('<h3>Folder debt map</h3><div style="display:flex;flex-wrap:wrap;gap:12px">')
    for row in data.folders[:30]:
        parts.append(
            f'<div style="border:3px solid {COLOURS[row.severity]};padding:12px">'
            f'<code>{escape(row.path)}</code><br>{row.points:g} pts · '
            f'{row.issues} issues · {row.files} affected files · {row.severity}</div>'
        )
    parts.append('</div>')
    if len(data.folders) > 30:
        parts.append(f'<p>{len(data.folders) - 30} additional folders in JSON output.</p>')
    parts.append('<h3>Python dependency graph</h3><p>Expand a module: '
                 'incoming → selected → outgoing. Only retained edges are shown.</p>')
    if not data.nodes:
        parts.append('<p>No local Python import relationships detected.</p>')
    for node in data.nodes:
        incoming = [e.source for e in data.edges if e.target == node.id]
        outgoing = [e.target for e in data.edges if e.source == node.id]
        parts.append(
            f'<details><summary>{escape(node.id)} · {node.points:g} pts · '
            f'{node.issues} issues · {node.severity}</summary>'
            f'{_dependency_svg(node.id, incoming, outgoing, data.nodes)}'
            '<p>Diagram: up to 10 neighbours per side. Full retained connections below.</p>'
            '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">'
            f'<div>Incoming →<pre>{escape(chr(10).join(incoming) or "None")}</pre></div>'
            f'<div style="border:3px solid {COLOURS[node.severity]};padding:12px">'
            f'{escape(node.id)}</div>'
            f'<div>→ Outgoing<pre>{escape(chr(10).join(outgoing) or "None")}</pre></div>'
            '</div></details>'
        )
    parts.append(f'<p>Omitted: {data.omitted_nodes} nodes, {data.omitted_edges} edges. '
                 f'Unreadable/invalid Python files skipped: {data.skipped_python_files}.</p>')
    return ''.join(parts) + '</section>'
