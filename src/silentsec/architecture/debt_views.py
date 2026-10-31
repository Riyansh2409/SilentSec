"""Presentation data derived from logical findings and static local imports."""

from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

from silentsec.architecture.import_analyzer import analyze_python_imports, module_name_for_file
from silentsec.scoring.engine import SecurityDebtReport

VIEW_NOTE = (
    "Points sum deduplicated open findings before repository and architecture caps; "
    "they need not sum to the repository score. Test/sample findings are included. "
    "Colours show highest finding severity, not remediation effort. "
    "Dependencies are static repository-local Python imports only; src-layout analysis "
    "covers src/. Dynamic and third-party imports are not covered. "
    "An import relationship is not evidence of a vulnerability."
)


class DebtLocation(BaseModel):
    path: str
    points: float = 0
    issues: int = 0
    files: int = 0
    severity: str = "none"


class DependencyNode(BaseModel):
    id: str
    points: float = 0
    issues: int = 0
    severity: str = "none"


class DependencyEdge(BaseModel):
    source: str
    target: str


class DebtViews(BaseModel):
    files: list[DebtLocation] = Field(default_factory=list)
    folders: list[DebtLocation] = Field(default_factory=list)
    nodes: list[DependencyNode] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    omitted_nodes: int = 0
    omitted_edges: int = 0
    skipped_python_files: int = 0
    note: str = VIEW_NOTE


def build_debt_views(report: SecurityDebtReport, root: Path) -> DebtViews:
    """Keep graph payload bounded and ordering stable; never execute source code."""
    ranks = {s: i for i, s in enumerate(['none', 'info', 'low', 'medium', 'high', 'critical'])}
    files: dict[str, DebtLocation] = {}
    for item in report.scored_findings:
        path = item.finding.file_path.replace('\\', '/')
        row = files.setdefault(path, DebtLocation(path=path, files=1))
        row.points += item.score
        row.issues += 1
        severity = item.finding.severity.value
        if ranks[severity] > ranks[row.severity]:
            row.severity = severity
    folders: dict[str, DebtLocation] = {}
    for row in files.values():
        parent = str(PurePosixPath(row.path).parent)
        folder = folders.setdefault(parent, DebtLocation(path=parent))
        folder.points += row.points
        folder.issues += row.issues
        folder.files += 1
        if ranks[row.severity] > ranks[folder.severity]:
            folder.severity = row.severity
    analysis = analyze_python_imports(root)
    edges = sorted({(d.source_module, d.imported_module) for d in analysis.dependencies})
    names = {name for edge in edges for name in edge}
    nodes = {name: DependencyNode(id=name) for name in names}
    for row in files.values():
        name = module_name_for_file(row.path, root)
        if name in nodes:
            nodes[name].points += row.points
            nodes[name].issues += row.issues
            if ranks[row.severity] > ranks[nodes[name].severity]:
                nodes[name].severity = row.severity
    ordered = sorted(nodes.values(), key=lambda n: (-n.points, n.id))[:60]
    retained = {n.id for n in ordered}
    visible = [(s, t) for s, t in edges if s in retained and t in retained][:200]
    for row in [*files.values(), *folders.values(), *ordered]:
        row.points = round(row.points, 2)
    return DebtViews(
        files=sorted(files.values(), key=lambda r: (-r.points, r.path)),
        folders=sorted(folders.values(), key=lambda r: (-r.points, r.path)),
        nodes=ordered,
        edges=[DependencyEdge(source=s, target=t) for s, t in visible],
        omitted_nodes=len(nodes) - len(ordered),
        omitted_edges=len(edges) - len(visible),
        skipped_python_files=analysis.skipped_files,
    )
