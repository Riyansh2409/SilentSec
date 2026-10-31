from silentsec.architecture.debt_views import build_debt_views
from silentsec.report.debt_views import render_debt_views
from silentsec.schemas.finding import Finding
from silentsec.scoring import score_findings


def finding(path, fingerprint, severity='high', status='open'):
    return Finding(
        fingerprint=fingerprint, tool='test', rule_id=fingerprint,
        file_path=path, start_line=1, category='security', severity=severity,
        status=status, message='Example', confidence=1,
    )


def test_totals_use_logical_open_findings_and_severity(tmp_path):
    a = finding('pkg/a.py', 'a')
    b = finding('pkg/b.py', 'b', 'low')
    report = score_findings([a, a, b, finding('pkg/c.py', 'c', status='fixed')])
    data = build_debt_views(report, tmp_path)
    assert [(r.path, r.points, r.issues) for r in data.files] == [
        ('pkg/a.py', 15, 1), ('pkg/b.py', 3, 1),
    ]
    assert data.folders[0].points == 18
    assert data.folders[0].files == 2
    assert data.folders[0].severity == 'high'


def test_import_direction_src_layout_and_no_execution(tmp_path):
    package = tmp_path / 'src' / 'pkg'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'a.py').write_text('from . import b\nraise RuntimeError("never execute")')
    (package / 'b.py').write_text('import os\n')
    data = build_debt_views(score_findings([finding('src/pkg/b.py', 'b')]), tmp_path)
    assert [(e.source, e.target) for e in data.edges] == [('pkg.a', 'pkg.b')]
    assert data.nodes[0].id == 'pkg.b'
    assert data.nodes[0].points == 15
    assert data.model_validate_json(data.model_dump_json()) == data


def test_graph_limits_and_invalid_files_are_disclosed(tmp_path):
    for i in range(65):
        (tmp_path / f'm{i}.py').write_text(f'import m{(i+1) % 65}\n')
    (tmp_path / 'broken.py').write_text('def (')
    data = build_debt_views(score_findings([]), tmp_path)
    assert len(data.nodes) == 60
    assert data.omitted_nodes == 5
    assert len(data.edges) + data.omitted_edges == 65
    assert data.skipped_python_files == 1
    assert all(e.source in {n.id for n in data.nodes} for e in data.edges)


def test_offline_output_escapes_paths_and_handles_empty_scan(tmp_path):
    data = build_debt_views(score_findings([finding('<img onerror=x>.py', 'x')]), tmp_path)
    html = render_debt_views(data)
    assert '<img onerror=x>' not in html
    assert '&lt;img onerror=x&gt;' in html
    assert 'viewBox=' in html
    assert 'No local Python import relationships' in html
    assert render_debt_views(None) == ''
    assert 'No scored open findings' in render_debt_views(
        build_debt_views(score_findings([]), tmp_path)
    )


def test_scan_survives_a_debt_view_failure(tmp_path, monkeypatch):
    import silentsec.scanners.scanner_service as service

    def boom(*args, **kwargs):
        raise RuntimeError("graph failed")

    monkeypatch.setattr(service, "build_debt_views", boom)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = service.scan_repository(tmp_path)
    assert result.debt_views is None
    assert any("Debt visualization skipped" in error for error in result.errors)
