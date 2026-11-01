import pytest

pytest.importorskip("sqlalchemy")

from silentsec.platform.analysis import graph, normalized_tokens, patterns, safe_text, shingles


def test_tokens_normalize_identifiers_literals_and_comments():
    assert normalized_tokens("x = 'secret-a' # comment\n") == normalized_tokens(
        "another = 'secret-b'\n"
    )
    assert shingles("def f(a):\n return a + 100\n") == shingles(
        "def renamed(b):\n return b + 200\n"
    )
    assert "execute" in normalized_tokens("cursor.execute(query)")


def test_redaction_preserves_normal_names_and_withholds_opaque_tokens():
    assert safe_text("integration-demo.zip") == "integration-demo.zip"
    rule = "silentsec.python.sql-injection.formatted-query"
    assert safe_text(rule) == rule
    assert "ghp_" not in safe_text("ghp_abcdefghijklmnopqrstuv.zip")
    opaque = "".join(chr(i) for i in range(65, 91)) + "".join(str(i) for i in range(10))
    assert safe_text(opaque) == "[REDACTED]"


def test_graph_overlay_keeps_highest_severity_and_names_are_redacted():
    from silentsec.platform.jobs import job_view
    from silentsec.platform.models import ScanJob
    from silentsec.platform.runner import highest_severities

    assert highest_severities(
        [{"file_path": "app.py", "severity": "high"}, {"file_path": "app.py", "severity": "low"}]
    ) == {"app.py": "high"}
    job = ScanJob(
        id="example",
        source_name="ghp_abcdefghijklmnopqrstuv.zip",
        source_kind="upload",
        status="queued",
    )
    assert "ghp_" not in job_view(job)["source_name"]


def test_graph_import_cycles_routes_and_static_only(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "a.py").write_text(
        f"import b\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/search')\ndef search():\n return helper()\ndef helper():\n return 1\n"
    )
    (tmp_path / "b.py").write_text("import a\n")
    result = graph(tmp_path, detail=True)
    assert result["version"] == "1"
    assert any(n["kind"] == "route" for n in result["nodes"])
    assert any(e["kind"] == "calls" for e in result["edges"])
    assert result["metrics"]["cycle_edges"]
    assert not marker.exists()


def test_patterns_deterministic_advisory_and_no_literal_evidence(tmp_path):
    content = "def one(value):\n try:\n  return value + 1\n except Exception:\n  pass\n\ndef two(other):\n try:\n  return other + 2\n except Exception:\n  pass\n"
    (tmp_path / "app.py").write_text(content)
    (tmp_path / ".env.py").write_text("token = 'ghp_abcdefghijklmnopqrstuv'")
    first, second = patterns(tmp_path), patterns(tmp_path)
    assert first == second
    assert first["advisory"] and not first["affects_score"]
    assert first["matches"][0]["classification"] == "exception_suppression"
    assert "ghp_" not in str(first)
    assert "fingerprints" not in str(first)
