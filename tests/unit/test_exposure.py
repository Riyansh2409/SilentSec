"""Exposure: reachability from web entry points in the call graph."""

import json
from pathlib import Path

import pytest

from silentsec import cli
from silentsec.api.app import _issues
from silentsec.architecture.exposure import analyze_exposure
from silentsec.report import render_report
from silentsec.report.sarif import scan_to_sarif
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

FLASK_APP = b'''import sqlite3

from flask import Flask, request

app = Flask(__name__)


def run_query(sql):
    return sqlite3.connect("x.db").execute(sql)


def search_products(term):
    return run_query(f"SELECT * FROM products WHERE name = '{term}'")


def find_user(user_id):
    return run_query("SELECT * FROM users WHERE id = ?")


@app.route("/search")
def search():
    return search_products(request.args["q"])
'''
# Line numbers in FLASK_APP: run_query 8-9, search_products 12-13, find_user 16-17.
SQL_LINE = 13
UNUSED_LINE = 17


def write_repo(root: Path, files: dict[str, bytes]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


def by_name(analysis):
    return {function.qualname: function for function in analysis.functions}


# --- analysis ----------------------------------------------------------------


def test_route_to_helper_to_sink_is_reachable_with_shortest_path(tmp_path: Path):
    analysis = analyze_exposure(write_repo(tmp_path, {"app/db.py": FLASK_APP}))
    functions = by_name(analysis)

    assert analysis.web_framework_detected and analysis.complete
    assert analysis.entry_points == ["GET /search"]
    assert functions["search"].entry_point == "GET /search"
    assert functions["search_products"].exposure == "reachable"
    assert functions["run_query"].path == [
        "GET /search -> search()",
        "search() -> search_products()",
        "search_products() -> run_query()",
    ]


def test_unused_helper_is_not_reachable(tmp_path: Path):
    functions = by_name(analyze_exposure(write_repo(tmp_path, {"app/db.py": FLASK_APP})))

    assert functions["find_user"].exposure == "not_reachable"
    assert functions["find_user"].path == []


def test_fastapi_and_flask_decorators_are_entry_points(tmp_path: Path):
    write_repo(tmp_path, {
        "api.py": b'''from fastapi import APIRouter, FastAPI

app = FastAPI()
items = APIRouter()


@app.get("/items/{item_id}")
async def read_item(item_id):
    return item_id


@items.post(path="/items")
def create_item():
    return 1


@app.delete("/items/{item_id}")
def delete_item(item_id):
    return 1
''',
        "views.py": b'''from flask import Blueprint

bp = Blueprint("views", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    return 1


@bp.route("/")
def index():
    return 1
''',
    })

    analysis = analyze_exposure(tmp_path)

    assert analysis.entry_points == [
        "DELETE /items/{item_id}",
        "GET /",
        "GET /items/{item_id}",
        "GET,POST /login",
        "POST /items",
    ]
    assert all(function.exposure == "reachable" for function in analysis.functions)


def test_calls_are_resolved_across_repository_modules(tmp_path: Path):
    write_repo(tmp_path, {
        "src/shop/__init__.py": b"",
        "src/shop/helpers.py": b"def run(sql):\n    return sql\n\n\ndef unused():\n    return 0\n",
        "src/shop/queries.py": b"def lookup(term):\n    return term\n",
        "src/shop/web.py": b'''from flask import Flask

from . import queries
from .helpers import run as execute

app = Flask(__name__)


@app.route("/a")
def a():
    return execute(queries.lookup("x"))
''',
    })

    functions = by_name(analyze_exposure(tmp_path))

    assert functions["run"].path == ["GET /a -> a()", "a() -> run()"]
    assert functions["lookup"].exposure == "reachable"
    assert functions["unused"].exposure == "not_reachable"
    assert functions["run"].file_path == "src/shop/helpers.py"


def test_ambiguous_names_link_all_candidates(tmp_path: Path):
    write_repo(tmp_path, {"app.py": b'''from flask import Flask

app = Flask(__name__)


class Order:
    def save(self):
        return 1


class Invoice:
    def save(self):
        return 2

    def archive(self):
        return 3


@app.post("/orders")
def create(model):
    return model.save()
'''})

    analysis = analyze_exposure(tmp_path)
    functions = by_name(analysis)

    # The receiver's type is unknown, so both save() methods are linked.
    assert functions["Order.save"].exposure == "reachable"
    assert functions["Invoice.save"].exposure == "reachable"
    assert functions["Invoice.archive"].exposure == "not_reachable"
    assert any("all of them are linked" in item for item in analysis.limitations)


def test_self_calls_prefer_the_same_class(tmp_path: Path):
    write_repo(tmp_path, {"app.py": b'''from flask import Flask

app = Flask(__name__)


class A:
    def handle(self):
        return self.helper()

    def helper(self):
        return 1


class B:
    def helper(self):
        return 2


@app.get("/")
def index():
    return A().handle()
'''})

    functions = by_name(analyze_exposure(tmp_path))

    assert functions["A.helper"].exposure == "reachable"
    assert functions["B.helper"].exposure == "not_reachable"


def test_recursion_and_cycles_do_not_hang(tmp_path: Path):
    write_repo(tmp_path, {"app.py": b'''from flask import Flask

app = Flask(__name__)


def ping(n):
    return pong(n - 1)


def pong(n):
    return ping(n) if n else walk(n)


def walk(n):
    return walk(n - 1) if n else 0


@app.get("/")
def index():
    return ping(3)
'''})

    functions = by_name(analyze_exposure(tmp_path, timeout_seconds=5))

    assert functions["walk"].path == [
        "GET / -> index()", "index() -> ping()", "ping() -> pong()", "pong() -> walk()"
    ]


def test_chains_longer_than_the_limit_are_unknown(tmp_path: Path):
    chain = "".join(f"\n\ndef f{i}():\n    return f{i + 1}()\n" for i in range(12))
    source = 'from flask import Flask\n\napp = Flask(__name__)\n' + chain + (
        '\n\ndef f12():\n    return 0\n\n\n@app.get("/")\ndef index():\n    return f0()\n'
    )
    write_repo(tmp_path, {"app.py": source.encode()})

    analysis = analyze_exposure(tmp_path, max_path_length=8)
    functions = by_name(analysis)

    assert len(functions["f6"].path) == 8 and functions["f6"].exposure == "reachable"
    # Beyond the limit nothing can be claimed either way.
    assert functions["f7"].exposure == "unknown"
    assert any("longer than 8" in item for item in analysis.limitations)


def test_main_block_is_an_entry_point(tmp_path: Path):
    write_repo(tmp_path, {"app.py": b'''from flask import Flask

app = Flask(__name__)


def seed():
    return 1


if __name__ == "__main__":
    seed()
    app.run()
'''})

    analysis = analyze_exposure(tmp_path)

    assert analysis.entry_points == ["__main__ in app.py"]
    assert by_name(analysis)["seed"].path == ["__main__ in app.py -> seed()"]


def test_without_a_web_framework_everything_is_unknown(tmp_path: Path):
    write_repo(tmp_path, {"tool.py": b"def helper():\n    return 1\n\n\nif __name__ == '__main__':\n    helper()\n"})

    analysis = analyze_exposure(tmp_path)

    assert not analysis.web_framework_detected
    assert [function.exposure for function in analysis.functions] == ["unknown"]


def test_function_limit_makes_not_reachable_unknown(tmp_path: Path):
    write_repo(tmp_path, {"app/db.py": FLASK_APP, "zz_more.py": b"def a():\n    return 1\n"})

    analysis = analyze_exposure(tmp_path, max_functions=4)

    assert not analysis.complete
    assert {function.exposure for function in analysis.functions} == {"reachable", "unknown"}


def test_function_at_returns_the_innermost_function(tmp_path: Path):
    write_repo(tmp_path, {"m.py": b"def outer():\n    def inner():\n        return 1\n    return inner()\n"})

    analysis = analyze_exposure(tmp_path)

    assert analysis.function_at("m.py", 3).qualname == "outer.inner"
    assert analysis.function_at("m.py", 4).qualname == "outer"
    assert analysis.function_at("other.py", 3) is None


# --- scoring -----------------------------------------------------------------


def finding(line: int, *, category=FindingCategory.SECURITY, rule="sql", tool="semgrep") -> Finding:
    return Finding(
        fingerprint=f"{tool}|{rule}|{line}",
        tool=tool,
        rule_id=rule,
        file_path="app/db.py",
        start_line=line,
        category=category,
        severity=Severity.HIGH,
        message=f"{rule} message",
        cwe_id="CWE-89" if category == FindingCategory.SECURITY else None,
        confidence=0.9,
    )


@pytest.fixture
def flask_repo(tmp_path: Path) -> Path:
    return write_repo(tmp_path, {"app/db.py": FLASK_APP})


def test_reachable_security_finding_counts_more_and_explains_why(flask_repo: Path):
    report = score_findings([finding(SQL_LINE)], repo_root=str(flask_repo))
    item = report.scored_findings[0]

    assert item.exposure == "reachable"
    assert item.exposure_factor == 1.25
    assert item.score == pytest.approx(15 * 0.95 * 1.25, abs=0.001)
    assert item.exposure_path == ["GET /search -> search()", "search() -> search_products()"]
    assert "Reachable from GET /search via search() -> search_products(): x1.25" in item.explanation
    assert "does not prove the issue is exploitable" in item.explanation


def test_unreachable_and_unknown_findings_are_not_increased(flask_repo: Path):
    report = score_findings(
        [finding(UNUSED_LINE, rule="a"), finding(1, rule="b")], repo_root=str(flask_repo)
    )
    items = {item.finding.rule_id: item for item in report.scored_findings}

    assert items["a"].exposure == "not_reachable" and items["a"].exposure_factor == 1.0
    assert "Not reachable from a detected web route" in items["a"].explanation
    # Line 1 is outside any function.
    assert items["b"].exposure == "unknown" and items["b"].score == pytest.approx(14.25)


def test_architecture_findings_are_never_exposed(flask_repo: Path):
    architecture = finding(SQL_LINE, category=FindingCategory.ARCHITECTURE, rule="SSEC-ARCH-002",
                           tool="silentsec-arch")
    report = score_findings([architecture], repo_root=str(flask_repo))
    item = report.scored_findings[0]

    assert item.exposure == "unknown" and item.exposure_factor == 1.0
    assert item.score == pytest.approx(14.25)
    assert "Reachable" not in item.explanation


def test_exposure_component_and_cap(flask_repo: Path):
    report = score_findings([finding(SQL_LINE)], repo_root=str(flask_repo))
    components = {component.name: component for component in report.components}

    assert components["exposure"].points == pytest.approx(15 * 0.95 * 0.25, abs=0.001)
    assert components["security_severity"].points == pytest.approx(14.25)
    assert sum(c.points for c in report.components if not c.informational) == pytest.approx(report.score)

    many = [finding(SQL_LINE, rule=f"r{i}") for i in range(10)]
    capped = score_findings(many, repo_root=str(flask_repo))
    assert capped.score == 100.0
    assert capped.raw_score == pytest.approx(10 * 15 * 0.95 * 1.25, abs=0.01)


def test_without_repo_root_exposure_is_unknown():
    item = score_findings([finding(SQL_LINE)]).scored_findings[0]

    assert item.exposure == "unknown" and item.score == pytest.approx(14.25)


# --- output ------------------------------------------------------------------


def scan_of(repo: Path, findings: list[Finding]) -> RepositoryScanResult:
    return RepositoryScanResult(
        repo_path=str(repo),
        languages=["Python"],
        status=ScannerStatus.SUCCESS,
        scanners=[ScannerRunResult(scanner="semgrep", status=ScannerStatus.SUCCESS, duration_seconds=0)],
        findings=findings,
        duration_seconds=0,
        security_debt=score_findings(findings, repo_root=str(repo)),
        security_debt_complete=True,
    )


def test_cli_tags_reachable_findings(flask_repo: Path):
    text = cli.format_summary(scan_of(flask_repo, [finding(SQL_LINE), finding(UNUSED_LINE, rule="u")]))

    assert "app/db.py:13  sql  [reachable]" in text
    assert "app/db.py:17  u\n" in text + "\n"


def test_api_issue_has_exposure_fields(flask_repo: Path):
    issue = _issues(scan_of(flask_repo, [finding(SQL_LINE)]), {})[0]

    assert issue.exposure == "reachable"
    assert issue.exposure_path == ["GET /search -> search()", "search() -> search_products()"]


def test_sarif_has_exposure_property(flask_repo: Path):
    document = scan_to_sarif(scan_of(flask_repo, [finding(SQL_LINE), finding(UNUSED_LINE, rule="u")]))
    results = {result["ruleId"].split("/")[-1]: result for result in document["runs"][0]["results"]}

    assert results["sql"]["properties"]["exposure"] == "reachable"
    assert results["sql"]["properties"]["exposurePath"][0] == "GET /search -> search()"
    assert results["u"]["properties"]["exposure"] == "not_reachable"
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parent.parent / "schemas" / "sarif-schema-2.1.0.json"
    jsonschema.validate(document, json.loads(schema_path.read_text(encoding="utf-8")))


def test_report_shows_badge_and_path(flask_repo: Path):
    from datetime import datetime

    document = render_report(
        scan_of(flask_repo, [finding(SQL_LINE), finding(UNUSED_LINE, rule="u")]),
        repo_name="demo",
        generated_at=datetime(2026, 10, 31, 12, 0),
    )

    assert document.count(">Reachable from the web</span>") == 1
    assert "<li>search() -&gt; search_products()</li>" in document
    assert "does not prove the issue is exploitable" in document
