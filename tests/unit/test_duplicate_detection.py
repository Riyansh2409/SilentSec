"""SSEC-ARCH-005: structurally identical functions."""

from pathlib import Path

from silentsec.architecture.analyzer import run_architecture_analyzer
from silentsec.scanners.results import ScannerStatus
from silentsec.scoring import score_findings

ORIGINAL = '''
def load_users(conn, limit):
    """Load active users."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE active = 1")
    rows = cursor.fetchmany(limit)
    result = []
    for row in rows:
        result.append(row[0])
    cursor.close()
    return result
'''

# Same logic with renamed variables, other literals, a type hint and no docstring.
RENAMED_CLONE = '''
def load_orders(db, count: int) -> list:
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE paid = 0")
    items = cur.fetchmany(count)
    out = []
    for item in items:
        out.append(item[1])
    cur.close()
    return out
'''


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def duplicates(root: Path):
    result = run_architecture_analyzer(root)
    assert result.status == ScannerStatus.SUCCESS, result.errors
    return [finding for finding in result.findings if finding.rule_id == "SSEC-ARCH-005"]


def test_renamed_clone_in_another_file_is_detected(tmp_path: Path):
    found = duplicates(write(tmp_path, {"users.py": ORIGINAL, "orders.py": RENAMED_CLONE}))

    assert len(found) == 1
    finding = found[0]
    assert finding.file_path == "orders.py"
    assert "'load_users' at users.py:2" in finding.message
    assert finding.severity.value == "low"
    assert finding.category.value == "maintainability"
    assert finding.end_line > finding.start_line


def test_different_attribute_call_is_not_a_clone(tmp_path: Path):
    different = RENAMED_CLONE.replace("fetchmany", "fetchall")

    assert duplicates(write(tmp_path, {"users.py": ORIGINAL, "orders.py": different})) == []


def test_extra_statement_is_not_a_clone(tmp_path: Path):
    different = RENAMED_CLONE.replace("    cur.close()\n", "    cur.close()\n    db.commit()\n")

    assert duplicates(write(tmp_path, {"users.py": ORIGINAL, "orders.py": different})) == []


def test_small_functions_are_ignored(tmp_path: Path):
    small = "def get_a(x):\n    return x.a\n\n\ndef get_b(y):\n    return y.b\n"
    same = "def one(x):\n    return x.a\n\n\ndef two(x):\n    return x.a\n"

    assert duplicates(write(tmp_path, {"a.py": small, "b.py": same})) == []


def test_three_copies_give_one_finding(tmp_path: Path):
    third = RENAMED_CLONE.replace("load_orders", "load_items")
    found = duplicates(
        write(tmp_path, {"a.py": ORIGINAL, "b.py": RENAMED_CLONE, "c.py": third})
    )

    assert len(found) == 1
    assert "2 other function(s)" in found[0].message


def test_methods_in_classes_are_compared(tmp_path: Path):
    method = "class Repo:\n" + "".join(
        "    " + line if line else line for line in ORIGINAL.replace("(conn,", "(self, conn,").splitlines(True)
    )
    other = "class Store:\n" + "".join(
        "    " + line if line else line
        for line in RENAMED_CLONE.replace("(db,", "(self, db,").splitlines(True)
    )

    assert len(duplicates(write(tmp_path, {"a.py": method, "b.py": other}))) == 1


def test_nested_duplicate_inside_reported_duplicate_is_not_repeated(tmp_path: Path):
    outer = "def outer(conn, limit):\n" + "".join(
        "    " + line if line else line for line in ORIGINAL.splitlines(True)
    ) + "    return load_users(conn, limit)\n"
    renamed = outer.replace("outer", "wrapper")

    found = duplicates(write(tmp_path, {"a.py": outer, "b.py": renamed}))

    assert len(found) == 1
    assert "'outer'" in found[0].message or "'wrapper'" in found[0].message


def test_duplicate_detection_is_deterministic(tmp_path: Path):
    root = write(tmp_path, {"users.py": ORIGINAL, "orders.py": RENAMED_CLONE})

    first = [(f.fingerprint, f.message) for f in duplicates(root)]
    second = [(f.fingerprint, f.message) for f in duplicates(root)]

    assert first == second


def test_duplicate_finding_counts_as_architecture_debt_with_medium_effort(tmp_path: Path):
    root = write(tmp_path, {"users.py": ORIGINAL, "orders.py": RENAMED_CLONE})

    report = score_findings(duplicates(root), repo_root=str(root))

    assert report.security_points == 0
    assert report.architecture_debt_points > 0
    assert report.scored_findings[0].remediation_effort == "medium"
