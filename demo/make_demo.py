r"""Create the SilentSec demo repository.

Usage:  python demo/make_demo.py <new folder>      e.g. python demo/make_demo.py C:\demo\shop

Creates a small, deliberately vulnerable app (the API key is fake) whose
four commits add security and architecture debt step by step, and next to
it a <folder>-patches folder and a <folder>.zip:

  main               4 commits; the 3rd ("Add admin tools (AI-generated)")
                     adds the most debt (Time Machine)
  feature/good-fix   fixes the SQL injection             -> gate PASS
  feature/bad-fix    fixes SQL but adds os.system()      -> gate FAIL
  good_fix.diff      the same fix as a patch             -> verify: VERIFIED FIX
  bad_fix.diff                                           -> verify: REGRESSION
  <folder>.zip       the main branch, for the API upload endpoints

Nothing here is executed; it is only scanned.
"""

import subprocess  # nosec B404 - runs git with fixed argument lists
import sys
from pathlib import Path

# Built from parts so this script itself is not flagged as a leaked secret.
FAKE_KEY = "ghp_" + "Zx9Qw" + "R7tYu1Io3Pa5Sd7Fg9Hj2Kl4Zx6Cv8Bn0Mq"

DB = '''import sqlite3


def connect():
    return sqlite3.connect("shop.db")


def find_user(user_id):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
'''

SEARCH = '''

def search_products(term):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
        return cursor.fetchall()
    except Exception:
        pass
'''

ADMIN = f'''import os

API_KEY = "{FAKE_KEY}"


def backup(folder):
    os.system("tar -czf backup.tgz " + folder)


def calculate(expression):
    return eval(expression)
'''

REPORTS = '''

def sales_report(rows):
    total = 0
    count = 0
    for row in rows:
        total += row["amount"]
        count += 1
    average = total / count if count else 0
    return {"total": total, "count": count, "average": average}


def refund_report(rows):
    total = 0
    count = 0
    for row in rows:
        total += row["amount"]
        count += 1
    average = total / count if count else 0
    return {"total": total, "count": count, "average": average}
'''

SQL_BAD = """cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")"""
SQL_GOOD = """cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{term}%",))"""
SQL_WITH_REGRESSION = (
    SQL_GOOD + '\n        os.system("echo searched " + term)'
)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))  # always LF, also on Windows


def git(repo: Path, *args: str) -> None:
    subprocess.run(  # nosec B603 B607 - git with a fixed argument list, no shell
        ["git", "-c", "user.name=SilentSec Demo", "-c", "user.email=demo@example.com",
         "-c", "core.autocrlf=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def make_patch(repo: Path, new_db: str, out: Path) -> None:
    db = repo / "app" / "db.py"
    original = db.read_bytes()
    write(db, new_db)
    git(repo, "diff", "--relative", f"--output={out}")
    db.write_bytes(original)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = Path(sys.argv[1]).expanduser().resolve()
    if repo.exists() and any(repo.iterdir()):
        sys.exit(f"{repo} is not empty. Choose a new folder.")
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")

    write(repo / "README.md", "# Demo shop\nA deliberately vulnerable demo app for SilentSec.\n")
    write(repo / "app" / "__init__.py", "")
    write(repo / "app" / "db.py", DB)
    commit(repo, "Initial shop app")

    write(repo / "app" / "db.py", DB + SEARCH)
    commit(repo, "Add product search (AI-generated)")

    write(repo / "app" / "admin.py", ADMIN)
    commit(repo, "Add admin tools (AI-generated)")

    write(repo / "app" / "reports.py", REPORTS)
    commit(repo, "Add sales and refund reports")

    full = DB + SEARCH
    patches = repo.parent / f"{repo.name}-patches"
    patches.mkdir(exist_ok=True)
    make_patch(repo, full.replace(SQL_BAD, SQL_GOOD), patches / "good_fix.diff")
    make_patch(
        repo,
        "import os\n" + full.replace(SQL_BAD, SQL_WITH_REGRESSION),
        patches / "bad_fix.diff",
    )

    for name in ("good", "bad"):
        git(repo, "switch", "-q", "-c", f"feature/{name}-fix", "main")
        git(repo, "apply", str(patches / f"{name}_fix.diff"))
        commit(repo, "Fix SQL search" + (" (AI suggestion)" if name == "bad" else ""))
    git(repo, "switch", "-q", "main")

    archive = repo.parent / f"{repo.name}.zip"
    git(repo, "archive", "--format=zip", "-o", str(archive), "main")

    print(f"Demo repo:  {repo}  (branches: main, feature/good-fix, feature/bad-fix)")
    print(f"Patches:    {patches / 'good_fix.diff'}")
    print(f"            {patches / 'bad_fix.diff'}")
    print(f"Zip:        {archive}")
    print()
    print("Try:")
    print(f"  cd {repo}")
    print("  silentsec scan .")
    print("  silentsec gate . --base main --head feature/bad-fix     # FAIL")
    print("  silentsec gate . --base main --head feature/good-fix    # PASS")
    print("  silentsec history . --commits 10")
    print("  silentsec report . --out ../report.html")


if __name__ == "__main__":
    main()
