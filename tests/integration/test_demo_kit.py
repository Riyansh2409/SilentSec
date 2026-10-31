"""The demo kit builds a repository whose gate and verify results are known."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from silentsec.gate import GateVerdict, run_gate

KIT = Path(__file__).resolve().parents[2] / "demo" / "make_demo.py"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(scope="module")
def demo(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("demo") / "shop"
    subprocess.run([sys.executable, str(KIT), str(root)], check=True, capture_output=True)
    return root


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def test_kit_creates_repository_branches_patches_and_zip(demo: Path):
    assert git(demo, "branch", "--show-current").strip() == "main"
    branches = git(demo, "branch", "--format=%(refname:short)").split()
    assert sorted(branches) == ["feature/bad-fix", "feature/good-fix", "main"]
    assert len(git(demo, "log", "--oneline", "main").splitlines()) == 4
    assert git(demo, "status", "--porcelain") == ""
    patches = demo.parent / "shop-patches"
    for name in ("good_fix.diff", "bad_fix.diff"):
        git(demo, "apply", "--check", str(patches / name))
    assert (demo.parent / "shop.zip").stat().st_size > 0


def test_kit_refuses_a_non_empty_folder(demo: Path):
    completed = subprocess.run(
        [sys.executable, str(KIT), str(demo)], capture_output=True, text=True, check=False
    )
    assert completed.returncode != 0
    assert "is not empty" in completed.stderr


@pytest.mark.skipif(
    shutil.which("semgrep") is None or shutil.which("bandit") is None,
    reason="needs the real Semgrep and Bandit",
)
def test_demo_gate_results_with_real_scanners(demo: Path):
    bad = run_gate(demo, base="main", head="feature/bad-fix")
    good = run_gate(demo, base="main", head="feature/good-fix")

    assert bad.verdict == GateVerdict.FAIL
    assert {item.rule_id.rsplit(".", 1)[-1] for item in bad.blocking} >= {"os-system"}
    assert good.verdict == GateVerdict.PASS
    assert good.score_after < good.score_before
