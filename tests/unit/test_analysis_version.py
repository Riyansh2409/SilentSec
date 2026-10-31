from pathlib import Path

from silentsec.history import store as store_module
from silentsec.history.store import analysis_version


def test_analysis_version_changes_with_analysis_code(tmp_path: Path, monkeypatch):
    package = tmp_path / "silentsec"
    (package / "scoring").mkdir(parents=True)
    engine = package / "scoring" / "engine.py"
    engine.write_text("POINTS = 1\n", encoding="utf-8")
    monkeypatch.setattr(store_module, "_PACKAGE_DIR", package)
    before = analysis_version()

    engine.write_text("POINTS = 2\n", encoding="utf-8")
    changed = analysis_version()
    engine.write_bytes(b"POINTS = 2\r\n")  # a Windows checkout of the same code

    assert changed != before
    assert analysis_version() == changed


def test_analysis_version_ignores_bytecode_caches(tmp_path: Path, monkeypatch):
    package = tmp_path / "silentsec"
    package.mkdir()
    (package / "cli.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(store_module, "_PACKAGE_DIR", package)
    before = analysis_version()

    (package / "__pycache__").mkdir()
    (package / "__pycache__" / "cli.cpython-311.py").write_text("junk\n", encoding="utf-8")

    assert analysis_version() == before
