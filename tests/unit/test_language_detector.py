
from pathlib import Path

import pytest

from silentsec.languages import detect_languages


def test_detects_multiple_languages(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "app.ts").write_text("const app = 1;", encoding="utf-8")
    (tmp_path / "Main.java").write_text(
        "class Main {}",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        "package main",
        encoding="utf-8",
    )

    result = detect_languages(tmp_path)

    assert result.total_source_files == 4
    assert result.language_counts == {
        "Go": 1,
        "Java": 1,
        "Python": 1,
        "TypeScript": 1,
    }


def test_returns_relative_file_paths(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "print('hello')",
        encoding="utf-8",
    )

    result = detect_languages(tmp_path)

    assert result.files_by_language["Python"] == ["src/main.py"]


def test_ignores_dependency_directories(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('app')", encoding="utf-8")

    dependency_dir = tmp_path / "node_modules" / "example"
    dependency_dir.mkdir(parents=True)
    (dependency_dir / "index.js").write_text(
        "console.log('dependency')",
        encoding="utf-8",
    )

    result = detect_languages(tmp_path)

    assert result.total_source_files == 1
    assert result.languages == ["Python"]


def test_ignores_unknown_file_extensions(tmp_path: Path):
    (tmp_path / "README.txt").write_text("Documentation", encoding="utf-8")

    result = detect_languages(tmp_path)

    assert result.total_source_files == 0
    assert result.languages == []


def test_rejects_nonexistent_repository(tmp_path: Path):
    missing_path = tmp_path / "missing-repository"

    with pytest.raises(ValueError, match="Repository directory"):
        detect_languages(missing_path)
