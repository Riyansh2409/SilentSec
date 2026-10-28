from pathlib import Path

from silentsec.architecture.import_analyzer import (
    analyze_python_imports,
    module_name_for_file,
)


def test_detects_internal_import(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import services.auth\n",
        encoding="utf-8",
    )
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "services" / "auth.py").write_text(
        "def login():\n    pass\n",
        encoding="utf-8",
    )

    result = analyze_python_imports(tmp_path)

    assert result.analyzed_files == 3
    assert result.skipped_files == 0
    assert len(result.dependencies) == 1
    assert result.dependencies[0].source_file == "app.py"
    assert result.dependencies[0].imported_module == "services.auth"


def test_detects_relative_import(tmp_path: Path):
    package = tmp_path / "myapp"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "utils.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "main.py").write_text(
        "from . import utils\n",
        encoding="utf-8",
    )

    result = analyze_python_imports(tmp_path)

    assert any(
        dependency.source_file == "myapp/main.py"
        and dependency.imported_module == "myapp.utils"
        and dependency.is_relative
        for dependency in result.dependencies
    )


def test_ignores_external_imports(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import os\nimport requests\nfrom pydantic import BaseModel\n",
        encoding="utf-8",
    )

    result = analyze_python_imports(tmp_path)

    assert result.dependencies == []
    assert result.analyzed_files == 1


def test_skips_invalid_python_file(tmp_path: Path):
    (tmp_path / "valid.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "invalid.py").write_text("def broken(:\n", encoding="utf-8")

    result = analyze_python_imports(tmp_path)

    assert result.analyzed_files == 1
    assert result.skipped_files == 1


def test_dependency_order_is_deterministic(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import z_module\nimport a_module\n",
        encoding="utf-8",
    )
    (tmp_path / "z_module.py").write_text("", encoding="utf-8")
    (tmp_path / "a_module.py").write_text("", encoding="utf-8")

    first = analyze_python_imports(tmp_path)
    second = analyze_python_imports(tmp_path)

    assert first.model_dump() == second.model_dump()
    assert [
        dependency.imported_module for dependency in first.dependencies
    ] == ["a_module", "z_module"]

def test_maps_src_layout_file_to_module(tmp_path: Path):
    source_file = tmp_path / "src" / "silentsec" / "scoring" / "engine.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("", encoding="utf-8")

    assert (
        module_name_for_file("src/silentsec/scoring/engine.py", tmp_path)
        == "silentsec.scoring.engine"
    )


def test_maps_package_init_to_package_module(tmp_path: Path):
    package_init = tmp_path / "src" / "silentsec" / "scoring" / "__init__.py"
    package_init.parent.mkdir(parents=True)
    package_init.write_text("", encoding="utf-8")

    assert (
        module_name_for_file("src/silentsec/scoring/__init__.py", tmp_path)
        == "silentsec.scoring"
    )


def test_rejects_file_outside_repository(tmp_path: Path):
    outside_file = tmp_path.parent / "outside.py"

    assert module_name_for_file(outside_file, tmp_path) is None

def test_detects_imports_in_bom_prefixed_file(tmp_path: Path):
    (tmp_path / "app.py").write_bytes(
        b"\xef\xbb\xbf" + b"import services\n"
    )
    (tmp_path / "services.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )

    result = analyze_python_imports(tmp_path)

    assert result.analyzed_files == 2
    assert result.skipped_files == 0
    assert any(
        dependency.source_file == "app.py"
        and dependency.imported_module == "services"
        for dependency in result.dependencies
    )
