"""Extract repository-local Python import dependencies."""

import ast
import os
from pathlib import Path

from pydantic import BaseModel, Field

EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    "node_modules",
    "vendor",
}


class ImportDependency(BaseModel):
    """One Python import relationship found in a repository."""

    source_file: str
    source_module: str
    imported_module: str
    imported_names: list[str] = Field(default_factory=list)
    is_relative: bool = False


class ImportAnalysisResult(BaseModel):
    """Deterministic summary of repository-local Python dependencies."""

    dependencies: list[ImportDependency] = Field(default_factory=list)
    analyzed_files: int = 0
    skipped_files: int = 0


def _module_name(relative_path: Path) -> str:
    """Convert a Python path into a dotted module name."""
    parts = list(relative_path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)

def module_name_for_file(
    file_path: str | Path,
    repo_root: str | Path,
) -> str | None:
    """Map a repository-relative Python file path to its module name."""
    root = Path(repo_root).expanduser().resolve()
    package_root = root / "src"
    uses_src_layout = package_root.is_dir()

    if uses_src_layout:
        root = package_root

    path = Path(file_path)

    if path.is_absolute():
        try:
            path = path.resolve().relative_to(root)
        except (OSError, ValueError):
            return None
    else:
        path = Path(*path.parts)

        # Finding paths may include the src/ prefix even though root
        # already points to the src directory.
        if uses_src_layout and path.parts and path.parts[0] == "src":
            path = Path(*path.parts[1:])

    if path.suffix != ".py" or ".." in path.parts:
        return None

    return _module_name(path)

def _resolve_relative_import(
    source_module: str,
    is_package: bool,
    module: str | None,
    level: int,
) -> str:
    """Resolve a relative import to a repository-style module name."""
    parts = source_module.split(".") if source_module else []
    if not is_package and parts:
        parts.pop()

    # level=1 means current package; each additional dot moves up one level.
    for _ in range(max(0, level - 1)):
        if parts:
            parts.pop()

    if module:
        parts.extend(module.split("."))

    return ".".join(parts)


def analyze_python_imports(
    repo_root: str | Path,
) -> ImportAnalysisResult:
    """Extract imports between Python modules inside a repository.

    Third-party and standard-library imports are excluded from the dependency
    graph. Invalid or unreadable Python files are skipped safely.
    """
    root = Path(repo_root).expanduser().resolve()
    package_root = root / "src"
    if package_root.is_dir():
        root = package_root
    if not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {repo_root}")

    python_files: list[Path] = []
    for current_dir, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in EXCLUDED_DIRECTORIES
        )
        base = Path(current_dir)
        python_files.extend(
            base / filename
            for filename in sorted(filenames)
            if filename.endswith(".py")
        )

    module_to_path = {
        _module_name(path.relative_to(root)): path
        for path in python_files
    }
    package_modules = {
        _module_name(path.relative_to(root))
        for path in python_files
        if path.name == "__init__.py"
    }

    dependencies: set[tuple[str, str, tuple[str, ...], bool, str]] = set()
    skipped_files = 0

    for path in sorted(python_files):
        relative_path = path.relative_to(root)
        source_module = _module_name(relative_path)
        source_is_package = path.name == "__init__.py"

        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(relative_path))
        except (OSError, UnicodeError, SyntaxError, ValueError):
            skipped_files += 1
            continue

        for node in ast.walk(tree):
            imported_names: list[str] = []
            is_relative = False

            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = alias.name
                    resolved = next(
                        (
                            candidate
                            for candidate in sorted(
                                module_to_path,
                                key=lambda value: (-len(value.split(".")), value),
                            )
                            if target == candidate or target.startswith(candidate + ".")
                        ),
                        None,
                    )
                    if resolved is not None:
                        dependencies.add(
                            (
                                relative_path.as_posix(),
                                source_module,
                                resolved,
                                (),
                                False,
                            )
                        )

            elif isinstance(node, ast.ImportFrom):
                is_relative = node.level > 0
                if is_relative:
                    target = _resolve_relative_import(
                        source_module,
                        source_is_package,
                        node.module,
                        node.level,
                    )
                else:
                    target = node.module or ""

                imported_names = sorted(
                    alias.name for alias in node.names if alias.name != "*"
                )

                # Prefer the deepest known repository module matching the
                # import. For "from package import module", also check whether
                # the imported name itself identifies a local module.
                candidates = [target] if target else []
                candidates.extend(
                    f"{target}.{name}"
                    for name in imported_names
                    if target
                )
                resolved = next(
                    (
                        candidate
                        for candidate in sorted(
                            set(candidates),
                            key=lambda value: (-len(value.split(".")), value),
                        )
                        if candidate in module_to_path
                        or candidate in package_modules
                    ),
                    None,
                )

                if resolved is not None:
                    dependencies.add(
                        (
                            relative_path.as_posix(),
                            source_module,
                            resolved,
                            tuple(imported_names),
                            is_relative,
                        )
                    )

    records = [
        ImportDependency(
            source_file=source_file,
            source_module=source_module,
            imported_module=imported_module,
            imported_names=list(imported_names),
            is_relative=is_relative,
        )
        for (
            source_file,
            source_module,
            imported_module,
            imported_names,
            is_relative,
        ) in sorted(dependencies)
    ]

    return ImportAnalysisResult(
        dependencies=records,
        analyzed_files=len(python_files) - skipped_files,
        skipped_files=skipped_files,
    )
