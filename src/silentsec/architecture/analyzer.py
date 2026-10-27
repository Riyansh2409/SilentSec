
"""Deterministic AST-based architectural debt analysis for Python repositories."""

import ast
import os
from hashlib import sha256
from pathlib import Path
from time import perf_counter

from silentsec.architecture.import_analyzer import analyze_python_imports
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.schemas import Finding, FindingCategory, Severity

COMPLEXITY_LOW = 10
COMPLEXITY_MEDIUM = 20
MAX_FILE_BYTES = 256 * 1024

EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    "site-packages",
    ".tox",
    ".mypy_cache",
}

TOOL_NAME = "silentsec-arch"


def _discover_python_files(root: Path) -> list[Path]:
    """Find eligible Python files without following directory symlinks."""
    files: list[Path] = []

    for current_dir, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directories[:] = sorted(
            name
            for name in directories
            if name not in EXCLUDED_DIRECTORIES
            and not (Path(current_dir) / name).is_symlink()
        )

        base = Path(current_dir)
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                path = base / filename
                if not path.is_symlink():
                    files.append(path)

    return sorted(files)


class _SkippedPythonFile(Exception):
    """Raised when a source file should be skipped without a scan error."""


def _read_python_file(path: Path, root: Path) -> str:
    """Read a bounded, repository-local UTF-8 Python source file."""
    resolved = path.resolve(strict=True)
    resolved.relative_to(root)

    if not resolved.is_file():
        raise ValueError("Not a regular file")

    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise _SkippedPythonFile("File exceeds 256 KB limit")

    content = resolved.read_bytes()
    if b"\x00" in content:
        raise _SkippedPythonFile("File appears to be binary")

    return content.decode("utf-8")


def _make_finding(
    *,
    file_path: str,
    rule_id: str,
    start_line: int,
    end_line: int | None,
    category: FindingCategory,
    severity: Severity,
    message: str,
    confidence: float,
) -> Finding:
    """Create a normalized, deterministic architecture finding."""
    return Finding(
        fingerprint=sha256(
            f"{TOOL_NAME}|{rule_id}|{file_path}|{start_line}".encode()
        ).hexdigest(),
        tool=TOOL_NAME,
        rule_id=rule_id,
        file_path=file_path,
        start_line=max(1, start_line),
        end_line=max(start_line, end_line or start_line),
        category=category,
        severity=severity,
        message=message,
        confidence=confidence,
    )


def _handler_body_summary(handler: ast.ExceptHandler) -> str:
    """Describe handler actions without claiming that they are safe."""
    if not handler.body:
        return "empty handler body"

    actions: list[str] = []
    for statement in handler.body:
        if isinstance(statement, ast.Pass):
            actions.append("pass")
        elif (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        ):
            actions.append("...")
        elif isinstance(statement, ast.Continue):
            actions.append("continue")
        elif isinstance(statement, ast.Return) and statement.value is None:
            actions.append("return")
        elif isinstance(statement, ast.Raise):
            actions.append("raise")
        elif isinstance(statement, (ast.Call, ast.Expr)):
            actions.append(ast.unparse(statement)[:100])
        else:
            actions.append(type(statement).__name__)

    return "; ".join(actions)


def _is_swallowed_exception(handler: ast.ExceptHandler) -> bool:
    """Identify only handlers whose statements are all silent no-ops."""
    if not handler.body:
        return False

    allowed = (ast.Pass, ast.Continue)
    for statement in handler.body:
        if isinstance(statement, allowed):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        ):
            continue
        if isinstance(statement, ast.Return) and statement.value is None:
            continue
        return False

    return True


def _is_broad_exception(handler: ast.ExceptHandler) -> bool:
    """Detect bare handlers and handlers catching Exception/BaseException."""
    if handler.type is None:
        return True

    if isinstance(handler.type, ast.Name):
        return handler.type.id in {"Exception", "BaseException"}

    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(item, ast.Name)
            and item.id in {"Exception", "BaseException"}
            for item in handler.type.elts
        )

    return False


def _complexity(node: ast.AST) -> int:
    """Calculate deterministic McCabe-style complexity for one function."""
    score = 1

    class ComplexityVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            if child is node:
                for statement in child.body:
                    self.visit(statement)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            if child is node:
                for statement in child.body:
                    self.visit(statement)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, child: ast.Lambda) -> None:
            return

        def visit_If(self, child: ast.If) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_For(self, child: ast.For) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_AsyncFor(self, child: ast.AsyncFor) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_While(self, child: ast.While) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_ExceptHandler(self, child: ast.ExceptHandler) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_With(self, child: ast.With) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_Assert(self, child: ast.Assert) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_BoolOp(self, child: ast.BoolOp) -> None:
            nonlocal score
            score += len(child.values) - 1
            self.generic_visit(child)

        def visit_ListComp(self, child: ast.ListComp) -> None:
            nonlocal score
            score += sum(len(generator.ifs) for generator in child.generators)
            self.generic_visit(child)

        def visit_SetComp(self, child: ast.SetComp) -> None:
            nonlocal score
            score += sum(len(generator.ifs) for generator in child.generators)
            self.generic_visit(child)

        def visit_DictComp(self, child: ast.DictComp) -> None:
            nonlocal score
            score += sum(len(generator.ifs) for generator in child.generators)
            self.generic_visit(child)

        def visit_GeneratorExp(self, child: ast.GeneratorExp) -> None:
            nonlocal score
            score += sum(len(generator.ifs) for generator in child.generators)
            self.generic_visit(child)

        def visit_IfExp(self, child: ast.IfExp) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

        def visit_Match(self, child: ast.Match) -> None:
            self.generic_visit(child)

        def visit_match_case(self, child: ast.match_case) -> None:
            nonlocal score
            score += 1
            self.generic_visit(child)

    visitor = ComplexityVisitor()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for statement in node.body:
            visitor.visit(statement)
    else:
        visitor.visit(node)

    return score


def _collect_module_cycles(dependencies: list) -> list[list[str]]:
    """Return unique directed cycles, canonicalized by rotation."""
    graph: dict[str, set[str]] = {}

    for dependency in dependencies:
        source = dependency.source_module
        target = dependency.imported_module
        if source and target:
            graph.setdefault(source, set()).add(target)
            graph.setdefault(target, set())

    cycles: set[tuple[str, ...]] = set()

    def visit(start: str, current: str, path: list[str]) -> None:
        for neighbor in sorted(graph.get(current, set())):
            if neighbor == start and len(path) > 1:
                rotations = [
                    tuple(path[index:] + path[:index])
                    for index in range(len(path))
                ]
                cycles.add(min(rotations))
            elif neighbor > start and neighbor not in path:
                visit(start, neighbor, [*path, neighbor])

    for start in sorted(graph):
        visit(start, start, [start])

    return [list(cycle) for cycle in sorted(cycles)]


def run_architecture_analyzer(
    repo_path: str | Path,
    timeout_seconds: int = 180,
    *,
    complexity_low: int = COMPLEXITY_LOW,
    complexity_medium: int = COMPLEXITY_MEDIUM,
) -> ScannerRunResult:
    """Analyze Python architecture and maintainability without executing source."""
    started = perf_counter()
    root = Path(repo_path).expanduser().resolve()

    if not root.is_dir():
        return ScannerRunResult(
            scanner="architecture",
            status=ScannerStatus.FAILED,
            duration_seconds=0,
            errors=["Repository directory does not exist."],
        )

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if complexity_low <= 0 or complexity_medium <= complexity_low:
        raise ValueError("Complexity thresholds must be positive and increasing.")

    findings: list[Finding] = []
    errors: list[str] = []
    parsed: dict[str, ast.AST] = {}
    deadline = started + timeout_seconds
    timed_out = False

    for path in _discover_python_files(root):
        if perf_counter() >= deadline:
            errors.append(
                "Architecture analysis timed out before all files were analyzed."
            )
            timed_out = True
            break

        relative_path = path.relative_to(root).as_posix()

        try:
            source = _read_python_file(path, root)
            tree = ast.parse(source, filename=relative_path)
        except _SkippedPythonFile:
            continue
        except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
            errors.append(
                f"{relative_path}: source could not be analyzed ({type(exc).__name__})."
            )
            continue

        parsed[relative_path] = tree

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                caught = (
                    ast.unparse(node.type)
                    if node.type is not None
                    else "bare except"
                )
                summary = _handler_body_summary(node)

                if _is_broad_exception(node):
                    findings.append(
                        _make_finding(
                            file_path=relative_path,
                            rule_id="SSEC-ARCH-001",
                            start_line=node.lineno,
                            end_line=node.end_lineno,
                            category=FindingCategory.MAINTAINABILITY,
                            severity=Severity.LOW,
                            message=(
                                f"Broad exception handler catches {caught}; "
                                f"handler actions: {summary}."
                            ),
                            confidence=0.9,
                        )
                    )

                if _is_swallowed_exception(node):
                    findings.append(
                        _make_finding(
                            file_path=relative_path,
                            rule_id="SSEC-ARCH-002",
                            start_line=node.lineno,
                            end_line=node.end_lineno,
                            category=FindingCategory.MAINTAINABILITY,
                            severity=Severity.MEDIUM,
                            message=(
                                "Heuristic: exception handler appears to suppress "
                                "the exception without logging or re-raising; "
                                f"body: {summary}."
                            ),
                            confidence=0.6,
                        )
                    )

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = _complexity(node)
                if complexity > complexity_low:
                    severity = (
                        Severity.MEDIUM
                        if complexity > complexity_medium
                        else Severity.LOW
                    )
                    findings.append(
                        _make_finding(
                            file_path=relative_path,
                            rule_id="SSEC-ARCH-003",
                            start_line=node.lineno,
                            end_line=node.end_lineno,
                            category=FindingCategory.MAINTAINABILITY,
                            severity=severity,
                            message=(
                                f"Function {node.name!r} has estimated cyclomatic "
                                f"complexity {complexity}; threshold is "
                                f"{complexity_low} (medium above {complexity_medium})."
                            ),
                            confidence=0.9,
                        )
                    )

    try:
        import_result = analyze_python_imports(root)
        cycles = _collect_module_cycles(import_result.dependencies)

        for cycle in cycles:
            # Anchor the finding to the import edge that closes this cycle.
            source_module = cycle[-1]
            target_module = cycle[0]

            matching_dependencies = sorted(
                (
                    dependency
                    for dependency in import_result.dependencies
                    if dependency.source_module == source_module
                    and dependency.imported_module == target_module
                    and dependency.source_file in parsed
                ),
                key=lambda dependency: (
                    dependency.source_file,
                    dependency.line_number,
                ),
            )

            if not matching_dependencies:
                continue

            dependency = matching_dependencies[0]

            findings.append(
                _make_finding(
                    file_path=dependency.source_file,
                    rule_id="SSEC-ARCH-004",
                    start_line=dependency.line_number,
                    end_line=dependency.line_number,
                    category=FindingCategory.ARCHITECTURE,
                    severity=Severity.MEDIUM,
                    message=(
                        "Circular import detected: "
                        + " -> ".join([*cycle, cycle[0]])
                    ),
                    confidence=0.9,
                )
            )
    except (OSError, ValueError) as exc:
        errors.append(
            f"Import graph could not be analyzed ({type(exc).__name__})."
        )

    findings.sort(key=lambda item: (item.file_path, item.start_line, item.rule_id))

    return ScannerRunResult(
        scanner="architecture",
        status=(
            ScannerStatus.PARTIAL
            if errors or timed_out
            else ScannerStatus.SUCCESS
        ),
        findings=findings,
        duration_seconds=round(perf_counter() - started, 3),
        errors=errors,
    )
