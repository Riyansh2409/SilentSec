"""Detect duplicated Python functions by normalized AST structure.

Two functions are duplicates when their syntax trees are identical after
normalization: local names, argument names, literal values, docstrings,
type hints and decorators are ignored. Attribute and keyword names are kept,
because ``conn.execute`` and ``conn.close`` really are different code.

This finds copy-paste-and-rename clones. It does not find near-duplicates
whose structure differs (for example, one extra statement); that is a
deliberate trade-off for zero false positives from merely similar code.
"""

import ast
import copy
from hashlib import sha256

from pydantic import BaseModel, Field

MIN_STATEMENTS = 5
MIN_LINES = 6


class FunctionLocation(BaseModel):
    file_path: str
    name: str
    start_line: int
    end_line: int

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


class DuplicateGroup(BaseModel):
    """Functions with identical normalized structure, sorted by location."""

    structure_hash: str
    functions: list[FunctionLocation] = Field(min_length=2)
    statement_count: int


class _Normalizer(ast.NodeTransformer):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return self._function(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.AST:
        node.name = "_"
        node.decorator_list = []
        node.returns = None
        node.type_comment = None
        if hasattr(node, "type_params"):
            node.type_params = []
        node.body = _without_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = "_"
        node.decorator_list = []
        node.body = _without_docstring(node.body)
        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = "_"
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "_"
        node.annotation = None
        node.type_comment = None
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST:
        node.annotation = ast.Name(id="_", ctx=ast.Load())
        self.generic_visit(node)
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        # Keep the literal's type (str vs int) but not its value.
        node.value = type(node.value).__name__
        node.kind = None
        return node


def _without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:] or [ast.Pass()]
    return body


def _statement_count(node: ast.AST) -> int:
    return sum(isinstance(child, ast.stmt) for child in ast.walk(node)) - 1


def structure_hash(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Hash a function's normalized syntax tree."""
    normalized = _Normalizer().visit(copy.deepcopy(node))
    dumped = ast.dump(normalized, annotate_fields=False, include_attributes=False)
    return sha256(dumped.encode("utf-8")).hexdigest()


def find_duplicate_functions(
    parsed: dict[str, ast.AST],
    *,
    min_statements: int = MIN_STATEMENTS,
    min_lines: int = MIN_LINES,
) -> list[DuplicateGroup]:
    """Group functions across files whose normalized structure is identical.

    Small functions (fewer than ``min_statements`` statements or
    ``min_lines`` lines) are ignored, since short helpers often look alike
    legitimately. A duplicate nested inside an already-reported duplicate is
    not reported again.
    """
    buckets: dict[str, list[tuple[FunctionLocation, int]]] = {}

    for file_path in sorted(parsed):
        for node in ast.walk(parsed[file_path]):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            location = FunctionLocation(
                file_path=file_path,
                name=node.name,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
            )
            statements = _statement_count(node)
            if statements < min_statements or location.line_count < min_lines:
                continue
            buckets.setdefault(structure_hash(node), []).append((location, statements))

    groups = [
        DuplicateGroup(
            structure_hash=digest,
            functions=sorted(
                (location for location, _ in members),
                key=lambda item: (item.file_path, item.start_line),
            ),
            statement_count=members[0][1],
        )
        for digest, members in buckets.items()
        if len(members) >= 2
    ]

    # Larger duplicates first, so nested duplicates inside them are skipped.
    groups.sort(
        key=lambda group: (
            -group.statement_count,
            group.functions[0].file_path,
            group.functions[0].start_line,
        )
    )

    reported: list[FunctionLocation] = []
    kept: list[DuplicateGroup] = []
    for group in groups:
        if all(_inside_any(location, reported) for location in group.functions):
            continue
        kept.append(group)
        reported.extend(group.functions)

    kept.sort(key=lambda group: (group.functions[0].file_path, group.functions[0].start_line))
    return kept


def _inside_any(location: FunctionLocation, others: list[FunctionLocation]) -> bool:
    return any(
        other.file_path == location.file_path
        and other.start_line <= location.start_line
        and location.end_line <= other.end_line
        and other != location
        for other in others
    )
