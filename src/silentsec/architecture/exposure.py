"""Which functions are reachable from a web entry point, from the source alone.

Python files are parsed with ``ast``; repository code is never imported or
executed. Entry points are Flask/FastAPI route handlers and
``if __name__ == "__main__":`` blocks. Calls are linked by name (``f()``,
``module.f()``, ``self.f()``), resolving imports between repository modules
where possible. When a name has several candidates, all of them are linked,
so the graph over-approximates.

"Reachable" means a chain of calls from an entry point exists in the code.
It does not prove that a finding in that function is exploitable.
"""

import ast
from collections import deque
from pathlib import Path
from time import perf_counter
from typing import Literal

from pydantic import BaseModel, Field

from silentsec.architecture.analyzer import (
    _discover_python_files,
    _read_python_file,
    _SkippedPythonFile,
)
from silentsec.architecture.import_analyzer import _resolve_relative_import

MAX_FUNCTIONS = 5000
MAX_PATH_LENGTH = 8
DEFAULT_TIMEOUT_SECONDS = 15.0

Exposure = Literal["reachable", "not_reachable", "unknown"]

# Decorator receivers that are treated as a web app or router even when the
# module does not visibly create them (e.g. "from .app import app").
ROUTE_RECEIVERS = {"app", "router", "bp", "blueprint", "api"}
ROUTE_FACTORIES = {"Flask", "FastAPI", "APIRouter", "Blueprint"}
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
ROUTE_METHODS = HTTP_METHODS | {"route", "api_route", "websocket"}
WEB_FRAMEWORK_MODULES = {"flask", "fastapi", "starlette"}

LIMITATIONS = [
    (
        "Reachable in the call graph means a chain of calls from a web route or "
        "__main__ block exists in the code; it does not prove the issue is exploitable."
    ),
    (
        "Calls are linked by function name; when a name matches several functions, "
        "all of them are linked, so some paths may not exist at run time."
    ),
    (
        "Calls through variables, callbacks, add_url_rule, dependency injection and "
        "other dynamic dispatch are not followed."
    ),
]


class FunctionExposure(BaseModel):
    """One function or method and whether an entry point reaches it."""

    file_path: str
    qualname: str
    start_line: int
    end_line: int
    entry_point: str | None = None  # e.g. "GET /search" for a route handler
    exposure: Exposure = "unknown"
    # Shortest call chain, e.g. ["GET /search -> search_products()",
    # "search_products() -> run_query()"].
    path: list[str] = Field(default_factory=list)


class ExposureAnalysis(BaseModel):
    """Call-graph exposure for the Python functions of a repository."""

    web_framework_detected: bool = False
    entry_points: list[str] = Field(default_factory=list)
    functions: list[FunctionExposure] = Field(default_factory=list)
    complete: bool = True
    limitations: list[str] = Field(default_factory=list)

    def function_at(self, file_path: str, line: int) -> FunctionExposure | None:
        """The innermost function whose lines contain ``line``."""
        best: FunctionExposure | None = None
        for function in self.functions:
            if (
                function.file_path == file_path
                and function.start_line <= line <= function.end_line
                and (best is None or function.start_line >= best.start_line)
            ):
                best = function
        return best


class _Function:
    def __init__(self, file_path: str, module: str, qualname: str, node: ast.AST,
                 class_name: str | None) -> None:
        self.file_path = file_path
        self.module = module
        self.qualname = qualname
        self.name = qualname.rsplit(".", 1)[-1]
        self.class_name = class_name
        self.node = node
        self.label = f"{qualname}()"


class _Module:
    """Per-module name bindings needed to resolve calls."""

    def __init__(self, name: str, is_package: bool) -> None:
        self.name = name
        self.is_package = is_package
        self.module_aliases: dict[str, str] = {}  # local name -> repo module
        self.imported_names: dict[str, tuple[str, str]] = {}  # local -> (module, name)
        self.star_imports: list[str] = []
        self.external_names: set[str] = set()  # names bound to non-repo imports
        self.route_receivers: set[str] = set(ROUTE_RECEIVERS)
        self.uses_web_framework = False


def _module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _route_label(decorator: ast.AST, module: _Module) -> str | None:
    """'GET /search' for a Flask/FastAPI route decorator, else None."""
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    method = decorator.func.attr
    receiver = decorator.func.value
    receiver_name = receiver.id if isinstance(receiver, ast.Name) else None
    if method not in ROUTE_METHODS or receiver_name not in module.route_receivers:
        return None

    path = _string(decorator.args[0]) if decorator.args else None
    for keyword in decorator.keywords:
        if keyword.arg == "path" and path is None:
            path = _string(keyword.value)
    path = path or "?"

    if method in HTTP_METHODS:
        return f"{method.upper()} {path}"
    if method == "websocket":
        return f"WEBSOCKET {path}"
    methods = ["GET"]
    for keyword in decorator.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            listed = [_string(item) for item in keyword.value.elts]
            methods = [item.upper() for item in listed if item] or methods
    return f"{','.join(methods)} {path}"


def _is_main_block(node: ast.AST) -> bool:
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    test = node.test
    sides = [test.left, *test.comparators]
    return (
        len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and any(isinstance(side, ast.Name) and side.id == "__name__" for side in sides)
        and any(_string(side) == "__main__" for side in sides)
    )


def _collect_bindings(tree: ast.AST, module: _Module, repo_modules: set[str]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in WEB_FRAMEWORK_MODULES:
                    module.uses_web_framework = True
                if alias.asname:
                    if alias.name in repo_modules:
                        module.module_aliases[alias.asname] = alias.name
                    else:
                        module.external_names.add(alias.asname)
                elif top in repo_modules or any(m.startswith(top + ".") for m in repo_modules):
                    module.module_aliases[top] = top
                else:
                    module.external_names.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                target = _resolve_relative_import(
                    module.name, module.is_package, node.module, node.level
                )
            else:
                target = node.module or ""
            if target.split(".")[0] in WEB_FRAMEWORK_MODULES:
                module.uses_web_framework = True
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == "*":
                    if target in repo_modules:
                        module.star_imports.append(target)
                elif f"{target}.{alias.name}" in repo_modules:
                    module.module_aliases[local] = f"{target}.{alias.name}"
                elif target in repo_modules:
                    module.imported_names[local] = (target, alias.name)
                else:
                    module.external_names.add(local)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            factory = _dotted(node.value.func)
            if factory and factory.rsplit(".", 1)[-1] in ROUTE_FACTORIES:
                module.route_receivers.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )


class _CallCollector(ast.NodeVisitor):
    """Collect functions and, for each, the calls made directly in its body."""

    def __init__(self, file_path: str, module: _Module) -> None:
        self.file_path = file_path
        self.module = module
        self.functions: list[_Function] = []
        self.calls: dict[_Function, list[ast.Call]] = {}
        self.routes: list[tuple[str, _Function]] = []
        self.main_calls: list[ast.Call] = []
        self._scope: list[str] = []
        self._classes: list[str | None] = [None]
        self._current: list[_Function] = []
        self._in_main = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._scope.append(node.name)
        self._classes.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._classes.pop()
        self._scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        qualname = ".".join([*self._scope, node.name])
        function = _Function(self.file_path, self.module.name, qualname, node, self._classes[-1])
        self.functions.append(function)
        self.calls[function] = []
        for decorator in node.decorator_list:
            label = _route_label(decorator, self.module)
            if label:
                self.routes.append((label, function))

        self._scope.append(node.name)
        self._classes.append(None)  # a nested def is not a method
        self._current.append(function)
        for statement in node.body:
            self.visit(statement)
        self._current.pop()
        self._classes.pop()
        self._scope.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_If(self, node: ast.If) -> None:
        if not self._current and _is_main_block(node):
            self._in_main = True
            self.generic_visit(node)
            self._in_main = False
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._current:
            self.calls[self._current[-1]].append(node)
        elif self._in_main:
            self.main_calls.append(node)
        self.generic_visit(node)


class _Graph:
    def __init__(self) -> None:
        self.functions: list[_Function] = []
        self.by_module: dict[str, dict[str, list[_Function]]] = {}
        self.top_level_by_name: dict[str, list[_Function]] = {}
        self.methods_by_name: dict[str, list[_Function]] = {}

    def add(self, function: _Function) -> None:
        self.functions.append(function)
        if "." not in function.qualname:
            self.by_module.setdefault(function.module, {}).setdefault(
                function.name, []
            ).append(function)
            self.top_level_by_name.setdefault(function.name, []).append(function)
        elif function.class_name is not None:
            self.methods_by_name.setdefault(function.name, []).append(function)

    def module_function(self, module: str, name: str) -> list[_Function]:
        return self.by_module.get(module, {}).get(name, [])

    def resolve(self, call: ast.Call, module: _Module, caller: _Function | None,
                local_functions: dict[str, list[_Function]]) -> list[_Function]:
        func = call.func
        if isinstance(func, ast.Name):
            name = func.id
            if name in local_functions:
                return local_functions[name]
            if name in module.imported_names:
                target, original = module.imported_names[name]
                found = self.module_function(target, original)
                # A package may re-export a name defined elsewhere: link every
                # top-level function with that name (over-approximation).
                return found or self.top_level_by_name.get(original, [])
            starred = [
                function
                for target in module.star_imports
                for function in self.module_function(target, name)
            ]
            return starred

        if not isinstance(func, ast.Attribute):
            return []
        name = func.attr
        receiver = func.value

        if isinstance(receiver, ast.Name) and receiver.id in {"self", "cls"}:
            if caller is not None:
                owner = caller.qualname.rsplit(".", 1)[0]
                same_class = [
                    function
                    for function in self.methods_by_name.get(name, [])
                    if function.file_path == caller.file_path
                    and function.qualname == f"{owner}.{name}"
                ]
                if same_class:
                    return same_class
            # Inherited or mixin method: any method with that name.
            return self.methods_by_name.get(name, [])

        dotted = _dotted(receiver)
        if dotted:
            head, _, rest = dotted.partition(".")
            if head in module.module_aliases:
                target = module.module_aliases[head] + (f".{rest}" if rest else "")
                return self.module_function(target, name)
            if head in module.external_names or head in module.route_receivers:
                return []
        # Unknown receiver (a local variable, parameter or attribute): any
        # method with that name.
        return self.methods_by_name.get(name, [])


def analyze_exposure(
    repo_root: str | Path,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_functions: int = MAX_FUNCTIONS,
    max_path_length: int = MAX_PATH_LENGTH,
) -> ExposureAnalysis:
    """Find the functions reachable from Flask/FastAPI routes and __main__ blocks."""
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {repo_root}")
    deadline = perf_counter() + timeout_seconds
    limitations = list(LIMITATIONS)
    complete = True

    parsed: list[tuple[str, ast.AST, _Module]] = []
    for path in _discover_python_files(root):
        if perf_counter() >= deadline:
            limitations.append("Exposure analysis timed out before all files were parsed.")
            complete = False
            break
        relative = path.relative_to(root)
        try:
            tree = ast.parse(_read_python_file(path, root), filename=relative.as_posix())
        except (_SkippedPythonFile, OSError, UnicodeError, SyntaxError, ValueError):
            continue
        module = _Module(_module_name(relative), path.name == "__init__.py")
        parsed.append((relative.as_posix(), tree, module))

    repo_modules = {module.name for _, _, module in parsed}
    graph = _Graph()
    collected: list[tuple[_CallCollector, dict[str, list[_Function]]]] = []
    for file_path, tree, module in parsed:
        _collect_bindings(tree, module, repo_modules)
        collector = _CallCollector(file_path, module)
        collector.visit(tree)
        if len(graph.functions) + len(collector.functions) > max_functions:
            limitations.append(
                f"Only the first {max_functions} functions were analyzed."
            )
            complete = False
            break
        local: dict[str, list[_Function]] = {}
        for function in collector.functions:
            graph.add(function)
            local.setdefault(function.name, []).append(function)
        collected.append((collector, local))

    web_framework = any(
        collector.module.uses_web_framework or collector.routes for collector, _ in collected
    )

    # Edges between functions, plus virtual entry nodes ("GET /search",
    # "__main__ in app.py") pointing at the functions they reach first.
    edges: dict[_Function, list[_Function]] = {function: [] for function in graph.functions}
    entries: list[tuple[str, list[_Function]]] = []
    entry_of: dict[_Function, str] = {}
    for collector, local in collected:
        for function, calls in collector.calls.items():
            if perf_counter() >= deadline:
                break
            targets = edges[function]
            for call in calls:
                for target in graph.resolve(call, collector.module, function, local):
                    if target not in targets:
                        targets.append(target)
        for label, function in collector.routes:
            entries.append((label, [function]))
            entry_of.setdefault(function, label)
        if collector.main_calls:
            reached: list[_Function] = []
            for call in collector.main_calls:
                for target in graph.resolve(call, collector.module, None, local):
                    if target not in reached:
                        reached.append(target)
            if reached:
                entries.append((f"__main__ in {collector.file_path}", reached))
    if perf_counter() >= deadline and complete:
        limitations.append("Exposure analysis timed out while linking calls.")
        complete = False

    # Breadth-first search from all entry points at once gives each function
    # its shortest path; the visited set makes cycles and recursion safe.
    paths: dict[_Function, list[str]] = {}
    queue: deque[_Function] = deque()
    for label, first in entries:
        for function in first:
            if function not in paths:
                paths[function] = [f"{label} -> {function.label}"]
                queue.append(function)
    depth_limited = False
    while queue:
        if perf_counter() >= deadline:
            limitations.append("Exposure analysis timed out while following calls.")
            complete = False
            break
        current = queue.popleft()
        for target in edges.get(current, []):
            if target in paths:
                continue
            if len(paths[current]) >= max_path_length:
                depth_limited = True
                continue
            paths[target] = [*paths[current], f"{current.label} -> {target.label}"]
            queue.append(target)
    if depth_limited:
        limitations.append(
            f"Call chains longer than {max_path_length} steps are not followed; "
            "functions beyond that are marked unknown."
        )

    # Without a web framework or with an incomplete graph, "not reachable"
    # cannot be claimed.
    certain = web_framework and complete and not depth_limited
    functions = [
        FunctionExposure(
            file_path=function.file_path,
            qualname=function.qualname,
            start_line=function.node.lineno,
            end_line=getattr(function.node, "end_lineno", None) or function.node.lineno,
            entry_point=entry_of.get(function),
            exposure=(
                "reachable" if function in paths and web_framework
                else "not_reachable" if certain
                else "unknown"
            ),
            path=paths.get(function, []) if web_framework else [],
        )
        for function in graph.functions
    ]
    if not web_framework:
        limitations.append("No Flask or FastAPI usage was detected, so exposure is unknown.")

    return ExposureAnalysis(
        web_framework_detected=web_framework,
        entry_points=sorted({label for label, _ in entries}),
        functions=functions,
        complete=complete,
        limitations=limitations,
    )
