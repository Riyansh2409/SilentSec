"""Bounded static views and advisory hashed token patterns; never import scanned code."""

import ast
import hashlib
import io
import math
import re
import tokenize
from collections import Counter
from pathlib import Path
from time import monotonic

from silentsec.architecture.analyzer import (
    _discover_python_files,
    _read_python_file,
    _SkippedPythonFile,
)
from silentsec.architecture.exposure import LIMITATIONS, analyze_exposure
from silentsec.architecture.import_analyzer import analyze_python_imports
from silentsec.triage.sanitization import redact_sensitive_text

MAX_FILES = 1000
MAX_NODES = 2000
MAX_EDGES = 5000
MAX_BLOCKS = 500
MAX_PAIRS = 10000
SECURITY_APIS = {
    "eval",
    "exec",
    "system",
    "popen",
    "subprocess",
    "pickle",
    "loads",
    "load",
    "execute",
    "yaml",
    "shell",
    "password",
    "authenticate",
}
RULES = {
    "unsafe_subprocess",
    "deserialization",
    "query_construction",
    "auth_pattern",
    "exception_suppression",
}
ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9_+/=.-]{20,}")


def safe_text(text):
    text = redact_sensitive_text(str(text))

    def scrub(match):
        value = match.group()
        counts = Counter(value)
        entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
        # Normal paths/rule identifiers contain diverse letters too. Avoid
        # treating ordinary names such as integration-demo.zip as credentials.
        opaque_hex = len(value) >= 32 and re.fullmatch(r"[A-Fa-f0-9]+", value) and entropy > 3.2
        return "[REDACTED]" if entropy > 4.5 or opaque_hex else value

    return ENTROPY_TOKEN.sub(scrub, text)[:2000]


def identifier(*parts):
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:24]


def graph(root, *, detail=False):
    root = Path(root)
    files = _discover_python_files(root)
    complete = len(files) <= MAX_FILES
    files = files[:MAX_FILES]
    nodes = [{"id": "repository", "kind": "repository", "label": "Repository", "confidence": 1.0}]
    edges, limits, by_module, file_ids = [], list(LIMITATIONS), {}, {}
    for file in files:
        relative = file.relative_to(root).as_posix()
        module = (
            relative.removeprefix("src/")
            .removesuffix(".py")
            .replace("/", ".")
            .removesuffix(".__init__")
        )
        item = {
            "id": identifier(relative),
            "kind": "module",
            "label": safe_text(module),
            "file_path": safe_text(relative),
            "line": 1,
            "confidence": 1.0,
        }
        by_module[module] = item["id"]
        file_ids[relative] = item["id"]
        nodes.append(item)
        edges.append(
            {"source": "repository", "target": item["id"], "kind": "contains", "confidence": 1.0}
        )
    # Existing import analysis is reused only within the platform size bound.
    if complete:
        imported = analyze_python_imports(root)
        complete = imported.skipped_files == 0
        for dependency in imported.dependencies:
            source, target = (
                by_module.get(dependency.source_module),
                by_module.get(dependency.imported_module),
            )
            if source and target:
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "kind": "imports",
                        "line": dependency.line_number,
                        "confidence": 1.0,
                    }
                )
    exposure = analyze_exposure(root, timeout_seconds=5, max_functions=1000)
    complete = complete and exposure.complete
    functions, route_ids, names = {}, {}, {}
    for f in exposure.functions:
        fid = identifier(f.file_path, f.qualname, f.start_line)
        functions[(f.file_path, f.qualname)] = fid
        names.setdefault(f.qualname.split(".")[-1], []).append(fid)
        if detail and len(nodes) < MAX_NODES:
            nodes.append(
                {
                    "id": fid,
                    "kind": "function",
                    "label": safe_text(f.qualname),
                    "file_path": safe_text(f.file_path),
                    "line": f.start_line,
                    "end_line": f.end_line,
                    "reachable": f.exposure == "reachable",
                    "confidence": 0.6,
                }
            )
            if f.file_path in file_ids:
                edges.append(
                    {
                        "source": file_ids[f.file_path],
                        "target": fid,
                        "kind": "contains",
                        "confidence": 1.0,
                    }
                )
            if f.entry_point:
                rid = identifier("route", f.file_path, f.entry_point)
                route_ids[f.entry_point] = rid
                nodes.append(
                    {
                        "id": rid,
                        "kind": "route",
                        "label": safe_text(f.entry_point),
                        "file_path": safe_text(f.file_path),
                        "line": f.start_line,
                        "confidence": 0.8,
                    }
                )
                edges.append(
                    {"source": rid, "target": fid, "kind": "route_reaches", "confidence": 0.6}
                )
    if detail:
        for file in files:
            try:
                tree = ast.parse(_read_python_file(file, root))
            except (_SkippedPythonFile, ValueError, SyntaxError, OSError, UnicodeError):
                complete = False
                continue
            for f in exposure.functions:
                if f.file_path != file.relative_to(root).as_posix():
                    continue
                node = next(
                    (
                        n
                        for n in ast.walk(tree)
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and n.lineno == f.start_line
                    ),
                    None,
                )
                if node:
                    for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
                        name = (
                            call.func.id
                            if isinstance(call.func, ast.Name)
                            else getattr(call.func, "attr", "")
                        )
                        for target in names.get(name, []):
                            edges.append(
                                {
                                    "source": functions[(f.file_path, f.qualname)],
                                    "target": target,
                                    "kind": "calls",
                                    "confidence": 0.4,
                                }
                            )
    valid = {n["id"] for n in nodes[:MAX_NODES]}
    edge_map = {
        (e["source"], e["target"], e["kind"]): e
        for e in edges
        if e["source"] in valid and e["target"] in valid
    }
    edges = list(edge_map.values())
    if len(nodes) > MAX_NODES or len(edges) > MAX_EDGES or len(files) >= MAX_FILES:
        complete = False
        limits.append("Graph truncated at configured node, edge or file limit.")
    imports = {(e["source"], e["target"]) for e in edges if e["kind"] == "imports"}
    outgoing, incoming = Counter(a for a, _ in imports), Counter(b for _, b in imports)
    # Iterative reachability identifies all import edges participating in cycles.
    adjacency = {}
    for a, b in imports:
        adjacency.setdefault(a, set()).add(b)
    cycle_edges = []
    budget = 100000
    for edge in edges:
        if edge["kind"] != "imports":
            continue
        stack, seen = [edge["target"]], set()
        while stack and budget > 0:
            budget -= 1
            current = stack.pop()
            if current == edge["source"]:
                edge["cycle"] = True
                cycle_edges.append([edge["source"], edge["target"]])
                break
            if current not in seen:
                seen.add(current)
                stack.extend(adjacency.get(current, []))
        if budget <= 0:
            complete = False
            break
    return {
        "version": "1",
        "level": "detail" if detail else "module",
        "complete": complete,
        "nodes": nodes[:MAX_NODES],
        "edges": edges[:MAX_EDGES],
        "limitations": limits,
        "metrics": {
            "cycle_edges": cycle_edges[:100],
            "fan_in": incoming.most_common(20),
            "fan_out": outgoing.most_common(20),
            "route_reachable_functions": sum(f.exposure == "reachable" for f in exposure.functions),
            "isolated_modules": sum(
                not outgoing[n["id"]] and not incoming[n["id"]]
                for n in nodes
                if n["kind"] == "module"
            ),
        },
    }


def normalized_tokens(source):
    tokens = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in {
            tokenize.COMMENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
        }:
            continue
        if token.type == tokenize.NAME:
            import keyword

            tokens.append(
                token.string
                if keyword.iskeyword(token.string) or token.string in SECURITY_APIS
                else "NAME"
            )
        elif token.type == tokenize.STRING:
            tokens.append("STRING")
        elif token.type == tokenize.NUMBER:
            tokens.append("NUMBER")
        else:
            tokens.append(token.string)
        if len(tokens) > 10000:
            raise ValueError("Token budget exceeded")
    return tokens


def shingles(source, width=5):
    tokens = normalized_tokens(source)
    return {
        hashlib.blake2b(" ".join(tokens[i : i + width]).encode(), digest_size=16).hexdigest()
        for i in range(max(0, len(tokens) - width + 1))
    }


def classification(node):
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    if (names | attrs) & {"system", "popen", "subprocess"}:
        return "unsafe_subprocess"
    if (names | attrs) & {"pickle", "yaml", "loads"}:
        return "deserialization"
    if "execute" in attrs:
        return "query_construction"
    if (names | attrs) & {"password", "authenticate"}:
        return "auth_pattern"
    if any(
        isinstance(n, ast.ExceptHandler) and any(isinstance(b, ast.Pass) for b in n.body)
        for n in ast.walk(node)
    ):
        return "exception_suppression"
    return None


def patterns(root, *, rules=None):
    blocks, results, complete = [], [], True
    deadline = monotonic() + 5
    enabled = set(rules or RULES)
    files = _discover_python_files(Path(root))
    for file in files[:MAX_FILES]:
        if monotonic() > deadline or len(blocks) >= MAX_BLOCKS:
            complete = False
            break
        if file.name.startswith(".env") or any(
            part.startswith(".") for part in file.relative_to(root).parts
        ):
            continue
        try:
            source = _read_python_file(file, Path(root))
            tree = ast.parse(source)
            lines = source.splitlines()
            for node in ast.walk(tree):
                if (
                    not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or len(blocks) >= MAX_BLOCKS
                ):
                    continue
                category = classification(node)
                if category not in enabled:
                    continue
                fingerprints = shingles("\n".join(lines[node.lineno - 1 : node.end_lineno]))
                if len(fingerprints) >= 5:
                    blocks.append(
                        (
                            category,
                            safe_text(file.relative_to(root).as_posix()),
                            node.lineno,
                            node.end_lineno,
                            fingerprints,
                        )
                    )
        except (
            _SkippedPythonFile,
            OSError,
            ValueError,
            SyntaxError,
            UnicodeError,
            tokenize.TokenError,
            IndentationError,
        ):
            complete = False
    pairs = 0
    for i, first in enumerate(blocks):
        for second in blocks[i + 1 :]:
            pairs += 1
            if pairs > MAX_PAIRS or monotonic() > deadline:
                complete = False
                break
            if first[0] != second[0]:
                continue
            score = len(first[4] & second[4]) / max(1, len(first[4] | second[4]))
            if score >= 0.8:
                results.append(
                    {
                        "classification": first[0],
                        "similarity": round(score, 3),
                        "locations": [
                            {"file_path": row[1], "start_line": row[2], "end_line": row[3]}
                            for row in (first, second)
                        ],
                        "evidence": "Normalized token patterns overlap; inspect both locations. Source literals are withheld.",
                    }
                )
            if len(results) >= 100:
                complete = False
                break
        if not complete and (pairs > MAX_PAIRS or len(results) >= 100 or monotonic() > deadline):
            break
    return {
        "version": "1",
        "advisory": True,
        "affects_score": False,
        "complete": complete and len(files) <= MAX_FILES,
        "threshold": 0.8,
        "matches": results,
        "limitations": [
            "Normalized-token similarity is not proof of a vulnerability.",
            "Only bounded Python function bodies in selected pattern classes are compared.",
            "Identifiers and literals are normalized; this can create false positives.",
        ],
    }
