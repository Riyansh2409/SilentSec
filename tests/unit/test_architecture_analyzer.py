
from pathlib import Path

from silentsec.architecture.analyzer import run_architecture_analyzer
from silentsec.scanners.results import ScannerStatus


def write_file(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def rule_ids(result) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def test_detects_broad_exception_handler(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        logger.error('failed')\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-001" in rule_ids(result)
    finding = next(
        item for item in result.findings
        if item.rule_id == "SSEC-ARCH-001"
    )
    assert finding.severity.value == "low"
    assert finding.confidence == 0.9
    assert finding.file_path == "app.py"


def test_does_not_flag_specific_logged_exception_as_broad(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except ValueError:\n"
        "        logger.error('invalid value')\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-001" not in rule_ids(result)


def test_detects_swallowed_exception_heuristically(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except ValueError:\n"
        "        pass\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-002" in rule_ids(result)
    finding = next(
        item for item in result.findings
        if item.rule_id == "SSEC-ARCH-002"
    )
    assert finding.severity.value == "medium"
    assert finding.confidence == 0.6
    assert "heuristic" in finding.message.lower()


def test_does_not_flag_reraised_exception_as_swallowed(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except ValueError:\n"
        "        raise\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-002" not in rule_ids(result)



def test_detects_high_complexity_function(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def complicated(a, b, c):\n"
        "    if a:\n"
        "        pass\n"
        "    if b:\n"
        "        pass\n"
        "    if c:\n"
        "        pass\n"
        "    if a and b:\n"
        "        pass\n"
        "    if b or c:\n"
        "        pass\n"
        "    for item in []:\n"
        "        pass\n"
        "    while False:\n"
        "        pass\n"
        "    assert a or b\n"
        "    return a if b else c\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-003" in rule_ids(result)
    finding = next(
        item for item in result.findings
        if item.rule_id == "SSEC-ARCH-003"
    )
    assert "complicated" in finding.message
    assert "complexity" in finding.message.lower()

def test_does_not_flag_simple_function_for_complexity(tmp_path: Path):
    write_file(
        tmp_path,
        "app.py",
        "def simple(value):\n"
        "    return value + 1\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-003" not in rule_ids(result)



def test_complexity_threshold_boundary_10_and_11(tmp_path: Path):
    exactly_ten = "".join(
        f"    if value == {index}:\n"
        "        pass\n"
        for index in range(9)
    )
    eleven = "".join(
        f"    if value == {index}:\n"
        "        pass\n"
        for index in range(10)
    )
    write_file(
        tmp_path,
        "app.py",
        "def exactly_ten(value):\n"
        f"{exactly_ten}"
        "def eleven(value):\n"
        f"{eleven}",
    )

    result = run_architecture_analyzer(tmp_path)

    complexity_findings = [
        finding for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-003"
    ]
    names = [finding.message for finding in complexity_findings]

    assert not any("exactly_ten" in message for message in names)
    assert any("eleven" in message for message in names)


def test_detects_two_module_import_cycle(tmp_path: Path):
    write_file(tmp_path, "alpha.py", "import beta\n")
    write_file(tmp_path, "beta.py", "import alpha\n")

    result = run_architecture_analyzer(tmp_path)

    cycle_findings = [
        finding for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-004"
    ]
    assert len(cycle_findings) == 1
    assert cycle_findings[0].severity.value == "medium"
    assert "alpha" in cycle_findings[0].message
    assert "beta" in cycle_findings[0].message


def test_detects_three_module_import_cycle(tmp_path: Path):
    write_file(tmp_path, "alpha.py", "import beta\n")
    write_file(tmp_path, "beta.py", "import gamma\n")
    write_file(tmp_path, "gamma.py", "import alpha\n")

    result = run_architecture_analyzer(tmp_path)

    cycle_findings = [
        finding for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-004"
    ]
    assert len(cycle_findings) == 1
    assert all(
        module in cycle_findings[0].message
        for module in ("alpha", "beta", "gamma")
    )


def test_detects_cycle_with_relative_imports(tmp_path: Path):
    write_file(tmp_path, "pkg/__init__.py", "")
    write_file(tmp_path, "pkg/alpha.py", "from . import beta\n")
    write_file(tmp_path, "pkg/beta.py", "# comment\nfrom . import alpha\n")

    result = run_architecture_analyzer(tmp_path)

    cycle_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-004"
    ]
    assert len(cycle_findings) == 1
    assert cycle_findings[0].file_path == "pkg/beta.py"
    assert cycle_findings[0].start_line == 2


def test_does_not_flag_acyclic_imports(tmp_path: Path):
    write_file(tmp_path, "app.py", "import services\n")
    write_file(tmp_path, "services.py", "VALUE = 1\n")

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-004" not in rule_ids(result)


def test_syntax_error_is_partial_but_other_files_are_analyzed(
    tmp_path: Path,
):
    write_file(tmp_path, "broken.py", "def invalid(:\n")
    write_file(
        tmp_path,
        "valid.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        pass\n",
    )

    result = run_architecture_analyzer(tmp_path)

    assert result.status == ScannerStatus.PARTIAL
    assert result.errors
    assert "SSEC-ARCH-001" in rule_ids(result)


def test_skips_excluded_directories(tmp_path: Path):
    write_file(
        tmp_path,
        ".venv/hidden.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        pass\n",
    )
    write_file(tmp_path, "app.py", "VALUE = 1\n")

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-001" not in rule_ids(result)


def test_skips_oversized_python_file(tmp_path: Path):
    write_file(tmp_path, "large.py", "x = 1\n" * 50000)

    result = run_architecture_analyzer(tmp_path)

    assert not result.findings


def test_empty_repository_succeeds_without_findings(tmp_path: Path):
    result = run_architecture_analyzer(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert result.findings == []
    assert result.errors == []


def test_finding_order_and_fingerprints_are_deterministic(
    tmp_path: Path,
):
    write_file(
        tmp_path,
        "z.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        pass\n",
    )
    write_file(
        tmp_path,
        "a.py",
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        pass\n",
    )

    first = run_architecture_analyzer(tmp_path)
    second = run_architecture_analyzer(tmp_path)

    first_signature = [
        (item.file_path, item.start_line, item.rule_id, item.fingerprint)
        for item in first.findings
    ]
    second_signature = [
        (item.file_path, item.start_line, item.rule_id, item.fingerprint)
        for item in second.findings
    ]

    assert first_signature == second_signature
    assert first_signature == sorted(
        first_signature,
        key=lambda item: (item[0], item[1], item[2]),
    )


def test_timeout_returns_partial_result(tmp_path: Path, monkeypatch):
    from silentsec.architecture import analyzer

    write_file(tmp_path, "app.py", "VALUE = 1\\n")

    clock = iter([1000.0, 1002.0])
    monkeypatch.setattr(
        analyzer,
        "perf_counter",
        lambda: next(clock, 1002.0),
    )
    result = run_architecture_analyzer(tmp_path, timeout_seconds=1)

    assert result.status == ScannerStatus.PARTIAL
    assert any("timed out" in error.lower() for error in result.errors)

def test_detects_broad_exception_in_bom_prefixed_file(tmp_path: Path):
    content = (
        "def run():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    (tmp_path / "app.py").write_bytes(
        b"\xef\xbb\xbf" + content.encode("utf-8")
    )

    result = run_architecture_analyzer(tmp_path)

    assert "SSEC-ARCH-001" in rule_ids(result)
    assert result.status == ScannerStatus.SUCCESS


def test_dense_import_graph_reports_one_cycle_under_one_second(
    tmp_path: Path,
):
    import time

    module_names = [f"module_{index:02}" for index in range(12)]
    for module in module_names:
        imports = [
            f"import {other}"
            for other in module_names
            if other != module
        ]
        write_file(tmp_path, f"{module}.py", "\n".join(imports) + "\n")

    started = time.perf_counter()
    result = run_architecture_analyzer(tmp_path)
    elapsed = time.perf_counter() - started

    cycle_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-004"
    ]
    assert len(cycle_findings) == 1
    assert all(module in cycle_findings[0].message for module in module_names)
    assert "Example cycle:" in cycle_findings[0].message
    assert elapsed < 1.0


def test_with_statement_does_not_increase_cyclomatic_complexity(
    tmp_path: Path,
):
    branches = "".join(
        f"    if value == {index}:\n"
        "        pass\n"
        for index in range(9)
    )
    write_file(
        tmp_path,
        "app.py",
        "def exactly_ten(value):\n"
        "    with open('sample.txt') as handle:\n"
        "        handle.read()\n"
        + branches,
    )

    result = run_architecture_analyzer(tmp_path)

    complexity_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "SSEC-ARCH-003"
    ]
    assert not any(
        "exactly_ten" in finding.message
        for finding in complexity_findings
    )


def test_oversized_file_is_reported_without_partial_status(tmp_path: Path):
    from silentsec.architecture.analyzer import MAX_FILE_BYTES

    write_file(tmp_path, "app.py", "VALUE = 1\n")
    (tmp_path / "large.py").write_bytes(b"#" * (MAX_FILE_BYTES + 1))

    result = run_architecture_analyzer(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert any(
        "1 oversized Python file(s)" in error
        and "0 binary Python file(s)" in error
        for error in result.errors
    )


def test_binary_file_is_reported_without_partial_status(tmp_path: Path):
    write_file(tmp_path, "app.py", "VALUE = 1\n")
    (tmp_path / "binary.py").write_bytes(b"VALUE = 1\x00\xff")

    result = run_architecture_analyzer(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert any(
        "0 oversized Python file(s)" in error
        and "1 binary Python file(s)" in error
        for error in result.errors
    )
