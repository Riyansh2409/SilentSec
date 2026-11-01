"""Which findings count toward the main score.

Two kinds of findings are kept out of the main security debt score:

- Test and sample code (tests/, test_*.py, fixtures/, examples/ ...). These
  often contain deliberate "bad" code. They are still scanned and reported
  in their own section with their own points.
- Paths matched by a ``.silentsecignore`` file in the repository root
  (gitignore-style globs). These are dropped, and the report lists what was
  excluded and why.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

IGNORE_FILE_NAME = ".silentsecignore"
MAX_IGNORE_BYTES = 64 * 1024
MAX_LISTED_PATHS = 50

# Folder names anywhere in the path that mark test or sample code.
TEST_DIRECTORIES = frozenset(
    {"tests", "test", "__tests__", "fixtures", "sample_repositories", "examples"}
)
TEST_FILE_PATTERNS = (
    re.compile(r"test_.*\.py"),
    re.compile(r".*_test\.py"),
    re.compile(r"conftest\.py"),
)


def _posix(path: str) -> str:
    posix = path.replace("\\", "/")
    while posix.startswith("./"):
        posix = posix[2:]
    return posix


def is_test_path(path: str) -> bool:
    """True for files under a test/sample folder or named like a test module."""
    parts = PurePosixPath(_posix(path)).parts
    if not parts:
        return False
    if any(part.lower() in TEST_DIRECTORIES for part in parts[:-1]):
        return True
    name = parts[-1].lower()
    return any(pattern.fullmatch(name) for pattern in TEST_FILE_PATTERNS)


def _glob_to_regex(pattern: str) -> str:
    """Translate one gitignore-style glob (without leading ! or trailing /)."""
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if pattern[i : i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = pattern[i + 1 : end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


class IgnoreRule(BaseModel):
    pattern: str
    negated: bool = False
    regex: str


class IgnoreRules(BaseModel):
    """Parsed .silentsecignore. The last matching rule wins, as in .gitignore."""

    rules: list[IgnoreRule] = Field(default_factory=list)

    @classmethod
    def parse(cls, text: str) -> IgnoreRules:
        rules = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:].strip()
            directory = line.endswith("/")
            line = line.strip("/") if directory else line
            if not line:
                continue
            anchored = raw.strip().lstrip("!").startswith("/") or "/" in line
            body = _glob_to_regex(line.lstrip("/"))
            prefix = "" if anchored else "(?:.*/)?"
            # A match also covers everything below it (a folder pattern).
            suffix = "/.*" if directory else "(?:/.*)?"
            rules.append(
                IgnoreRule(pattern=raw.strip(), negated=negated, regex=f"{prefix}{body}{suffix}")
            )
        return cls(rules=rules)

    @classmethod
    def load(cls, root: Path) -> IgnoreRules:
        path = root / IGNORE_FILE_NAME
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_IGNORE_BYTES:
                return cls()
            return cls.parse(path.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            return cls()

    def match(self, path: str) -> IgnoreRule | None:
        """The rule that excludes ``path``, or None when it is not ignored."""
        posix = _posix(path)
        matched: IgnoreRule | None = None
        for rule in self.rules:
            if re.fullmatch(rule.regex, posix):
                matched = None if rule.negated else rule
        return matched


class ScopeSummary(BaseModel):
    """What was kept out of the main score, stated plainly for reports."""

    test_code_findings: int = 0
    test_code_file_count: int = 0
    test_code_files: list[str] = Field(default_factory=list)
    ignore_file_present: bool = False
    ignore_patterns: list[str] = Field(default_factory=list)
    ignored_findings: int = 0
    ignored_files: list[str] = Field(default_factory=list)
    ignored_files_truncated: int = 0

    def lines(self) -> list[str]:
        """Plain sentences describing exclusions (empty when nothing was excluded)."""
        out = []
        if self.test_code_findings:
            out.append(
                f"{self.test_code_findings} finding(s) in {self.test_code_file_count} test or "
                "sample file(s) are shown separately and not counted in the main score."
            )
        if self.ignored_findings:
            out.append(
                f"{self.ignored_findings} finding(s) in "
                f"{len(self.ignored_files) + self.ignored_files_truncated} file(s) were "
                f"excluded by {IGNORE_FILE_NAME} "
                f"(patterns: {', '.join(self.ignore_patterns)})."
            )
        elif self.ignore_file_present:
            out.append(f"{IGNORE_FILE_NAME} is present but excluded no findings.")
        return out


def split_findings(findings, root: Path, ignore_rules: IgnoreRules | None = None):
    """Split findings into (main, test_code, ignored) and summarize the exclusions."""
    rules = ignore_rules if ignore_rules is not None else IgnoreRules.load(root)
    main, test_code, ignored = [], [], []
    used_patterns: list[str] = []
    for finding in findings:
        rule = rules.match(finding.file_path)
        if rule is not None:
            ignored.append(finding)
            if rule.pattern not in used_patterns:
                used_patterns.append(rule.pattern)
        elif is_test_path(finding.file_path):
            test_code.append(finding)
        else:
            main.append(finding)
    ignored_files = sorted({_posix(f.file_path) for f in ignored})
    test_files = sorted({_posix(f.file_path) for f in test_code})
    summary = ScopeSummary(
        test_code_findings=len(test_code),
        test_code_file_count=len(test_files),
        test_code_files=test_files[:MAX_LISTED_PATHS],
        ignore_file_present=bool(rules.rules),
        ignore_patterns=used_patterns,
        ignored_findings=len(ignored),
        ignored_files=ignored_files[:MAX_LISTED_PATHS],
        ignored_files_truncated=max(0, len(ignored_files) - MAX_LISTED_PATHS),
    )
    return main, test_code, ignored, summary
