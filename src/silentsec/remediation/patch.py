"""Validate unified diffs before they are applied anywhere.

Validation is deliberately strict. A patch that touches paths outside the
repository, binary content, Git internals, file modes, or symlinks is
rejected instead of being "fixed up".
"""

import re
from pathlib import PurePosixPath, PureWindowsPath

from pydantic import BaseModel, Field

MAX_PATCH_BYTES = 200_000
MAX_PATCH_FILES = 20

_DIFF_GIT_RE = re.compile(r"^diff --git (\S+) (\S+)$")
# Only regular, non-executable files may be created or deleted.
_ALLOWED_FILE_MODE = "100644"


class PatchValidation(BaseModel):
    """Outcome of validating a unified diff."""

    ok: bool
    touched_files: list[str] = Field(default_factory=list)
    strip_level: int = 1
    errors: list[str] = Field(default_factory=list)
    # Line numbers in the ORIGINAL file that the patch removes or edits, or
    # next to which it inserts lines. Used to pick the findings a patch targets.
    changed_lines: dict[str, list[int]] = Field(default_factory=dict)


def _strip_prefix(raw_path: str, strip_level: int) -> str:
    path = raw_path.split("\t", 1)[0].strip()
    if strip_level == 1 and path[:2] in {"a/", "b/"}:
        return path[2:]
    return path


def _path_errors(path: str) -> list[str]:
    """Explain why a repository-relative patch path is unsafe, if it is."""
    if not path:
        return ["Patch contains an empty file path."]

    if "\\" in path:
        return [f"Patch path uses backslashes: {path!r}."]

    if PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute():
        return [f"Patch path is absolute: {path!r}."]

    if PureWindowsPath(path).drive:
        return [f"Patch path names a drive: {path!r}."]

    parts = PurePosixPath(path).parts

    if ".." in parts:
        return [f"Patch path leaves the repository: {path!r}."]

    if any(part.casefold() == ".git" for part in parts):
        return [f"Patch path touches Git internals: {path!r}."]

    return []


def _detect_strip_level(header_paths: list[str]) -> int:
    """Use -p1 for a/ b/ style diffs (git diff default), otherwise -p0."""
    real_paths = [path for path in header_paths if path != "/dev/null"]
    if real_paths and all(path[:2] in {"a/", "b/"} for path in real_paths):
        return 1
    return 0


def validate_patch(diff_text: str) -> PatchValidation:
    """Check a unified diff without touching the filesystem."""
    errors: list[str] = []

    if not diff_text.strip():
        return PatchValidation(ok=False, errors=["Patch is empty."])

    if len(diff_text.encode("utf-8")) > MAX_PATCH_BYTES:
        return PatchValidation(
            ok=False,
            errors=[f"Patch is larger than {MAX_PATCH_BYTES} bytes."],
        )

    parsed = _parse_diff(diff_text.splitlines())

    for line in parsed.metadata_lines:
        if line.startswith("GIT binary patch") or (
            line.startswith("Binary files ") and line.endswith(" differ")
        ):
            errors.append("Binary patches are not supported.")
        elif line.startswith(("old mode ", "new mode ")):
            errors.append("File mode changes are not allowed.")
        elif line.startswith(("new file mode ", "deleted file mode ")):
            mode = line.rsplit(" ", 1)[-1]
            if mode != _ALLOWED_FILE_MODE:
                errors.append(f"File mode {mode} is not allowed (only {_ALLOWED_FILE_MODE}).")
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            errors.append("Renames and copies are not supported.")

    if not parsed.header_paths:
        errors.append("Patch has no file headers (expected ---/+++ lines).")

    if not parsed.hunk_count:
        errors.append("Patch has no hunks (expected @@ lines).")

    strip_level = _detect_strip_level(parsed.header_paths)
    touched: set[str] = set()

    for raw_path in parsed.header_paths:
        if raw_path == "/dev/null":
            continue
        path = _strip_prefix(raw_path, strip_level)
        path_problems = _path_errors(path)
        if path_problems:
            errors.extend(path_problems)
        else:
            touched.add(path)

    if len(touched) > MAX_PATCH_FILES:
        errors.append(f"Patch touches more than {MAX_PATCH_FILES} files.")

    # Keep each distinct error once, in first-seen order.
    unique_errors = list(dict.fromkeys(errors))
    changed: dict[str, list[int]] = {}
    if not unique_errors:
        for raw_path, numbers in parsed.changed_lines.items():
            path = _strip_prefix(raw_path, strip_level)
            changed[path] = sorted(set(changed.get(path, [])) | numbers)

    return PatchValidation(
        ok=not unique_errors,
        touched_files=sorted(touched),
        strip_level=strip_level,
        errors=unique_errors,
        changed_lines=dict(sorted(changed.items())),
    )


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class _ParsedDiff(BaseModel):
    metadata_lines: list[str] = Field(default_factory=list)
    header_paths: list[str] = Field(default_factory=list)
    hunk_count: int = 0
    # Raw (unstripped) original path -> original line numbers changed.
    changed_lines: dict[str, set[int]] = Field(default_factory=dict)


def _parse_diff(lines: list[str]) -> _ParsedDiff:
    """Walk a unified diff, using hunk line counts to know where hunks end.

    Counting matters: a removed line whose content starts with "-- " (a SQL
    comment) or "--" (YAML "---") appears as "---..." inside a hunk and must
    not be mistaken for a file header.
    """
    parsed = _ParsedDiff()
    old_path: str | None = None
    old_line = 0
    old_remaining = new_remaining = 0
    # True while the current run of +/- lines started with a removal, i.e.
    # the additions replace removed lines rather than being pure insertions.
    run_has_removal = False

    for line in lines:
        if old_remaining > 0 or new_remaining > 0:
            if line.startswith("\\"):
                continue  # "\ No newline at end of file"
            if line.startswith("-"):
                if old_path is not None:
                    parsed.changed_lines.setdefault(old_path, set()).add(old_line)
                old_line += 1
                old_remaining -= 1
                run_has_removal = True
            elif line.startswith("+"):
                if old_path is not None and not run_has_removal:
                    # A pure insertion sits between two original lines; mark both.
                    marks = parsed.changed_lines.setdefault(old_path, set())
                    marks.update({max(1, old_line - 1), old_line})
                new_remaining -= 1
            else:  # context line (" " or an editor-stripped empty line)
                old_line += 1
                old_remaining -= 1
                new_remaining -= 1
                run_has_removal = False
            continue

        match = _HUNK_RE.match(line)
        if match:
            parsed.hunk_count += 1
            old_line = int(match.group(1))
            run_has_removal = False
            old_remaining = int(match.group(2)) if match.group(2) is not None else 1
            new_remaining = int(match.group(4)) if match.group(4) is not None else 1
            continue

        if line.startswith("--- "):
            raw = line[4:].split("\t", 1)[0].strip()
            parsed.header_paths.append(raw)
            old_path = None if raw == "/dev/null" else raw
        elif line.startswith("+++ "):
            parsed.header_paths.append(line[4:].split("\t", 1)[0].strip())
        else:
            git_header = _DIFF_GIT_RE.match(line)
            if git_header:
                parsed.header_paths.extend(git_header.groups())
            parsed.metadata_lines.append(line)

    return parsed
