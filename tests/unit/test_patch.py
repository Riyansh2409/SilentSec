import pytest

from silentsec.remediation.patch import (
    MAX_PATCH_BYTES,
    MAX_PATCH_FILES,
    crlf_content_lines,
    validate_patch,
)

VALID_PATCH = """\
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,2 +1,2 @@
-x = 1
+x = 2
 y = 3
diff --git a/app/new.py b/app/new.py
new file mode 100644
--- /dev/null
+++ b/app/new.py
@@ -0,0 +1 @@
+z = 4
"""


def single_file_patch(path: str) -> str:
    return f"--- {path}\n+++ {path}\n@@ -1 +1 @@\n-a\n+b\n"


def test_valid_multi_file_patch():
    result = validate_patch(VALID_PATCH)

    assert result.ok, result.errors
    assert result.touched_files == ["app/db.py", "app/new.py"]
    assert result.strip_level == 1


def test_patch_without_prefixes_uses_strip_level_zero():
    result = validate_patch(single_file_patch("app/db.py"))

    assert result.ok
    assert result.strip_level == 0
    assert result.touched_files == ["app/db.py"]


@pytest.mark.parametrize("text", ["", "   \n\n"])
def test_empty_patch_is_rejected(text: str):
    assert not validate_patch(text).ok


def test_oversized_patch_is_rejected():
    result = validate_patch(VALID_PATCH + "+" + "x" * MAX_PATCH_BYTES + "\n")

    assert not result.ok
    assert "larger than" in result.errors[0]


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("/etc/passwd", "absolute"),
        ("C:/Windows/win.ini", "absolute"),
        ("../outside.py", "leaves the repository"),
        ("app/../../outside.py", "leaves the repository"),
        (".git/config", "Git internals"),
        ("sub/.git/hooks/pre-commit", "Git internals"),
        ("app\\db.py", "backslashes"),
    ],
)
def test_unsafe_paths_are_rejected(path: str, message: str):
    result = validate_patch(single_file_patch(path))

    assert not result.ok
    assert any(message in error for error in result.errors), result.errors


def test_unsafe_path_in_diff_git_header_is_rejected():
    patch = (
        "diff --git a/../evil.py b/../evil.py\n"
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n"
    )

    assert not validate_patch(patch).ok


def test_binary_patch_is_rejected():
    patch = "diff --git a/img.png b/img.png\nGIT binary patch\nliteral 5\n@@ -1 +1 @@\n"

    result = validate_patch(patch)

    assert not result.ok
    assert "Binary" in result.errors[0]


def test_binary_files_differ_is_rejected():
    patch = "--- a/x.bin\n+++ b/x.bin\nBinary files a/x.bin and b/x.bin differ\n@@ -1 +1 @@\n"

    assert not validate_patch(patch).ok


def test_mode_change_is_rejected():
    patch = (
        "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n"
        "--- a/run.sh\n+++ b/run.sh\n@@ -1 +1 @@\n-a\n+b\n"
    )

    result = validate_patch(patch)

    assert not result.ok
    assert any("mode" in error for error in result.errors)


@pytest.mark.parametrize("mode", ["100755", "120000"])
def test_executable_or_symlink_new_file_is_rejected(mode: str):
    patch = (
        f"diff --git a/x b/x\nnew file mode {mode}\n"
        "--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+target\n"
    )

    assert not validate_patch(patch).ok


def test_rename_is_rejected():
    patch = (
        "diff --git a/a.py b/b.py\nrename from a.py\nrename to b.py\n"
        "--- a/a.py\n+++ b/b.py\n@@ -1 +1 @@\n-a\n+b\n"
    )

    assert not validate_patch(patch).ok


def test_patch_without_hunks_is_rejected():
    result = validate_patch("--- a/x.py\n+++ b/x.py\n")

    assert not result.ok
    assert any("hunks" in error for error in result.errors)


def test_too_many_files_is_rejected():
    patch = "".join(
        f"--- a/f{index}.py\n+++ b/f{index}.py\n@@ -1 +1 @@\n-a\n+b\n"
        for index in range(MAX_PATCH_FILES + 1)
    )

    result = validate_patch(patch)

    assert not result.ok
    assert any("more than" in error for error in result.errors)


def test_text_that_is_not_a_diff_is_rejected():
    assert not validate_patch("please fix the sql injection").ok


def test_changed_lines_for_replacements_are_the_removed_lines():
    patch = (
        "--- a/app.py\n+++ b/app.py\n@@ -8,7 +8,7 @@\n"
        " a\n b\n-old_line_10\n+new_line_10\n c\n d\n-old_line_13\n+new_line_13\n"
    )

    assert validate_patch(patch).changed_lines == {"app.py": [10, 13]}


def test_pure_insertion_marks_both_neighbouring_lines():
    patch = "--- a/app.py\n+++ b/app.py\n@@ -4,2 +4,3 @@\n check()\n+validate()\n call()\n"

    assert validate_patch(patch).changed_lines == {"app.py": [4, 5]}


def test_removed_lines_that_look_like_headers_stay_inside_the_hunk():
    # Removing "-- comment" (SQL) or "---" (YAML) produces lines starting "---".
    patch = (
        "--- a/q.sql\n+++ b/q.sql\n@@ -1,3 +1,2 @@\n"
        " select 1;\n--- old comment\n----\n+-- new comment\n"
    )

    result = validate_patch(patch)

    assert result.ok, result.errors
    assert result.touched_files == ["q.sql"]
    assert result.changed_lines == {"q.sql": [2, 3]}


def test_new_file_has_no_original_lines():
    assert "app/new.py" not in validate_patch(VALID_PATCH).changed_lines


def test_crlf_content_lines_converts_only_hunk_content():
    converted = crlf_content_lines(VALID_PATCH)

    assert converted.splitlines(keepends=True)[:7] == [
        "diff --git a/app/db.py b/app/db.py\n",
        "--- a/app/db.py\n",
        "+++ b/app/db.py\n",
        "@@ -1,2 +1,2 @@\n",
        "-x = 1\r\n",
        "+x = 2\r\n",
        " y = 3\r\n",
    ]
    # The second file's headers follow the first hunk and keep LF.
    assert "new file mode 100644\n--- /dev/null\n+++ b/app/new.py\n@@ -0,0 +1 @@\n" in converted
    assert converted.endswith("+z = 4\r\n")


def test_crlf_content_lines_keeps_header_like_removed_lines_in_the_hunk():
    patch = "--- a/q.sql\n+++ b/q.sql\n@@ -1,2 +1,1 @@\n--- comment\n select 1\n"

    assert crlf_content_lines(patch) == (
        "--- a/q.sql\n+++ b/q.sql\n@@ -1,2 +1,1 @@\n--- comment\r\n select 1\r\n"
    )


def test_crlf_content_lines_leaves_line_before_no_newline_marker_without_cr():
    # In a CRLF file without a final newline, the last line has no CR either.
    patch = (
        "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n a\n-b\n"
        "\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
    )

    assert crlf_content_lines(patch) == (
        "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n a\r\n-b\n"
        "\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
    )
