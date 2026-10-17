
import os
from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "vendor",
    ".next",
    ".idea",
}


EXTENSION_TO_LANGUAGE = {
    # Python
    ".py": "Python",
    ".pyi": "Python",

    # JavaScript and TypeScript
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".tsx": "TypeScript",

    # JVM languages
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".groovy": "Groovy",
    ".gradle": "Groovy",

    # Systems languages
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C/C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hh": "C++",
    ".hpp": "C++",
    ".hxx": "C++",

    # .NET
    ".cs": "C#",
    ".fs": "F#",
    ".fsx": "F#",
    ".vb": "Visual Basic",

    # Other backend languages
    ".php": "PHP",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".hs": "Haskell",
    ".lua": "Lua",
    ".pl": "Perl",
    ".r": "R",
    ".jl": "Julia",
    ".ps1": "PowerShell",
    ".sol": "Solidity",
    ".clj": "Clojure",
    ".cljs": "Clojure",
    ".cljc": "Clojure",
    ".pas": "Pascal",

    # Web and query languages
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "SCSS",
    ".less": "Less",
    ".sql": "SQL",
}


class LanguageDetectionResult(BaseModel):
    """Repository language inventory."""

    languages: list[str] = Field(default_factory=list)
    language_counts: dict[str, int] = Field(default_factory=dict)
    files_by_language: dict[str, list[str]] = Field(default_factory=dict)
    total_source_files: int = 0


def detect_languages(repo_path: str | Path) -> LanguageDetectionResult:
    """Detect recognizable source files without scanning dependency directories."""

    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {repo_path}")

    grouped_files: dict[str, list[str]] = defaultdict(list)

    for current_dir, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        # Prevent scanning dependencies, generated files, and Git internals.
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in EXCLUDED_DIRECTORIES
        )

        current_path = Path(current_dir)

        for filename in sorted(filenames):
            file_path = current_path / filename
            language = EXTENSION_TO_LANGUAGE.get(file_path.suffix.lower())

            if language is None:
                continue

            relative_path = file_path.relative_to(root).as_posix()
            grouped_files[language].append(relative_path)

    files_by_language = {
        language: sorted(files)
        for language, files in sorted(grouped_files.items())
    }

    language_counts = {
        language: len(files)
        for language, files in files_by_language.items()
    }

    return LanguageDetectionResult(
        languages=list(files_by_language.keys()),
        language_counts=language_counts,
        files_by_language=files_by_language,
        total_source_files=sum(language_counts.values()),
    )
