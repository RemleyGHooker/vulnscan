"""Discover source files, optional Git clone, and chunk with line numbers."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Iterator

from git import Repo

PRIORITY_EXTENSIONS = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".py", ".js", ".jsx", ".ts", ".tsx")
OTHER_CODE_EXTENSIONS = (
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".m",
    ".mm",
    ".sql",
    ".sh",
    ".bash",
    ".zsh",
)

# Env / small config files (hardcoded secrets review); capped size in discover.
SECRETS_MAX_BYTES = 256_000

SECRETS_EXACT_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
    "docker-compose.yml",
    "docker-compose.yaml",
}
SECRETS_SUFFIXES = (".env",)  # e.g. foo.env

CONFIG_BASENAMES = {
    "config.yaml",
    "config.yml",
    "application.yaml",
    "application.yml",
    "settings.json",
    "credentials.json",
    "secrets.json",
}

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    ".idea",
    ".vscode",
}


def is_github_url(target: str) -> bool:
    return bool(
        re.match(
            r"^https?://(www\.)?github\.com/[\w.-]+/[\w.-]+/?",
            target.strip(),
            re.IGNORECASE,
        )
    )


def clone_repo(url: str, target: Path | None = None) -> Path:
    tmp = target if target is not None else Path(tempfile.mkdtemp(prefix="vulnscan_clone_"))
    tmp.mkdir(parents=True, exist_ok=True)
    Repo.clone_from(url, tmp, depth=1)
    return tmp


def cleanup_clone(path: Path | None) -> None:
    if path and path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _extension_order(path: Path) -> tuple[int, str]:
    ext = path.suffix.lower()
    if ext in PRIORITY_EXTENSIONS:
        return (0, ext)
    if ext in OTHER_CODE_EXTENSIONS:
        return (1, ext)
    return (2, ext)


def _is_secrets_or_config_candidate(p: Path) -> bool:
    if not p.is_file():
        return False
    try:
        if p.stat().st_size > SECRETS_MAX_BYTES:
            return False
    except OSError:
        return False
    name = p.name
    lower = name.lower()
    if lower in SECRETS_EXACT_NAMES or lower in CONFIG_BASENAMES:
        return True
    if lower.startswith(".env"):
        return True
    if lower.endswith(".env"):
        return True
    return False


def discover_source_files(
    root: Path,
    *,
    include_secrets_candidates: bool = True,
) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []
    seen: set[Path] = set()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        ext = p.suffix.lower()
        if ext in PRIORITY_EXTENSIONS or ext in OTHER_CODE_EXTENSIONS:
            files.append(p)
            seen.add(p.resolve())
            continue
        if include_secrets_candidates and _is_secrets_or_config_candidate(p):
            rp = p.resolve()
            if rp not in seen:
                files.append(p)
                seen.add(rp)

    files.sort(key=lambda p: (_extension_order(p), str(p.relative_to(root))))
    return files


def language_from_path(path: Path) -> str:
    ext = path.suffix.lower()
    mapping = {
        ".py": "python",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".swift": "swift",
        ".sql": "sql",
        ".sh": "shell",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".json": "json",
    }
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    return mapping.get(ext, "unknown")


def chunk_file_lines(
    path: Path,
    root: Path,
    max_lines: int = 120,
    overlap_lines: int = 10,
) -> Iterator[tuple[str, int, int]]:
    """
    Yields (chunk_text_with_line_prefixes, start_line, end_line).
    Lines are 1-based in output.
    """
    rel = str(path.relative_to(root)).replace("\\", "/")
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return

    n = len(lines)
    start = 0
    while start < n:
        end = min(start + max_lines, n)
        segment = lines[start:end]
        numbered = "\n".join(f"{start + i + 1}|{line}" for i, line in enumerate(segment))
        yield numbered, start + 1, end
        if end >= n:
            break
        start = max(0, end - overlap_lines)
