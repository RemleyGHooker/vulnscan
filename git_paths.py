"""Git helpers: files touched in the last commit."""

from __future__ import annotations

import subprocess
from pathlib import Path


def git_toplevel(start: Path) -> Path | None:
    r = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        return None
    return Path(r.stdout.strip()).resolve()


def paths_in_last_commit(root: Path) -> list[str]:
    """Paths (posix relative to repo root) changed in HEAD commit."""
    r = subprocess.run(
        ["git", "-C", str(root), "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        return []
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    return [ln.replace("\\", "/") for ln in lines]
