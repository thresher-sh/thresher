"""Filesystem utilities."""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def tempfile_with(content: str, *, suffix: str = "") -> Iterator[Path]:
    """Write *content* to a tempfile, yield its path, unlink on exit.

    Uses ``tempfile.mkstemp`` so the file is created atomically with no
    race window — the deprecated ``tempfile.mktemp`` returns a name that
    another process can grab before you open it.

    The file is always removed: on normal exit, on exception, and even
    if something inside the block already deleted it.
    """
    fd, path_str = tempfile.mkstemp(suffix=suffix)
    path = Path(path_str)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        yield path
    finally:
        path.unlink(missing_ok=True)
