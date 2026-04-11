"""Tests for thresher.fs filesystem utilities."""

from __future__ import annotations

import pytest

from thresher.fs import tempfile_with


class TestTempfileWith:
    def test_yields_path_with_content(self):
        with tempfile_with("hello world") as path:
            assert path.exists()
            assert path.read_text() == "hello world"

    def test_respects_suffix(self):
        with tempfile_with("x", suffix=".json") as path:
            assert path.name.endswith(".json")

    def test_unlinks_on_normal_exit(self):
        with tempfile_with("x") as path:
            saved = path
            assert saved.exists()
        assert not saved.exists()

    def test_unlinks_on_exception(self):
        saved = None
        with pytest.raises(RuntimeError, match="boom"):
            with tempfile_with("x") as path:
                saved = path
                raise RuntimeError("boom")
        assert saved is not None
        assert not saved.exists()

    def test_tolerates_already_deleted(self):
        """If the file is removed inside the block, __exit__ doesn't raise."""
        with tempfile_with("x") as path:
            path.unlink()
            assert not path.exists()

    def test_each_call_returns_unique_path(self):
        with tempfile_with("a") as p1, tempfile_with("b") as p2:
            assert p1 != p2
            assert p1.read_text() == "a"
            assert p2.read_text() == "b"

    def test_accepts_empty_content(self):
        with tempfile_with("") as path:
            assert path.exists()
            assert path.read_text() == ""
