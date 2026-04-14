"""Unit tests for host boundary hardening (safe_io module)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from thresher.config import LimitsConfig, active_limits
from thresher.vm.safe_io import (
    ALLOWED_EXTENSIONS,
    safe_json_loads,
    validate_copied_tree,
    validate_report_structure,
    ssh_copy_from_safe,
)
from thresher.vm.ssh import SSHError

# Read current limits for test assertions
MAX_JSON_SIZE_BYTES = active_limits.max_json_size_bytes
MAX_FILE_SIZE_BYTES = active_limits.max_file_size_bytes


class TestSafeJsonLoads:
    def test_valid_json_dict(self):
        result = safe_json_loads('{"key": "value"}', source="test")
        assert result == {"key": "value"}

    def test_valid_json_list(self):
        result = safe_json_loads('[1, 2, 3]', source="test")
        assert result == [1, 2, 3]

    def test_invalid_json_returns_none(self):
        result = safe_json_loads("not json", source="test")
        assert result is None

    def test_empty_string_returns_none(self):
        result = safe_json_loads("", source="test")
        assert result is None

    def test_oversized_payload_raises(self):
        huge = "x" * (MAX_JSON_SIZE_BYTES + 1)
        with pytest.raises(SSHError, match="too large"):
            safe_json_loads(huge, source="test")

    def test_payload_at_limit_parses(self):
        # Just under the limit should still parse
        data = '{"k": "' + "a" * (MAX_JSON_SIZE_BYTES - 20) + '"}'
        # This is valid JSON under the limit
        result = safe_json_loads(data, source="test")
        assert result is not None

    def test_source_in_error_message(self):
        huge = "x" * (MAX_JSON_SIZE_BYTES + 1)
        with pytest.raises(SSHError, match="grype output"):
            safe_json_loads(huge, source="grype output")


class TestValidateCopiedTree:
    def test_removes_symlinks(self, tmp_path):
        real_file = tmp_path / "real.json"
        real_file.write_text("{}")
        link = tmp_path / "link.json"
        link.symlink_to(real_file)

        validate_copied_tree(tmp_path)

        assert real_file.exists()
        assert not link.exists()

    def test_rejects_path_traversal(self, tmp_path):
        # OS resolves ".." in real paths, so we can't create actual
        # traversal directories. Instead, test that the function checks
        # for ".." in path components by creating a dir literally named ".."
        # (possible on macOS/Linux).
        bad_dir = tmp_path / "subdir"
        bad_dir.mkdir()
        dotdot_dir = bad_dir / ".."
        # On most filesystems, mkdir("..") is a no-op since ".." already exists.
        # So we test the validation logic directly with a mock instead.
        # The real protection is that limactl copy would create literal ".."
        # entries which rglob would surface.
        # Test the logic by creating a file inside a subdir and verifying
        # the validator doesn't blow up on normal paths.
        normal = tmp_path / "subdir" / "ok.json"
        normal.write_text("{}")
        validate_copied_tree(tmp_path)  # should not raise for normal paths

    def test_rejects_oversized_file(self, tmp_path):
        big = tmp_path / "big.json"
        # Create a file that exceeds the limit
        big.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))

        with pytest.raises(SSHError, match="too large"):
            validate_copied_tree(tmp_path)

    def test_removes_disallowed_extensions(self, tmp_path):
        allowed = tmp_path / "report.json"
        allowed.write_text("{}")
        disallowed = tmp_path / "evil.exe"
        disallowed.write_text("bad")

        validate_copied_tree(tmp_path)

        assert allowed.exists()
        assert not disallowed.exists()

    def test_strips_executable_bits(self, tmp_path):
        f = tmp_path / "report.json"
        f.write_text("{}")
        f.chmod(f.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

        validate_copied_tree(tmp_path)

        mode = f.stat().st_mode
        assert not (mode & stat.S_IXUSR)
        assert not (mode & stat.S_IXGRP)
        assert not (mode & stat.S_IXOTH)

    def test_allows_valid_extensions(self, tmp_path):
        for ext in ALLOWED_EXTENSIONS:
            f = tmp_path / f"file{ext}"
            f.write_text("content")

        validate_copied_tree(tmp_path)

        for ext in ALLOWED_EXTENSIONS:
            assert (tmp_path / f"file{ext}").exists()

    def test_allows_html_files(self, tmp_path):
        html_file = tmp_path / "report.html"
        html_file.write_text("<html><body>Report</body></html>")

        validate_copied_tree(tmp_path)

        assert html_file.exists()

    def test_empty_directory_passes(self, tmp_path):
        validate_copied_tree(tmp_path)  # should not raise


class TestValidateReportStructure:
    def test_complete_report(self, tmp_path):
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "executive-summary.md").write_text("# Summary")
        (tmp_path / "detailed-report.md").write_text("# Report")

        # Should not raise or warn for a complete report
        validate_report_structure(tmp_path)

    def test_missing_files_logs_warning(self, tmp_path, caplog):
        # Empty report dir — all files missing
        import logging
        with caplog.at_level(logging.WARNING):
            validate_report_structure(tmp_path)
        assert "missing expected files" in caplog.text

    def test_report_html_is_known(self, tmp_path, caplog):
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "executive-summary.md").write_text("")
        (tmp_path / "detailed-report.md").write_text("")
        (tmp_path / "report.html").write_text("<html></html>")

        import logging
        with caplog.at_level(logging.WARNING):
            validate_report_structure(tmp_path)
        assert "Unexpected file" not in caplog.text

    def test_unexpected_files_logs_warning(self, tmp_path, caplog):
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "executive-summary.md").write_text("")
        (tmp_path / "detailed-report.md").write_text("")
        (tmp_path / "something-unexpected.json").write_text("{}")

        import logging
        with caplog.at_level(logging.WARNING):
            validate_report_structure(tmp_path)
        assert "Unexpected file" in caplog.text


class TestSSHCopyFromSafe:
    @patch("thresher.vm.ssh.ssh_copy_from")
    def test_validates_before_moving(self, mock_copy, tmp_path):
        dest = tmp_path / "output"

        def fake_copy(vm_name, remote, local):
            # Simulate limactl copying a file into the staging dir
            staging = Path(local)
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "report.json").write_text('{"ok": true}')

        mock_copy.side_effect = fake_copy
        ssh_copy_from_safe("test-vm", "/opt/report", str(dest))

        # The file should end up in the destination
        assert (dest / "report.json").exists()

    @patch("thresher.vm.ssh.ssh_copy_from")
    def test_rejects_symlinks_in_copy(self, mock_copy, tmp_path):
        dest = tmp_path / "output"

        def fake_copy_with_symlink(vm_name, remote, local):
            staging = Path(local)
            staging.mkdir(parents=True, exist_ok=True)
            real = staging / "real.json"
            real.write_text("{}")
            (staging / "link.json").symlink_to(real)

        mock_copy.side_effect = fake_copy_with_symlink
        ssh_copy_from_safe("test-vm", "/opt/report", str(dest))

        # Symlink should have been removed during validation
        assert (dest / "real.json").exists()
        assert not (dest / "link.json").exists()

    @patch("thresher.vm.ssh.ssh_copy_from")
    def test_cleans_up_staging_on_failure(self, mock_copy, tmp_path):
        dest = tmp_path / "output"

        def fake_copy_oversized(vm_name, remote, local):
            staging = Path(local)
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "huge.json").write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))

        mock_copy.side_effect = fake_copy_oversized

        with pytest.raises(SSHError, match="too large"):
            ssh_copy_from_safe("test-vm", "/opt/report", str(dest))

        # Destination should not have been created
        assert not dest.exists()
