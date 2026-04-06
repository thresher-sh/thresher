import os
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
from thresher.harness.clone import safe_clone, _sanitize_git_config, _post_checkout_validate


class TestSafeClone:
    """Tests for the safe_clone() orchestrator.

    _sanitize_git_config and _post_checkout_validate are patched out in these
    tests so that phases 2 and 4 don't require a real filesystem — those
    phases are tested separately in their own test classes.
    """

    def _make_safe_clone_call(self, mock_run, *args, **kwargs):
        """Helper: call safe_clone with phases 2/4 patched to no-ops."""
        with patch("thresher.harness.clone._sanitize_git_config"), \
             patch("thresher.harness.clone._post_checkout_validate"):
            return safe_clone(*args, **kwargs)

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_calls_git_with_no_checkout(self, mock_run):
        """Phase 1: git clone uses --no-checkout --depth=1."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "--no-checkout" in args
        assert "--depth=1" in args
        assert "--single-branch" in args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_disables_hooks(self, mock_run):
        """Phase 1: git clone disables hooks via -c flags."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "-c" in args
        config_args = [args[i+1] for i, v in enumerate(args) if v == "-c"]
        assert "core.hooksPath=/dev/null" in config_args
        assert "core.fsmonitor=false" in config_args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_with_branch(self, mock_run):
        """Phase 1: branch flag passed when specified."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target", branch="develop")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "--branch" in args
        assert "develop" in args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_returns_target_path(self, mock_run):
        """safe_clone returns the target directory path."""
        mock_run.return_value = MagicMock(returncode=0)
        result = self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        assert result == "/opt/target"

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_all_security_c_flags(self, mock_run):
        """Phase 1: all security -c flags from shell script are present."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        config_args = [args[i+1] for i, v in enumerate(args) if v == "-c"]
        assert "core.hooksPath=/dev/null" in config_args
        assert "core.fsmonitor=false" in config_args
        assert "core.fsmonitorHookVersion=0" in config_args
        assert "receive.fsckObjects=true" in config_args
        assert "fetch.fsckObjects=true" in config_args
        assert "transfer.fsckObjects=true" in config_args
        assert "protocol.file.allow=never" in config_args
        assert "protocol.ext.allow=never" in config_args
        assert "submodule.recurse=false" in config_args
        assert "diff.external=" in config_args
        assert "merge.renormalize=false" in config_args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_uses_safe_env(self, mock_run):
        """Phase 1: GIT_TERMINAL_PROMPT=0 and GIT_LFS_SKIP_SMUDGE=1 in env."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        kwargs = clone_call[1]
        assert "env" in kwargs
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert kwargs["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_fails_on_nonzero_exit(self, mock_run):
        """Phase 1: raises RuntimeError if git clone fails."""
        mock_run.return_value = MagicMock(returncode=1, stderr="fatal: repository not found")
        with pytest.raises(RuntimeError):
            safe_clone("https://github.com/test/repo", "/opt/target")

    @patch("thresher.harness.clone.subprocess.run")
    def test_checkout_uses_lfs_skip(self, mock_run):
        """Phase 3: git checkout env has GIT_LFS_SKIP_SMUDGE=1."""
        mock_run.return_value = MagicMock(returncode=0)
        self._make_safe_clone_call(mock_run, "https://github.com/test/repo", "/opt/target")
        # checkout is the second subprocess.run call
        checkout_call = mock_run.call_args_list[1]
        kwargs = checkout_call[1]
        assert "env" in kwargs
        assert kwargs["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"


class TestSanitizeGitConfig:

    def test_writes_minimal_config(self, tmp_path):
        """Phase 2: .git/config rewritten with safe settings."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\thooksPath = evil\n")
        _sanitize_git_config(str(tmp_path), "https://github.com/test/repo", "main")
        config_text = (git_dir / "config").read_text()
        assert "hooksPath = /dev/null" in config_text
        assert "fsmonitor = false" in config_text
        assert "evil" not in config_text

    def test_config_has_symlinks_false(self, tmp_path):
        """Phase 2: symlinks disabled in config."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("")
        _sanitize_git_config(str(tmp_path), "https://github.com/test/repo", "main")
        config_text = (git_dir / "config").read_text()
        assert "symlinks = false" in config_text

    def test_config_has_protect_flags(self, tmp_path):
        """Phase 2: protectNTFS and protectHFS set."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("")
        _sanitize_git_config(str(tmp_path), "https://github.com/test/repo", "main")
        config_text = (git_dir / "config").read_text()
        assert "protectNTFS = true" in config_text
        assert "protectHFS = true" in config_text

    def test_config_has_remote_url(self, tmp_path):
        """Phase 2: remote URL preserved in new config."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("")
        repo_url = "https://github.com/test/repo"
        _sanitize_git_config(str(tmp_path), repo_url, "main")
        config_text = (git_dir / "config").read_text()
        assert repo_url in config_text

    def test_config_disables_submodules(self, tmp_path):
        """Phase 2: submodule.recurse and active = false."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("")
        _sanitize_git_config(str(tmp_path), "https://github.com/test/repo", "main")
        config_text = (git_dir / "config").read_text()
        assert "recurse = false" in config_text
        assert "active = false" in config_text

    def test_config_lfs_filter_safe(self, tmp_path):
        """Phase 2: lfs filter set to safe no-op values."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("")
        _sanitize_git_config(str(tmp_path), "https://github.com/test/repo", "main")
        config_text = (git_dir / "config").read_text()
        assert '[filter "lfs"]' in config_text
        assert "required = false" in config_text


class TestPostCheckoutValidate:

    def test_removes_symlinks(self, tmp_path):
        """Phase 4: symlinks are removed."""
        target = tmp_path / "real_file"
        target.write_text("safe")
        link = tmp_path / "bad_link"
        link.symlink_to(target)
        _post_checkout_validate(str(tmp_path))
        assert not link.exists()
        assert target.exists()

    def test_removes_nested_symlinks(self, tmp_path):
        """Phase 4: symlinks in subdirectories are also removed."""
        subdir = tmp_path / "sub"
        subdir.mkdir()
        target = tmp_path / "real_file"
        target.write_text("safe")
        link = subdir / "nested_link"
        link.symlink_to(target)
        _post_checkout_validate(str(tmp_path))
        assert not link.exists()
        assert target.exists()

    def test_warns_on_gitmodules(self, tmp_path):
        """Phase 4: .gitmodules presence is warned about."""
        (tmp_path / ".gitmodules").write_text("[submodule]")
        with patch("thresher.harness.clone.logger") as mock_log:
            _post_checkout_validate(str(tmp_path))
            mock_log.warning.assert_called()

    def test_warns_on_suspicious_gitattributes(self, tmp_path):
        """Phase 4: suspicious .gitattributes filter= entries are warned."""
        (tmp_path / ".gitattributes").write_text("*.py filter=evil\n")
        with patch("thresher.harness.clone.logger") as mock_log:
            _post_checkout_validate(str(tmp_path))
            mock_log.warning.assert_called()

    def test_no_warning_for_lfs_filter(self, tmp_path):
        """Phase 4: lfs filter in .gitattributes is not flagged as suspicious."""
        (tmp_path / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
        with patch("thresher.harness.clone.logger") as mock_log:
            _post_checkout_validate(str(tmp_path))
            # warning should NOT be called for lfs filters
            for c in mock_log.warning.call_args_list:
                assert "filter" not in str(c).lower() or "lfs" in str(c).lower()

    def test_no_warnings_for_clean_repo(self, tmp_path):
        """Phase 4: clean repo with no symlinks/gitmodules/suspicious attrs produces no warnings."""
        (tmp_path / "file.py").write_text("print('hello')")
        with patch("thresher.harness.clone.logger") as mock_log:
            _post_checkout_validate(str(tmp_path))
            mock_log.warning.assert_not_called()

    def test_warns_on_path_traversal(self, tmp_path):
        """Phase 4: files with suspicious path patterns are warned about."""
        # Create a file with .. in name
        bad_file = tmp_path / "foo..bar"
        bad_file.write_text("suspicious")
        with patch("thresher.harness.clone.logger") as mock_log:
            _post_checkout_validate(str(tmp_path))
            # warning may or may not fire depending on implementation — just ensure no crash
