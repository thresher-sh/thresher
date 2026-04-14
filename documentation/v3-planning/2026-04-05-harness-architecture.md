# Harness Architecture Redesign — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure Thresher from SSH-into-VM orchestration to a self-contained Hamilton DAG harness that runs anywhere, launched by a thin CLI.

**Architecture:** The harness is a mode-agnostic Python package (`thresher.harness`) that runs the full scan pipeline and writes reports to an output directory. The CLI is a thin launcher that decides where to run the harness (direct subprocess, Docker container, or Lima+Docker). Apache Hamilton defines the pipeline DAG. A single Docker image contains everything.

**Tech Stack:** Python 3.11+, Apache Hamilton (sf-hamilton), Click, Jinja2, subprocess, Docker, Lima

**Spec:** `docs/superpowers/specs/2026-04-05-harness-architecture-design.md`

**Spec Deviations:**
- **Scanner parallelization:** The spec defines individual Hamilton DAG nodes per scanner (22 functions). This plan uses a single `scan_results` node with internal `ThreadPoolExecutor` parallelization instead. Rationale: avoids 22 boilerplate Hamilton node functions that all delegate to `run_<tool>()` with slightly different kwargs. The dependency resolution (which scanners need sbom vs. source vs. deps) is handled in `_resolve_scanner_kwargs()` rather than Hamilton parameter names. The end result is the same parallel execution with less code.
- **Report/synthesize private functions:** `harness/report.py` imports `_collect_findings` and `_normalize_scanner_output` from `report/synthesize.py`. These are currently private-prefixed. During implementation, either rename them to be public or verify they exist before importing.

---

## Chunk 1: Foundation — Config, Harness Scaffold, Hamilton Pipeline

### Task 1: Add Hamilton dependency and update config

**Files:**
- Modify: `pyproject.toml:11-16` (add sf-hamilton dependency)
- Modify: `src/thresher/config.py:77-125` (add launch_mode, update ScanConfig)
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing test for launch_mode config**

```python
# tests/unit/test_config.py — add to existing tests

def test_scan_config_launch_mode_default():
    """launch_mode defaults to 'lima'."""
    config = ScanConfig()
    assert config.launch_mode == "lima"

def test_scan_config_launch_mode_from_dict():
    """launch_mode can be set from config dict."""
    config = ScanConfig(launch_mode="docker")
    assert config.launch_mode == "docker"

def test_scan_config_launch_mode_validates():
    """launch_mode rejects invalid values."""
    config = ScanConfig(launch_mode="invalid")
    with pytest.raises(ValueError, match="launch_mode"):
        config.validate()

def test_scan_config_serializes_to_json():
    """ScanConfig can round-trip through JSON for harness handoff."""
    import json
    config = ScanConfig(repo_url="https://github.com/test/repo", launch_mode="docker")
    blob = config.to_json()
    restored = ScanConfig.from_json(blob)
    assert restored.repo_url == config.repo_url
    assert restored.launch_mode == config.launch_mode

def test_scan_config_from_json():
    """ScanConfig.from_json handles all fields."""
    import json
    data = json.dumps({"repo_url": "https://example.com/repo", "launch_mode": "direct",
                       "skip_ai": True, "model": "opus"})
    config = ScanConfig.from_json(data)
    assert config.launch_mode == "direct"
    assert config.skip_ai is True
    assert config.model == "opus"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_config.py -v -k "launch_mode or serializes_to_json or from_json"`
Expected: FAIL — `launch_mode` attribute doesn't exist, no `to_json`/`from_json` methods

- [ ] **Step 3: Add launch_mode to ScanConfig and JSON serialization**

In `src/thresher/config.py`, add to the `ScanConfig` dataclass (around line 95):

```python
    launch_mode: str = "lima"  # lima | docker | direct
```

Add validation in the `validate()` method (around line 114):

```python
        if self.launch_mode not in ("lima", "docker", "direct"):
            raise ValueError(f"launch_mode must be lima, docker, or direct, got {self.launch_mode!r}")
```

Add serialization methods to `ScanConfig`:

```python
    def to_json(self) -> str:
        """Serialize config to JSON for harness handoff."""
        import json
        data = {
            "repo_url": self.repo_url,
            "depth": self.depth,
            "skip_ai": self.skip_ai,
            "verbose": self.verbose,
            "output_dir": self.output_dir,
            "model": self.model,
            "log_dir": self.log_dir,
            "tmux": self.tmux,
            "high_risk_dep": self.high_risk_dep,
            "branch": self.branch,
            "launch_mode": self.launch_mode,
            "analyst_max_turns": self.analyst_max_turns,
            "analyst_max_turns_by_name": self.analyst_max_turns_by_name,
            "adversarial_max_turns": self.adversarial_max_turns,
            "limits": {
                "max_json_size_mb": self.limits.max_json_size_mb,
                "max_file_size_mb": self.limits.max_file_size_mb,
                "max_copy_size_mb": self.limits.max_copy_size_mb,
                "max_stdout_mb": self.limits.max_stdout_mb,
                "max_concurrent_ssh": self.limits.max_concurrent_ssh,
            },
        }
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> "ScanConfig":
        """Deserialize config from JSON (used by harness)."""
        import json
        data = json.loads(json_str)
        limits_data = data.pop("limits", {})
        limits = LimitsConfig(**limits_data) if limits_data else LimitsConfig()
        return cls(limits=limits, **data)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_config.py -v -k "launch_mode or serializes_to_json or from_json"`
Expected: PASS

- [ ] **Step 5: Add sf-hamilton to pyproject.toml**

In `pyproject.toml`, add to the dependencies list (around line 15):

```toml
    "sf-hamilton>=1.82",
```

- [ ] **Step 6: Install updated dependencies**

Run: `pip install -e ".[dev]"`
Expected: sf-hamilton installs successfully

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/thresher/config.py tests/unit/test_config.py
git commit -m "feat: add launch_mode to ScanConfig, JSON serialization, Hamilton dep"
```

---

### Task 2: Create harness package scaffold

**Files:**
- Create: `src/thresher/harness/__init__.py`
- Create: `src/thresher/harness/__main__.py`
- Modify: `pyproject.toml:24-28` (add thresher-harness entrypoint)
- Test: `tests/unit/test_harness_main.py`

- [ ] **Step 1: Write failing test for harness main**

```python
# tests/unit/test_harness_main.py

import json
import tempfile
from unittest.mock import patch, MagicMock
from thresher.harness.__main__ import parse_args, main


def test_parse_args_requires_config():
    """Harness requires --config argument."""
    import sys
    with pytest.raises(SystemExit):
        parse_args([])


def test_parse_args_reads_config_file():
    """Harness reads config from JSON file."""
    config_data = {"repo_url": "https://github.com/test/repo", "skip_ai": True}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        f.flush()
        args = parse_args(["--config", f.name])
    assert args.config == f.name


def test_parse_args_output_default():
    """Harness defaults output to /output."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"repo_url": "https://example.com/r"}, f)
        f.flush()
        args = parse_args(["--config", f.name])
    assert args.output == "/output"


def test_parse_args_output_override():
    """Harness allows --output override."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"repo_url": "https://example.com/r"}, f)
        f.flush()
        args = parse_args(["--config", f.name, "--output", "/tmp/reports"])
    assert args.output == "/tmp/reports"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_harness_main.py -v`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Create harness package**

```python
# src/thresher/harness/__init__.py

"""Thresher harness — self-contained scan pipeline."""


def main():
    """Entry point for thresher-harness command."""
    from thresher.harness.__main__ import main as _main
    _main()
```

```python
# src/thresher/harness/__main__.py

"""Harness CLI — runs the full scan pipeline.

Usage:
    python -m thresher.harness --config config.json [--output /output]
    thresher-harness --config config.json [--output /output]
"""

import argparse
import json
import logging
import sys

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Thresher scan harness")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument("--output", default="/output", help="Output directory for report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    with open(args.config) as f:
        config = ScanConfig.from_json(f.read())

    config.output_dir = args.output
    logging.basicConfig(
        level=logging.DEBUG if config.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logger.info("Harness starting — repo=%s output=%s", config.repo_url, config.output_dir)

    # Pipeline execution will be wired in Task 3
    from thresher.harness.pipeline import run_pipeline
    run_pipeline(config)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_harness_main.py -v -k "not main"` (skip main, pipeline not wired yet)
Expected: PASS for parse_args tests

- [ ] **Step 5: Add entrypoint to pyproject.toml**

In `pyproject.toml`, add to `[project.scripts]` (around line 27):

```toml
thresher-harness = "thresher.harness:main"
```

- [ ] **Step 6: Commit**

```bash
git add src/thresher/harness/ tests/unit/test_harness_main.py pyproject.toml
git commit -m "feat: create harness package scaffold with CLI entrypoint"
```

---

### Task 3: Create Hamilton pipeline skeleton

**Files:**
- Create: `src/thresher/harness/pipeline.py`
- Create: `tests/unit/test_pipeline.py`

- [ ] **Step 1: Write failing test for pipeline DAG structure**

```python
# tests/unit/test_pipeline.py

import pytest
from unittest.mock import patch, MagicMock
from hamilton import driver
from thresher.harness import pipeline
from thresher.config import ScanConfig


def test_pipeline_module_has_required_functions():
    """Pipeline module defines all DAG node functions."""
    required = [
        "cloned_path", "ecosystems", "hidden_deps", "deps_path",
        "sbom_path", "scan_results", "analyst_findings",
        "verified_findings", "enriched_findings", "report_path",
    ]
    for name in required:
        assert hasattr(pipeline, name), f"Missing DAG node: {name}"


def test_pipeline_dag_builds():
    """Hamilton driver can build a DAG from the pipeline module."""
    dr = driver.Builder().with_modules(pipeline).build()
    assert dr is not None


def test_pipeline_skip_ai_short_circuits():
    """When skip_ai=True, AI stages return empty results."""
    config = ScanConfig(repo_url="https://example.com/repo", skip_ai=True)
    config_dict = {"skip_ai": True, "high_risk_dep": False}
    result = pipeline.hidden_deps(cloned_path="/opt/target", config=config_dict)
    assert result == {}


def test_run_pipeline_calls_hamilton_execute(tmp_path):
    """run_pipeline builds and executes the Hamilton DAG."""
    config = ScanConfig(
        repo_url="https://github.com/test/repo",
        output_dir=str(tmp_path),
        skip_ai=True,
    )
    with patch("thresher.harness.pipeline._build_driver") as mock_build:
        mock_dr = MagicMock()
        mock_dr.execute.return_value = {"report_path": str(tmp_path / "report")}
        mock_build.return_value = mock_dr
        pipeline.run_pipeline(config)
        mock_dr.execute.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_pipeline.py -v`
Expected: FAIL — pipeline module doesn't exist

- [ ] **Step 3: Create pipeline module with DAG node stubs**

```python
# src/thresher/harness/pipeline.py

"""Hamilton DAG pipeline for the Thresher scan harness.

Each function is a DAG node. Parameter names define dependencies.
Hamilton auto-resolves the execution graph and parallelizes independent nodes.
"""

import logging
from hamilton import driver

from thresher.config import ScanConfig
from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)


# ── DAG Node Functions ──────────────────────────────────────────────


def cloned_path(repo_url: str, config: dict) -> str:
    """Clone repo using hardened git clone."""
    from thresher.harness.clone import safe_clone
    branch = config.get("branch", "")
    return safe_clone(repo_url, "/opt/target", branch=branch)


def ecosystems(cloned_path: str) -> list[str]:
    """Detect package ecosystems in the cloned repo."""
    from thresher.harness.deps import detect_ecosystems
    return detect_ecosystems(cloned_path)


def hidden_deps(cloned_path: str, config: dict) -> dict:
    """Pre-dep agent discovers hidden dependencies. Skipped if skip_ai."""
    if config.get("skip_ai"):
        return {}
    from thresher.agents.predep import run_predep_discovery
    return run_predep_discovery(cloned_path, config)


def deps_path(cloned_path: str, ecosystems: list[str],
              hidden_deps: dict, config: dict) -> str:
    """Resolve and download dependencies as source-only."""
    from thresher.harness.deps import resolve_deps
    return resolve_deps(cloned_path, ecosystems, hidden_deps, config)


def sbom_path(cloned_path: str, output_dir: str) -> str:
    """Generate SBOM with Syft (sequential, required before Grype)."""
    from thresher.scanners.syft import run_syft
    result = run_syft(cloned_path, output_dir)
    return result.metadata.get("sbom_path", f"{output_dir}/sbom.json")


def scan_results(sbom_path: str, cloned_path: str, deps_path: str,
                 output_dir: str, config: dict) -> list[ScanResults]:
    """Run all scanners in parallel and aggregate results."""
    from thresher.harness.scanning import run_all_scanners
    return run_all_scanners(
        sbom_path=sbom_path,
        target_dir=cloned_path,
        deps_dir=deps_path,
        output_dir=output_dir,
        config=config,
    )


def analyst_findings(cloned_path: str, deps_path: str,
                     scan_results: list[ScanResults],
                     config: dict) -> list[dict]:
    """Run 8 analyst agents in parallel. Depends on scan_results for ordering."""
    if config.get("skip_ai"):
        return []
    from thresher.agents.analysts import run_all_analysts
    return run_all_analysts(cloned_path, deps_path, config)


def verified_findings(analyst_findings: list[dict],
                      cloned_path: str, config: dict) -> list[dict]:
    """Adversarial agent verifies high-risk findings."""
    if config.get("skip_ai") or not analyst_findings:
        return analyst_findings
    from thresher.agents.adversarial import run_adversarial_verification
    return run_adversarial_verification(analyst_findings, cloned_path, config)


def enriched_findings(scan_results: list[ScanResults],
                      verified_findings: list[dict]) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    from thresher.harness.report import enrich_all_findings
    return enrich_all_findings(scan_results, verified_findings)


def report_path(enriched_findings: dict, scan_results: list[ScanResults],
                config: dict) -> str:
    """Synthesize final report and write to output directory."""
    from thresher.harness.report import generate_report
    return generate_report(enriched_findings, scan_results, config)


# ── Pipeline Runner ─────────────────────────────────────────────────


def _build_driver() -> driver.Driver:
    """Build Hamilton driver from this module."""
    import thresher.harness.pipeline as pipeline_module
    return driver.Builder().with_modules(pipeline_module).build()


def run_pipeline(config: ScanConfig) -> str:
    """Execute the full scan pipeline via Hamilton DAG."""
    dr = _build_driver()

    config_dict = {
        "skip_ai": config.skip_ai,
        "high_risk_dep": config.high_risk_dep,
        "model": config.model,
        "branch": config.branch,
        "verbose": config.verbose,
        "depth": config.depth,
        "analyst_max_turns": config.analyst_max_turns,
        "analyst_max_turns_by_name": config.analyst_max_turns_by_name,
        "adversarial_max_turns": config.adversarial_max_turns,
    }

    inputs = {
        "repo_url": config.repo_url,
        "config": config_dict,
        "output_dir": "/opt/scan-results",
    }

    logger.info("Executing pipeline DAG")
    result = dr.execute(
        final_vars=["report_path"],
        inputs=inputs,
    )

    report = result["report_path"]
    logger.info("Pipeline complete — report at %s", report)
    return report
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_pipeline.py -v`
Expected: PASS

- [ ] **Step 5: Re-run Task 2's skipped harness main test**

Run: `python -m pytest tests/unit/test_harness_main.py -v`
Expected: PASS (pipeline.run_pipeline now importable)

- [ ] **Step 6: Commit**

```bash
git add src/thresher/harness/pipeline.py tests/unit/test_pipeline.py
git commit -m "feat: create Hamilton pipeline DAG skeleton with all node functions"
```

---

## Chunk 2: Core Harness Modules — Clone, Deps, Scanning, Report

### Task 4: Port hardened git clone to Python

**Files:**
- Create: `src/thresher/harness/clone.py`
- Create: `tests/unit/test_clone.py`
- Reference: `vm_scripts/safe_clone.sh` (lines 1-134, the 4-phase clone)

- [ ] **Step 1: Write failing tests for safe_clone**

```python
# tests/unit/test_clone.py

import os
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
from thresher.harness.clone import safe_clone, _sanitize_git_config, _post_checkout_validate


class TestSafeClone:

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_calls_git_with_no_checkout(self, mock_run):
        """Phase 1: git clone uses --no-checkout --depth=1."""
        mock_run.return_value = MagicMock(returncode=0)
        safe_clone("https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "--no-checkout" in args
        assert "--depth=1" in args
        assert "--single-branch" in args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_disables_hooks(self, mock_run):
        """Phase 1: git clone disables hooks via -c flags."""
        mock_run.return_value = MagicMock(returncode=0)
        safe_clone("https://github.com/test/repo", "/opt/target")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "-c" in args
        idx = args.index("-c")
        config_args = [args[i+1] for i, v in enumerate(args) if v == "-c"]
        assert "core.hooksPath=/dev/null" in config_args
        assert "core.fsmonitor=false" in config_args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_with_branch(self, mock_run):
        """Phase 1: branch flag passed when specified."""
        mock_run.return_value = MagicMock(returncode=0)
        safe_clone("https://github.com/test/repo", "/opt/target", branch="develop")
        clone_call = mock_run.call_args_list[0]
        args = clone_call[0][0]
        assert "--branch" in args
        assert "develop" in args

    @patch("thresher.harness.clone.subprocess.run")
    def test_clone_returns_target_path(self, mock_run):
        """safe_clone returns the target directory path."""
        mock_run.return_value = MagicMock(returncode=0)
        result = safe_clone("https://github.com/test/repo", "/opt/target")
        assert result == "/opt/target"


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

    def test_detects_path_traversal(self, tmp_path):
        """Phase 4: path traversal patterns are flagged."""
        bad_dir = tmp_path / "sub" / ".." / ".." / "escape"
        # Can't actually create traversal paths, but validate the check
        # exists in the function (implementation will use os.walk)
        _post_checkout_validate(str(tmp_path))  # should not raise

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_clone.py -v`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Implement safe_clone**

```python
# src/thresher/harness/clone.py

"""Hardened git clone — Python port of vm_scripts/safe_clone.sh.

Four-phase defense against code execution during git clone:
1. Fetch without checkout (disable hooks, fsmonitor, LFS)
2. Sanitize repo-level .git/config
3. Checkout with all filters disabled
4. Post-checkout validation (symlinks, path traversal, suspicious files)
"""

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def safe_clone(repo_url: str, target_dir: str, branch: str = "") -> str:
    """Clone a repository with all code execution vectors neutralized.

    Returns the target directory path.
    """
    logger.info("Phase 1: Fetching %s (no checkout)", repo_url)
    _phase1_fetch(repo_url, target_dir, branch)

    logger.info("Phase 2: Sanitizing .git/config")
    default_branch = branch or "HEAD"
    _sanitize_git_config(target_dir, repo_url, default_branch)

    logger.info("Phase 3: Checkout with filters disabled")
    _phase3_checkout(target_dir)

    logger.info("Phase 4: Post-checkout validation")
    _post_checkout_validate(target_dir)

    logger.info("Clone complete: %s", target_dir)
    return target_dir


def _phase1_fetch(repo_url: str, target_dir: str, branch: str) -> None:
    """Fetch repository without checking out any files."""
    cmd = [
        "git", "clone",
        "--no-checkout",
        "--depth=1",
        "--single-branch",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.file.allow=never",
        "-c", "transfer.fsckObjects=true",
        "-c", "fetch.fsckObjects=true",
        "-c", "receive.fsckObjects=true",
    ]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, target_dir])

    result = subprocess.run(
        cmd,
        capture_output=True,
        timeout=300,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"},
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.decode()}")


def _sanitize_git_config(target_dir: str, repo_url: str, branch: str) -> None:
    """Rewrite .git/config with minimal safe settings."""
    git_config = Path(target_dir) / ".git" / "config"
    safe_config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\thooksPath = /dev/null
\tfsmonitor = false
\tautocrlf = false
[remote "origin"]
\turl = {repo_url}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "{branch}"]
\tremote = origin
\tmerge = refs/heads/{branch}
[filter "lfs"]
\tsmudge = cat
\tclean = cat
\tprocess = cat
\trequired = false
[submodule]
\trecurse = false
"""
    git_config.write_text(safe_config)


def _phase3_checkout(target_dir: str) -> None:
    """Checkout files with all filter/hook execution disabled."""
    result = subprocess.run(
        ["git", "checkout"],
        cwd=target_dir,
        capture_output=True,
        timeout=120,
        env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        raise RuntimeError(f"git checkout failed: {result.stderr.decode()}")


def _post_checkout_validate(target_dir: str) -> None:
    """Validate the checkout: remove symlinks, detect suspicious patterns."""
    root = Path(target_dir)

    # Remove symlinks (filesystem escape vector)
    symlinks_removed = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            logger.warning("Removing symlink: %s -> %s", path, os.readlink(path))
            path.unlink()
            symlinks_removed += 1
    if symlinks_removed:
        logger.warning("Removed %d symlinks", symlinks_removed)

    # Check for path traversal
    for path in root.rglob("*"):
        try:
            rel = path.relative_to(root)
            if ".." in rel.parts:
                logger.warning("Path traversal detected: %s", path)
        except ValueError:
            logger.warning("Path outside target: %s", path)

    # Warn on .gitmodules
    gitmodules = root / ".gitmodules"
    if gitmodules.exists():
        logger.warning(".gitmodules found — submodules not initialized (security policy)")

    # Warn on suspicious .gitattributes
    gitattributes = root / ".gitattributes"
    if gitattributes.exists():
        content = gitattributes.read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if "filter=" in stripped and "filter=lfs" not in stripped:
                logger.warning("Suspicious .gitattributes filter: %s", stripped)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_clone.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/thresher/harness/clone.py tests/unit/test_clone.py
git commit -m "feat: port hardened git clone to Python (4-phase safe_clone)"
```

---

### Task 5: Port dependency resolution to Python

**Files:**
- Create: `src/thresher/harness/deps.py`
- Create: `tests/unit/test_deps.py`
- Reference: `docker/scripts/detect.sh`, `docker/scripts/download_*.sh`, `docker/scripts/run.sh`

- [ ] **Step 1: Write failing tests for ecosystem detection**

```python
# tests/unit/test_deps.py

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from thresher.harness.deps import (
    detect_ecosystems,
    download_python,
    download_node,
    download_rust,
    download_go,
    resolve_deps,
    build_manifest,
)


class TestDetectEcosystems:

    def test_detects_python_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_setup_py(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_pipfile(self, tmp_path):
        (tmp_path / "Pipfile").write_text("[packages]\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_node(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}\n')
        assert "node" in detect_ecosystems(str(tmp_path))

    def test_detects_rust(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        assert "rust" in detect_ecosystems(str(tmp_path))

    def test_detects_go(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/test\n")
        assert "go" in detect_ecosystems(str(tmp_path))

    def test_detects_multiple(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "package.json").write_text("{}\n")
        ecosystems = detect_ecosystems(str(tmp_path))
        assert "python" in ecosystems
        assert "node" in ecosystems

    def test_no_ecosystems(self, tmp_path):
        assert detect_ecosystems(str(tmp_path)) == []


class TestDownloadPython:

    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_pip_download_no_binary(self, mock_run, tmp_path):
        """Python deps downloaded with --no-binary :all: (source only)."""
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "requirements.txt").write_text("flask==2.0\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_python(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "pip" in args[0] or "pip3" in args[0]
        assert "--no-binary" in args
        assert ":all:" in args


class TestDownloadNode:

    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_npm_pack(self, mock_run, tmp_path):
        """Node deps downloaded via npm pack (no postinstall)."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"")
        src = tmp_path / "src"
        src.mkdir()
        pkg = {"dependencies": {"express": "4.18.0"}}
        (src / "package.json").write_text(json.dumps(pkg))
        deps = tmp_path / "deps"
        deps.mkdir()
        download_node(str(src), str(deps))
        npm_calls = [c for c in mock_run.call_args_list if "npm" in str(c)]
        assert len(npm_calls) > 0


class TestDownloadRust:

    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_cargo_vendor(self, mock_run, tmp_path):
        """Rust deps downloaded via cargo vendor."""
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "Cargo.toml").write_text("[package]\nname = 'test'\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_rust(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "cargo" in args
        assert "vendor" in args


class TestDownloadGo:

    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_go_mod_vendor(self, mock_run, tmp_path):
        """Go deps downloaded via go mod vendor."""
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "go.mod").write_text("module example.com/test\ngo 1.21\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_go(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "go" in args
        assert "vendor" in args[1:] or "mod" in args


class TestBuildManifest:

    def test_writes_manifest_json(self, tmp_path):
        """build_manifest writes dep_manifest.json."""
        py_dir = tmp_path / "python"
        py_dir.mkdir()
        (py_dir / "flask-2.0.tar.gz").write_text("fake")
        build_manifest(str(tmp_path))
        manifest = tmp_path / "dep_manifest.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert "python" in data


class TestResolveDeps:

    @patch("thresher.harness.deps.download_python")
    @patch("thresher.harness.deps.download_node")
    @patch("thresher.harness.deps.build_manifest")
    def test_calls_downloaders_for_detected_ecosystems(
        self, mock_manifest, mock_node, mock_python, tmp_path
    ):
        """resolve_deps calls the right downloader for each ecosystem."""
        deps_dir = str(tmp_path / "deps")
        resolve_deps(
            target_dir="/opt/target",
            ecosystems=["python", "node"],
            hidden_deps={},
            config={"depth": 2, "high_risk_dep": False},
            deps_dir=deps_dir,
        )
        mock_python.assert_called_once()
        mock_node.assert_called_once()
        mock_manifest.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_deps.py -v`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Implement deps module**

```python
# src/thresher/harness/deps.py

"""Dependency resolution — Python port of docker/scripts/*.sh.

Detects ecosystems, downloads dependencies as source-only (no install scripts),
builds a manifest of what was downloaded.
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

DEPS_DIR = "/opt/deps"

# Manifest files that indicate each ecosystem
_ECOSYSTEM_INDICATORS = {
    "python": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "node": ["package.json"],
    "rust": ["Cargo.toml"],
    "go": ["go.mod"],
}

_DOWNLOADERS = {
    "python": "download_python",
    "node": "download_node",
    "rust": "download_rust",
    "go": "download_go",
}


def detect_ecosystems(target_dir: str) -> list[str]:
    """Detect which package ecosystems are present in the target directory."""
    root = Path(target_dir)
    detected = []
    for eco, indicators in _ECOSYSTEM_INDICATORS.items():
        for indicator in indicators:
            if (root / indicator).exists():
                detected.append(eco)
                break
    logger.info("Detected ecosystems: %s", detected or "none")
    return detected


def resolve_deps(target_dir: str, ecosystems: list[str],
                 hidden_deps: dict, config: dict,
                 deps_dir: str = DEPS_DIR) -> str:
    """Download dependencies for all detected ecosystems. Returns deps directory."""
    os.makedirs(deps_dir, exist_ok=True)

    for eco in ecosystems:
        fn_name = _DOWNLOADERS.get(eco)
        if fn_name:
            fn = globals()[fn_name]
            try:
                fn(target_dir, deps_dir)
            except Exception:
                logger.exception("Failed to download %s dependencies", eco)

    # Process hidden dependencies from predep agent
    if hidden_deps and hidden_deps.get("hidden_dependencies"):
        download_hidden(hidden_deps, deps_dir, config)

    build_manifest(deps_dir)
    logger.info("Dependency resolution complete: %s", deps_dir)
    return deps_dir


def download_python(target_dir: str, deps_dir: str) -> None:
    """Download Python dependencies as source-only (no wheels)."""
    out = Path(deps_dir) / "python"
    out.mkdir(parents=True, exist_ok=True)
    root = Path(target_dir)

    # Find the requirements source
    req_file = None
    for name in ["requirements.txt", "pyproject.toml", "setup.py"]:
        if (root / name).exists():
            req_file = root / name
            break

    if (root / "Pipfile").exists() and req_file is None:
        # Extract package names from Pipfile [packages] section
        req_file = _pipfile_to_requirements(root / "Pipfile", out)

    if req_file is None:
        logger.warning("No Python requirements file found")
        return

    cmd = ["pip3", "download", "--no-binary", ":all:", "-d", str(out)]
    if req_file.name == "requirements.txt":
        cmd.extend(["-r", str(req_file)])
    elif req_file.name == "pyproject.toml":
        cmd.append(str(root))
    elif req_file.name == "setup.py":
        cmd.append(str(root))

    logger.info("Downloading Python deps: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, timeout=600)
    if result.returncode != 0:
        logger.warning("pip download failed (exit %d): %s", result.returncode,
                       result.stderr.decode()[:500])


def _pipfile_to_requirements(pipfile: Path, out_dir: Path) -> Path:
    """Extract package names from Pipfile [packages] section."""
    in_packages = False
    packages = []
    for line in pipfile.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[packages]":
            in_packages = True
            continue
        if stripped.startswith("[") and in_packages:
            break
        if in_packages and "=" in stripped:
            name = stripped.split("=")[0].strip().strip('"')
            packages.append(name)

    req_path = out_dir / "requirements_from_pipfile.txt"
    req_path.write_text("\n".join(packages) + "\n")
    return req_path


def download_node(target_dir: str, deps_dir: str) -> None:
    """Download Node dependencies via npm pack (no postinstall scripts)."""
    out = Path(deps_dir) / "node"
    out.mkdir(parents=True, exist_ok=True)
    root = Path(target_dir)
    pkg_json = root / "package.json"

    if not pkg_json.exists():
        return

    pkg = json.loads(pkg_json.read_text())
    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))

    for name, version in all_deps.items():
        spec = f"{name}@{version}" if version and version != "*" else name
        logger.debug("npm pack %s", spec)
        result = subprocess.run(
            ["npm", "pack", spec, "--pack-destination", str(out)],
            capture_output=True, timeout=120,
        )
        if result.returncode != 0:
            logger.warning("npm pack failed for %s: %s", spec,
                           result.stderr.decode()[:200])


def download_rust(target_dir: str, deps_dir: str) -> None:
    """Download Rust dependencies via cargo vendor."""
    out = Path(deps_dir) / "rust"
    out.mkdir(parents=True, exist_ok=True)

    # cargo vendor needs a writable project directory
    work_dir = Path("/tmp/rust-project")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    shutil.copytree(target_dir, work_dir)

    result = subprocess.run(
        ["cargo", "vendor", str(out)],
        cwd=str(work_dir),
        capture_output=True,
        timeout=600,
    )
    if result.returncode != 0:
        # Fallback: try nightly with -Znext-lockfile-bump for Cargo.lock v4
        logger.info("cargo vendor failed, trying nightly fallback")
        result = subprocess.run(
            ["cargo", "+nightly", "-Znext-lockfile-bump", "vendor", str(out)],
            cwd=str(work_dir),
            capture_output=True,
            timeout=600,
        )
        if result.returncode != 0:
            logger.warning("cargo vendor failed: %s", result.stderr.decode()[:500])


def download_go(target_dir: str, deps_dir: str) -> None:
    """Download Go dependencies via go mod vendor."""
    out = Path(deps_dir) / "go"
    out.mkdir(parents=True, exist_ok=True)

    # go mod vendor needs a writable project directory
    work_dir = Path("/tmp/go-project")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    shutil.copytree(target_dir, work_dir)

    env = {**os.environ, "GOMODCACHE": "/tmp/gomodcache"}
    result = subprocess.run(
        ["go", "mod", "vendor"],
        cwd=str(work_dir),
        capture_output=True,
        timeout=600,
        env=env,
    )
    if result.returncode != 0:
        logger.warning("go mod vendor failed: %s", result.stderr.decode()[:500])
        return

    # Copy vendored deps to output
    vendor_dir = work_dir / "vendor"
    if vendor_dir.exists():
        shutil.copytree(vendor_dir, out, dirs_exist_ok=True)


def download_hidden(hidden_deps: dict, deps_dir: str, config: dict) -> None:
    """Process hidden dependencies discovered by predep agent."""
    entries = hidden_deps.get("hidden_dependencies", [])
    skipped = []
    high_risk_allowed = config.get("high_risk_dep", False)

    for entry in entries:
        risk = entry.get("risk", "low")
        if risk == "high" and not high_risk_allowed:
            skipped.append(entry)
            logger.info("Skipping high-risk hidden dep: %s", entry.get("source", "unknown"))
            continue

        dep_type = entry.get("type", "")
        source = entry.get("source", "")

        try:
            if dep_type == "git":
                _download_hidden_git(source, deps_dir)
            elif dep_type in ("npm", "pypi", "cargo", "go"):
                _download_hidden_package(dep_type, source, deps_dir)
            elif dep_type == "url":
                _download_hidden_url(source, deps_dir)
            else:
                logger.info("Skipping hidden dep type %s: %s", dep_type, source)
        except Exception:
            logger.exception("Failed to download hidden dep: %s", source)

    if skipped:
        skipped_path = Path(deps_dir) / "skipped_high_risk.json"
        skipped_path.write_text(json.dumps(skipped, indent=2))


def _download_hidden_git(url: str, deps_dir: str) -> None:
    """Clone a hidden git dependency with safe_clone protections."""
    from thresher.harness.clone import safe_clone
    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    target = Path(deps_dir) / "hidden" / name
    target.mkdir(parents=True, exist_ok=True)
    safe_clone(url, str(target))


def _download_hidden_package(dep_type: str, source: str, deps_dir: str) -> None:
    """Download a hidden package manager dependency."""
    out = Path(deps_dir) / "hidden"
    out.mkdir(parents=True, exist_ok=True)
    if dep_type == "npm":
        subprocess.run(["npm", "pack", source, "--pack-destination", str(out)],
                       capture_output=True, timeout=120)
    elif dep_type == "pypi":
        subprocess.run(["pip3", "download", "--no-binary", ":all:", "-d", str(out), source],
                       capture_output=True, timeout=120)
    elif dep_type == "cargo":
        subprocess.run(["cargo", "download", source], cwd=str(out),
                       capture_output=True, timeout=120)
    elif dep_type == "go":
        subprocess.run(["go", "get", source], capture_output=True, timeout=120,
                       env={**os.environ, "GOPATH": str(out)})


def _download_hidden_url(url: str, deps_dir: str) -> None:
    """Download a file from a URL with safety limits."""
    out = Path(deps_dir) / "hidden"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["curl", "-sSfL", "--max-time", "60", "--max-filesize", "52428800",
         "--proto", "=https,http", "-o", str(out / url.split("/")[-1]), url],
        capture_output=True, timeout=120,
    )


def build_manifest(deps_dir: str) -> None:
    """Generate dep_manifest.json listing all downloaded dependencies."""
    root = Path(deps_dir)
    manifest = {}

    for eco_dir in root.iterdir():
        if not eco_dir.is_dir() or eco_dir.name == "hidden":
            continue
        files = []
        for f in eco_dir.rglob("*"):
            if f.is_file():
                files.append({"name": f.name, "path": str(f.relative_to(root)),
                              "size": f.stat().st_size})
        if files:
            manifest[eco_dir.name] = files

    # Include hidden deps
    hidden_dir = root / "hidden"
    if hidden_dir.exists():
        hidden_files = []
        for f in hidden_dir.rglob("*"):
            if f.is_file():
                hidden_files.append({"name": f.name, "path": str(f.relative_to(root)),
                                     "size": f.stat().st_size})
        if hidden_files:
            manifest["hidden"] = hidden_files

    manifest_path = root / "dep_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    logger.info("Manifest written: %s (%d ecosystems)", manifest_path, len(manifest))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_deps.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/thresher/harness/deps.py tests/unit/test_deps.py
git commit -m "feat: port dependency resolution to Python (detect, download, manifest)"
```

---

### Task 6: Create scanning orchestration wrapper and report module

**Files:**
- Create: `src/thresher/harness/scanning.py`
- Create: `src/thresher/harness/report.py`
- Create: `tests/unit/test_harness_scanning.py`
- Create: `tests/unit/test_harness_report.py`

- [ ] **Step 1: Write failing tests for scanning wrapper**

```python
# tests/unit/test_harness_scanning.py

import pytest
from unittest.mock import patch, MagicMock
from thresher.harness.scanning import run_all_scanners
from thresher.scanners.models import ScanResults


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_returns_results(mock_tasks):
    """run_all_scanners returns list of ScanResults."""
    mock_tasks.return_value = [
        ("grype", lambda **kw: ScanResults(tool_name="grype", execution_time_seconds=1.0,
                                            exit_code=0)),
    ]
    results = run_all_scanners(
        sbom_path="/opt/scan-results/sbom.json",
        target_dir="/opt/target",
        deps_dir="/opt/deps",
        output_dir="/opt/scan-results",
        config={},
    )
    assert len(results) == 1
    assert results[0].tool_name == "grype"


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_handles_failure(mock_tasks):
    """Scanner failure doesn't crash the pipeline."""
    def failing_scanner(**kwargs):
        raise RuntimeError("scanner exploded")

    mock_tasks.return_value = [
        ("broken", failing_scanner),
        ("working", lambda **kw: ScanResults(tool_name="working",
                                              execution_time_seconds=0.5, exit_code=0)),
    ]
    results = run_all_scanners(
        sbom_path="/x", target_dir="/x", deps_dir="/x",
        output_dir="/x", config={},
    )
    assert len(results) == 2
    broken = [r for r in results if r.tool_name == "broken"][0]
    assert broken.exit_code == -1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_harness_scanning.py -v`
Expected: FAIL

- [ ] **Step 3: Implement scanning wrapper**

```python
# src/thresher/harness/scanning.py

"""Scanner orchestration — runs all 22 scanners in parallel.

Replaces the SSH-based runner.py orchestration with direct subprocess calls.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)

MAX_WORKERS = 15


def run_all_scanners(sbom_path: str, target_dir: str, deps_dir: str,
                     output_dir: str, config: dict) -> list[ScanResults]:
    """Run all scanners in parallel and return aggregated results."""
    tasks = _get_scanner_tasks()
    results = []

    logger.info("Running %d scanners (max %d parallel)", len(tasks), MAX_WORKERS)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for name, fn in tasks:
            kwargs = _resolve_scanner_kwargs(
                name, sbom_path=sbom_path, target_dir=target_dir,
                deps_dir=deps_dir, output_dir=output_dir,
            )
            futures[pool.submit(fn, **kwargs)] = name

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.info("Scanner %s complete (exit %d, %.1fs)",
                            name, result.exit_code, result.execution_time_seconds)
            except Exception as e:
                logger.exception("Scanner %s failed", name)
                results.append(ScanResults(
                    tool_name=name, execution_time_seconds=0.0,
                    exit_code=-1, errors=[str(e)],
                ))

    logger.info("All scanners complete: %d results", len(results))
    return results


def _get_scanner_tasks() -> list[tuple[str, callable]]:
    """Return list of (name, run_function) for all scanners."""
    from thresher.scanners import (
        grype, osv, trivy, semgrep, bandit, checkov, guarddog,
        guarddog_deps, gitleaks, clamav, yara_scanner, capa_scanner,
        govulncheck, cargo_audit, scancode, hadolint, entropy,
        install_hooks, deps_dev, registry_meta, semgrep_supply_chain,
    )
    return [
        ("grype", grype.run_grype),
        ("osv", osv.run_osv),
        ("trivy", trivy.run_trivy),
        ("semgrep", semgrep.run_semgrep),
        ("bandit", bandit.run_bandit),
        ("checkov", checkov.run_checkov),
        ("guarddog", guarddog.run_guarddog),
        ("guarddog-deps", guarddog_deps.run_guarddog_deps),
        ("gitleaks", gitleaks.run_gitleaks),
        ("clamav", clamav.run_clamav),
        ("yara", yara_scanner.run_yara),
        ("capa", capa_scanner.run_capa),
        ("govulncheck", govulncheck.run_govulncheck),
        ("cargo-audit", cargo_audit.run_cargo_audit),
        ("scancode", scancode.run_scancode),
        ("hadolint", hadolint.run_hadolint),
        ("entropy", entropy.run_entropy),
        ("install-hooks", install_hooks.run_install_hooks),
        ("deps-dev", deps_dev.run_deps_dev),
        ("registry-meta", registry_meta.run_registry_meta),
        ("semgrep-sc", semgrep_supply_chain.run_semgrep_supply_chain),
    ]


def _resolve_scanner_kwargs(name: str, sbom_path: str, target_dir: str,
                            deps_dir: str, output_dir: str) -> dict:
    """Resolve the right kwargs for each scanner based on its dependencies."""
    # SBOM-dependent
    if name == "grype":
        return {"sbom_path": sbom_path, "output_dir": output_dir}
    # Source + deps dependent
    if name in ("osv", "trivy", "guarddog-deps"):
        return {"target_dir": target_dir, "deps_dir": deps_dir, "output_dir": output_dir}
    # Source-dependent (everything else)
    return {"target_dir": target_dir, "output_dir": output_dir}
```

- [ ] **Step 4: Write failing tests for report module**

```python
# tests/unit/test_harness_report.py

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from thresher.harness.report import (
    validate_report_output,
    enrich_all_findings,
    generate_report,
    ALLOWED_EXTENSIONS,
)
from thresher.scanners.models import ScanResults


class TestValidateReportOutput:

    def test_rejects_symlinks(self, tmp_path):
        """Symlinks in report output are removed."""
        real = tmp_path / "real.json"
        real.write_text("{}")
        link = tmp_path / "evil.json"
        link.symlink_to(real)
        validate_report_output(str(tmp_path))
        assert not link.exists()
        assert real.exists()

    def test_rejects_invalid_extensions(self, tmp_path):
        """Files with non-whitelisted extensions are removed."""
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "evil.exe").write_text("bad")
        validate_report_output(str(tmp_path))
        assert (tmp_path / "findings.json").exists()
        assert not (tmp_path / "evil.exe").exists()

    def test_rejects_oversized_files(self, tmp_path):
        """Files exceeding size limit are removed."""
        (tmp_path / "big.json").write_text("x" * 200)
        validate_report_output(str(tmp_path), max_file_bytes=100)
        assert not (tmp_path / "big.json").exists()

    def test_allowed_extensions(self):
        """All expected extensions are in the whitelist."""
        for ext in [".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html"]:
            assert ext in ALLOWED_EXTENSIONS


class TestEnrichAllFindings:

    @patch("thresher.harness.report.enrich_findings")
    def test_calls_enrichment(self, mock_enrich):
        """enrich_all_findings calls scoring.enrich_findings."""
        mock_enrich.return_value = [{"id": "test", "composite_priority": "high"}]
        result = enrich_all_findings([], [])
        assert "findings" in result
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_harness_report.py -v`
Expected: FAIL

- [ ] **Step 6: Implement report module**

```python
# src/thresher/harness/report.py

"""Report validation, enrichment, and generation.

Ports boundary validation from safe_io.py and wraps report/synthesize.py.
"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = frozenset({
    ".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html",
})

# Default limits (overridden by config)
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_JSON_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB


def validate_report_output(report_dir: str,
                           max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
    """Validate report directory: remove symlinks, bad extensions, oversized files."""
    root = Path(report_dir)

    for path in list(root.rglob("*")):
        # Remove symlinks
        if path.is_symlink():
            logger.warning("Removing symlink from report: %s", path)
            path.unlink()
            continue

        if not path.is_file():
            continue

        # Check extension
        if path.suffix.lower() not in ALLOWED_EXTENSIONS:
            logger.warning("Removing file with disallowed extension: %s", path)
            path.unlink()
            continue

        # Check size
        if path.stat().st_size > max_file_bytes:
            logger.warning("Removing oversized file: %s (%d bytes)", path,
                           path.stat().st_size)
            path.unlink()
            continue

        # Strip executable bits
        current = path.stat().st_mode
        path.chmod(current & 0o666)


def safe_json_loads(data: str | bytes, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> dict | None:
    """Parse JSON with size limit. Returns None on failure."""
    if isinstance(data, str):
        data = data.encode()
    if len(data) > max_bytes:
        logger.warning("JSON payload too large: %d > %d bytes", len(data), max_bytes)
        return None
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning("JSON parse failed: %s", e)
        return None


def enrich_all_findings(scan_results: list, verified_findings: list[dict]) -> dict:
    """Collect all findings and apply EPSS/KEV enrichment."""
    from thresher.report.scoring import enrich_findings
    from thresher.report.synthesize import _collect_findings, _normalize_scanner_output

    # Collect scanner findings from result files
    scanner_findings = {}
    for sr in scan_results:
        if sr.raw_output_path and Path(sr.raw_output_path).exists():
            try:
                raw = json.loads(Path(sr.raw_output_path).read_text())
                scanner_findings[sr.tool_name] = _normalize_scanner_output(sr.tool_name, raw)
            except Exception:
                logger.exception("Failed to read scanner output: %s", sr.tool_name)

    all_findings = _collect_findings(scanner_findings, verified_findings or None)
    enriched = enrich_findings(all_findings)
    return {"findings": enriched, "scanner_results": scanner_findings}


def generate_report(enriched_findings: dict, scan_results: list,
                    config: dict) -> str:
    """Generate the final report and write to output directory."""
    from thresher.report.synthesize import (
        _build_synthesis_input, _generate_agent_report, _generate_template_report,
    )

    output_dir = config.get("output_dir", "/output")
    os.makedirs(output_dir, exist_ok=True)

    findings = enriched_findings.get("findings", [])
    scanner_results = enriched_findings.get("scanner_results", {})

    if config.get("skip_ai"):
        _generate_template_report(output_dir, findings, scanner_results)
    else:
        synthesis_input = _build_synthesis_input(scanner_results, findings, findings)
        _generate_agent_report(output_dir, synthesis_input, config)

    validate_report_output(output_dir)
    logger.info("Report generated: %s", output_dir)
    return output_dir
```

- [ ] **Step 7: Run all tests to verify they pass**

Run: `python -m pytest tests/unit/test_harness_scanning.py tests/unit/test_harness_report.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/thresher/harness/scanning.py src/thresher/harness/report.py \
    tests/unit/test_harness_scanning.py tests/unit/test_harness_report.py
git commit -m "feat: create scanning orchestration wrapper and report validation module"
```

---

## Chunk 3: Scanner & Agent Refactoring

### Task 7: Refactor scanner modules — remove SSH, use subprocess

This is a mechanical refactor across all 22 scanner modules. The pattern is identical for each. Here we show the full refactor for 3 representative scanners (grype, semgrep, osv) and document the pattern for the remaining 19.

**Files:**
- Modify: `src/thresher/scanners/grype.py:25-75`
- Modify: `src/thresher/scanners/semgrep.py` (run function)
- Modify: `src/thresher/scanners/osv.py` (run function)
- Modify: All 19 remaining scanner modules (same pattern)
- Modify: `src/thresher/scanners/syft.py:16-65`
- Modify: `tests/unit/test_grype.py` (update mocks)
- Modify: All scanner tests (same pattern)

**The pattern for every scanner:**

Before (current):
```python
def run_<tool>(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    cmd = "<tool command>"
    result = ssh_exec(vm_name, cmd)
    return ScanResults(tool_name="<tool>", exit_code=result.exit_code, ...)
```

After (new):
```python
def run_<tool>(target_dir: str, output_dir: str) -> ScanResults:
    start = time.time()
    try:
        result = subprocess.run(
            ["<tool>", "<args>"],
            capture_output=True, timeout=300,
        )
        output_path = Path(output_dir) / "<tool>.json"
        output_path.write_bytes(result.stdout)
        return ScanResults(
            tool_name="<tool>",
            execution_time_seconds=time.time() - start,
            exit_code=result.returncode,
            raw_output_path=str(output_path),
        )
    except Exception as e:
        return ScanResults(
            tool_name="<tool>",
            execution_time_seconds=time.time() - start,
            exit_code=-1,
            errors=[str(e)],
        )
```

- [ ] **Step 1: Write updated test for grype scanner**

```python
# tests/unit/test_grype.py — update TestRunGrype class

from unittest.mock import patch, MagicMock

class TestRunGrype:

    @patch("thresher.scanners.grype.subprocess.run")
    def test_run_grype_calls_subprocess(self, mock_run):
        """run_grype uses subprocess.run, not ssh_exec."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b'{"matches":[]}')
        result = run_grype(sbom_path="/opt/scan-results/sbom.json",
                          output_dir="/opt/scan-results")
        assert result.tool_name == "grype"
        assert result.exit_code == 0
        args = mock_run.call_args[0][0]
        assert "grype" in args[0]

    @patch("thresher.scanners.grype.subprocess.run")
    def test_run_grype_no_vm_name_param(self, mock_run):
        """run_grype no longer takes vm_name parameter."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b'{}')
        import inspect
        sig = inspect.signature(run_grype)
        assert "vm_name" not in sig.parameters
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_grype.py::TestRunGrype -v`
Expected: FAIL — run_grype still takes vm_name, uses ssh_exec

- [ ] **Step 3: Refactor grype.py**

In `src/thresher/scanners/grype.py`, replace the `run_grype` function (lines 25-75):

```python
import subprocess
import time
from pathlib import Path

def run_grype(sbom_path: str, output_dir: str) -> ScanResults:
    """Run Grype vulnerability scanner against SBOM."""
    start = time.time()
    output_path = Path(output_dir) / "grype.json"

    try:
        result = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json"],
            capture_output=True,
            timeout=300,
        )
        output_path.write_bytes(result.stdout)

        # Exit codes 0 (no vulns) and 1 (vulns found) are both success
        exit_code = result.returncode if result.returncode > 1 else 0

        return ScanResults(
            tool_name="grype",
            execution_time_seconds=time.time() - start,
            exit_code=exit_code,
            raw_output_path=str(output_path),
        )
    except Exception as e:
        return ScanResults(
            tool_name="grype",
            execution_time_seconds=time.time() - start,
            exit_code=-1,
            errors=[str(e)],
        )
```

Remove the `ssh_exec` import. Keep the `parse_grype_output()` function and severity mapping unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_grype.py -v`
Expected: PASS

- [ ] **Step 5: Refactor syft.py (same pattern)**

Replace `run_syft` in `src/thresher/scanners/syft.py` (lines 16-65):

```python
import subprocess
import time
from pathlib import Path

def run_syft(target_dir: str, output_dir: str) -> ScanResults:
    """Generate SBOM with Syft."""
    start = time.time()
    sbom_path = Path(output_dir) / "sbom.json"

    try:
        result = subprocess.run(
            ["syft", "scan", f"dir:{target_dir}", "-o", "cyclonedx-json"],
            capture_output=True,
            timeout=600,
        )
        sbom_path.write_bytes(result.stdout)
        return ScanResults(
            tool_name="syft",
            execution_time_seconds=time.time() - start,
            exit_code=result.returncode,
            raw_output_path=str(sbom_path),
            metadata={"sbom_path": str(sbom_path)},
        )
    except Exception as e:
        return ScanResults(
            tool_name="syft",
            execution_time_seconds=time.time() - start,
            exit_code=-1,
            errors=[str(e)],
        )
```

- [ ] **Step 6: Refactor all remaining scanner modules (19 modules)**

Apply the same pattern to each. Key notes per scanner:

| Scanner | File | Tool command | Special notes |
|---------|------|-------------|---------------|
| osv | osv.py | `osv-scanner --format json <target>` | Also scans deps_dir |
| trivy | trivy.py | `trivy fs --format json <target>` | Also scans deps_dir |
| semgrep | semgrep.py | `semgrep --json <target>` | |
| bandit | bandit.py | `bandit -r <target> -f json` | Python only |
| checkov | checkov.py | `checkov -d <target> -o json` | IaC scanner |
| guarddog | guarddog.py | `guarddog pypi verify <target>` | JSON output via stdout |
| guarddog_deps | guarddog_deps.py | `guarddog pypi scan <deps>` | Scans deps_dir |
| gitleaks | gitleaks.py | `gitleaks detect -s <target> --report-format json` | |
| clamav | clamav.py | `clamscan -r <target>` | Text output, parsed |
| yara_scanner | yara_scanner.py | `yara -r <rules> <target>` | Text output, parsed |
| capa_scanner | capa_scanner.py | `capa <target> -j` | JSON output |
| govulncheck | govulncheck.py | `govulncheck -json ./...` | Requires go.mod |
| cargo_audit | cargo_audit.py | `cargo audit --json` | Requires Cargo.lock |
| scancode | scancode.py | `scancode --json <output> <target>` | |
| hadolint | hadolint.py | `hadolint <Dockerfile> --format json` | |
| entropy | entropy.py | Custom Python entropy analysis | No subprocess — just remove `vm_name`, use direct file I/O |
| install_hooks | install_hooks.py | Custom Python analysis | No subprocess — just remove `vm_name`, use direct file I/O |
| deps_dev | deps_dev.py | HTTP API calls | No subprocess — just remove `vm_name`, uses urllib directly |
| registry_meta | registry_meta.py | HTTP API calls | No subprocess — just remove `vm_name`, uses urllib directly |
| semgrep_supply_chain | semgrep_supply_chain.py | `semgrep --config <rules> --json` | |

For subprocess-based scanners: remove `vm_name` param, replace `ssh_exec()` with `subprocess.run()`.
For Python-native scanners (entropy, install_hooks): remove `vm_name` param, replace `ssh_exec` file reads with direct `Path.read_text()`.
For HTTP-based scanners (deps_dev, registry_meta): remove `vm_name` param only (they already use urllib/requests, not subprocess).
Keep all parse functions unchanged.

- [ ] **Step 7: Update all scanner tests**

For each test file, replace `ssh_exec` mocks with `subprocess.run` mocks. The parse function tests stay unchanged since they test the same data.

- [ ] **Step 8: Run full scanner test suite**

Run: `python -m pytest tests/unit/test_grype.py tests/unit/test_semgrep.py tests/unit/test_osv.py tests/unit/test_runner.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/thresher/scanners/ tests/unit/
git commit -m "refactor: remove SSH from all scanner modules, use direct subprocess"
```

---

### Task 8: Refactor agent modules — remove SSH, return data

**Files:**
- Modify: `src/thresher/agents/analyst.py:173-254`
- Modify: `src/thresher/agents/analysts.py:372-469,511-566`
- Modify: `src/thresher/agents/adversarial.py:523-669`
- Modify: `src/thresher/agents/predep.py:111-245`
- Modify: `tests/unit/test_analyst.py`
- Modify: `tests/unit/test_analysts.py`
- Modify: `tests/unit/test_adversarial.py`
- Modify: `tests/unit/test_predep.py`
- Modify: `tests/integration/test_agent_pipeline.py`

- [ ] **Step 1: Write updated test for single analyst**

```python
# tests/unit/test_analyst.py — add new tests

class TestRunAnalysisRefactored:

    @patch("thresher.agents.analyst.subprocess.run")
    def test_no_vm_name_param(self, mock_run):
        """run_analysis no longer takes vm_name."""
        import inspect
        from thresher.agents.analyst import run_analysis
        sig = inspect.signature(run_analysis)
        assert "vm_name" not in sig.parameters

    @patch("thresher.agents.analyst.subprocess.run")
    def test_returns_findings_dict(self, mock_run):
        """run_analysis returns findings dict (not None)."""
        mock_run.return_value = MagicMock(returncode=0)
        # Mock the output file
        with patch("pathlib.Path.read_text", return_value='{"findings": []}'):
            result = run_analysis(
                config=MagicMock(model="sonnet"),
                persona={"name": "paranoid", "number": 1},
                target_dir="/opt/target",
                output_dir="/opt/scan-results",
            )
        assert isinstance(result, dict)

    @patch("thresher.agents.analyst.subprocess.run")
    def test_uses_subprocess_not_ssh(self, mock_run):
        """run_analysis calls claude via subprocess, not ssh_exec."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch("pathlib.Path.read_text", return_value='{"findings": []}'):
            run_analysis(
                config=MagicMock(model="sonnet"),
                persona={"name": "paranoid", "number": 1},
                target_dir="/opt/target",
                output_dir="/opt/scan-results",
            )
        args = mock_run.call_args[0][0]
        assert "claude" in args[0]

    @patch("thresher.agents.analyst.subprocess.run")
    def test_api_key_from_env_not_tmpfs(self, mock_run):
        """API key comes from environment, not written to tmpfs."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch("pathlib.Path.read_text", return_value='{"findings": []}'):
            run_analysis(
                config=MagicMock(model="sonnet"),
                persona={"name": "paranoid", "number": 1},
                target_dir="/opt/target",
                output_dir="/opt/scan-results",
            )
        # Verify no /dev/shm writes
        call_args_str = str(mock_run.call_args_list)
        assert "/dev/shm" not in call_args_str
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_analyst.py::TestRunAnalysisRefactored -v`
Expected: FAIL

- [ ] **Step 3: Refactor analyst.py**

In `src/thresher/agents/analyst.py`, replace `run_analysis` (lines 173-254):

```python
import subprocess
import os
from pathlib import Path

def run_analysis(config, persona: dict, target_dir: str, output_dir: str) -> dict:
    """Run a single analyst agent via Claude Code headless.

    Returns the parsed findings dict. API key comes from environment.
    """
    prompt = _build_analyst_prompt(persona, target_dir)
    prompt_path = Path(f"/tmp/analyst_{persona['name']}_prompt.txt")
    prompt_path.write_text(prompt)

    findings_path = Path(output_dir) / f"analyst-{persona['number']}-{persona['name']}-findings.json"
    max_turns = config.analyst_max_turns or persona.get("max_turns", 100)

    cmd = [
        "claude", "-p", str(prompt_path),
        "--model", config.model,
        "--allowedTools", "Read,Glob,Grep",
        "--output-format", "stream-json",
        "--max-turns", str(max_turns),
    ]

    env = os.environ.copy()
    # API key already in env (ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN)

    logger.info("Starting analyst: %s", persona["name"])
    result = subprocess.run(
        cmd, env=env, capture_output=True,
        timeout=getattr(config, "agent_timeout", 1800),
    )

    # Parse output
    try:
        output = _parse_agent_json_output(result.stdout.decode())
        if output:
            findings_path.write_text(json.dumps(output, indent=2))
            return output
    except Exception:
        logger.exception("Failed to parse analyst output: %s", persona["name"])

    return {"analyst": persona["name"], "findings": [], "summary": "Agent produced no output"}
```

- [ ] **Step 4: Refactor analysts.py — parallel orchestration**

In `src/thresher/agents/analysts.py`, update `run_all_analysts` (lines 511-566) and `_run_single_analyst` (lines 372-469):

- Remove `vm_name` parameter
- Replace `ssh_exec`/`ssh_write_file` with direct calls to refactored `run_analysis`
- Change return type from `None` to `list[dict]` (collect all analyst findings)
- Remove tmpfs API key writes

```python
def run_all_analysts(target_dir: str, deps_dir: str, config: dict) -> list[dict]:
    """Run all 8 analyst agents in parallel, return combined findings."""
    definitions = _load_definitions()
    all_findings = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(
                run_analysis,
                config=config,
                persona=defn,
                target_dir=target_dir,
                output_dir="/opt/scan-results",
            ): defn["name"]
            for defn in definitions
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                all_findings.append(result)
                logger.info("Analyst %s complete", name)
            except Exception:
                logger.exception("Analyst %s failed", name)

    return all_findings
```

- [ ] **Step 5: Refactor adversarial.py**

In `src/thresher/agents/adversarial.py`, replace `run_adversarial_verification` (lines 523-669):

```python
def run_adversarial_verification(analyst_findings: list[dict],
                                  target_dir: str, config) -> list[dict]:
    """Run adversarial agent to verify high-risk findings.

    Accepts analyst findings directly (no VM file reading).
    Returns verified findings with adversarial verdicts.
    """
    high_risk = _extract_high_risk(analyst_findings)
    if not high_risk:
        logger.info("No high-risk findings to verify")
        return analyst_findings

    high_risk = _deduplicate_findings(high_risk)
    prompt = _build_adversarial_prompt(high_risk, target_dir)
    prompt_path = Path("/tmp/adversarial_prompt.txt")
    prompt_path.write_text(prompt)

    max_turns = getattr(config, "adversarial_max_turns", None) or 200
    cmd = [
        "claude", "-p", str(prompt_path),
        "--model", config.model,
        "--allowedTools", "Read,Glob,Grep,WebSearch,WebFetch",
        "--output-format", "stream-json",
        "--max-turns", str(max_turns),
    ]

    result = subprocess.run(cmd, env=os.environ.copy(), capture_output=True,
                           timeout=getattr(config, "agent_timeout", 1800))

    try:
        adversarial_output = _parse_adversarial_output(result.stdout.decode())
        verified = _merge_adversarial_results(analyst_findings, adversarial_output)

        output_path = Path("/opt/scan-results/adversarial-findings.json")
        output_path.write_text(json.dumps(verified, indent=2))
        return verified
    except Exception:
        logger.exception("Failed to parse adversarial output")
        return analyst_findings
```

Remove `_read_analyst_findings_from_vm()` — findings are passed directly.
Keep `_extract_high_risk()`, `_deduplicate_findings()`, `_parse_adversarial_output()`,
`_merge_adversarial_results()` unchanged.

- [ ] **Step 6: Refactor predep.py**

In `src/thresher/agents/predep.py`, replace `run_predep_discovery` (lines 111-245):

```python
def run_predep_discovery(target_dir: str, config) -> dict:
    """Run pre-dependency discovery agent.

    Returns dict with hidden_dependencies list.
    """
    prompt_path = Path("/tmp/predep_prompt.txt")
    prompt_path.write_text(PREDEP_PROMPT)

    cmd = [
        "claude", "-p", str(prompt_path),
        "--model", config.model if hasattr(config, "model") else config.get("model", "sonnet"),
        "--allowedTools", "Read,Glob,Grep",
        "--output-format", "stream-json",
        "--max-turns", "50",
    ]

    result = subprocess.run(cmd, env=os.environ.copy(), capture_output=True,
                           timeout=getattr(config, "agent_timeout", 900),
                           cwd=target_dir)

    try:
        output = _parse_predep_output(result.stdout.decode())
        if output:
            deps_path = Path("/opt/thresher/work/deps/hidden_deps.json")
            deps_path.parent.mkdir(parents=True, exist_ok=True)
            deps_path.write_text(json.dumps(output, indent=2))
            return output
    except Exception:
        logger.exception("Failed to parse predep output")

    return {"hidden_dependencies": [], "files_scanned": 0, "summary": "Agent produced no output"}
```

Remove SSH imports (`ssh_exec`, `ssh_write_file`). Keep `PREDEP_PROMPT` and
`_parse_predep_output()` unchanged.

- [ ] **Step 7: Update agent integration tests**

In `tests/integration/test_agent_pipeline.py`:
- Replace all `ssh_exec` mocks with `subprocess.run` mocks
- Update assertions: agents return data (not None)
- Remove tmpfs/SSH credential checks
- Update expected call counts (no more ssh_write_file for API keys)

- [ ] **Step 8: Run agent tests**

Run: `python -m pytest tests/unit/test_analyst.py tests/unit/test_analysts.py tests/unit/test_adversarial.py tests/unit/test_predep.py tests/integration/test_agent_pipeline.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/thresher/agents/ tests/unit/ tests/integration/
git commit -m "refactor: remove SSH from agent modules, agents return data directly"
```

---

## Chunk 4: Launcher, CLI, Dockerfile, Cleanup

### Task 9: Create launcher package

**Files:**
- Create: `src/thresher/launcher/__init__.py`
- Create: `src/thresher/launcher/direct.py`
- Create: `src/thresher/launcher/docker.py`
- Create: `src/thresher/launcher/lima.py`
- Create: `tests/unit/test_launcher_direct.py`
- Create: `tests/unit/test_launcher_docker.py`
- Create: `tests/unit/test_launcher_lima.py`

- [ ] **Step 1: Write failing tests for direct launcher**

```python
# tests/unit/test_launcher_direct.py

import pytest
from unittest.mock import patch, MagicMock, ANY
from thresher.launcher.direct import launch_direct
from thresher.config import ScanConfig


class TestDirectLauncher:

    @patch("thresher.launcher.direct.subprocess.run")
    def test_launches_harness_subprocess(self, mock_run):
        """Direct mode runs harness as subprocess."""
        mock_run.return_value = MagicMock(returncode=0)
        config = ScanConfig(repo_url="https://github.com/test/repo",
                           output_dir="/tmp/reports")
        launch_direct(config)
        args = mock_run.call_args[0][0]
        assert "python" in args[0] or "python3" in args[0]
        assert "-m" in args
        assert "thresher.harness" in args

    @patch("thresher.launcher.direct.subprocess.run")
    def test_passes_config_file(self, mock_run):
        """Direct mode writes config to temp file and passes --config."""
        mock_run.return_value = MagicMock(returncode=0)
        config = ScanConfig(repo_url="https://github.com/test/repo")
        launch_direct(config)
        args = mock_run.call_args[0][0]
        assert "--config" in args

    @patch("thresher.launcher.direct.subprocess.run")
    def test_passes_output_dir(self, mock_run):
        """Direct mode passes --output to harness."""
        mock_run.return_value = MagicMock(returncode=0)
        config = ScanConfig(repo_url="https://github.com/test/repo",
                           output_dir="/tmp/my-reports")
        launch_direct(config)
        args = mock_run.call_args[0][0]
        assert "--output" in args
        idx = args.index("--output")
        assert args[idx + 1] == "/tmp/my-reports"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_launcher_direct.py -v`
Expected: FAIL

- [ ] **Step 3: Implement direct launcher**

```python
# src/thresher/launcher/__init__.py

"""Launch mode implementations for the Thresher harness."""


# src/thresher/launcher/direct.py

"""Direct launch mode — runs harness as a subprocess on the host.

Dev mode. Assumes all scanners and tools are installed locally.
"""

import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


def launch_direct(config: ScanConfig) -> int:
    """Launch the harness as a local subprocess. Returns exit code."""
    # Write config to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name

    cmd = [
        sys.executable, "-m", "thresher.harness",
        "--config", config_path,
        "--output", config.output_dir,
    ]

    logger.info("Launching harness (direct mode): %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, env=None)  # inherit current env
        return result.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)
```

- [ ] **Step 4: Write failing tests for Docker launcher**

```python
# tests/unit/test_launcher_docker.py

import pytest
from unittest.mock import patch, MagicMock
from thresher.launcher.docker import launch_docker, _build_docker_cmd
from thresher.config import ScanConfig


class TestDockerLauncher:

    def test_docker_cmd_includes_security_flags(self):
        """Docker run command includes hardening flags."""
        config = ScanConfig(repo_url="https://github.com/test/repo",
                           output_dir="/tmp/reports")
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        cmd_str = " ".join(cmd)
        assert "--read-only" in cmd_str
        assert "--cap-drop=ALL" in cmd_str
        assert "--security-opt=no-new-privileges" in cmd_str
        assert "--user" in cmd_str
        assert "--rm" in cmd_str

    def test_docker_cmd_mounts_output(self):
        """Docker run mounts output directory."""
        config = ScanConfig(repo_url="https://github.com/test/repo",
                           output_dir="/tmp/reports")
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        cmd_str = " ".join(cmd)
        assert "/tmp/reports:/output" in cmd_str

    def test_docker_cmd_mounts_config(self):
        """Docker run mounts config file read-only."""
        config = ScanConfig(repo_url="https://github.com/test/repo")
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        cmd_str = " ".join(cmd)
        assert "/tmp/config.json:/config/config.json:ro" in cmd_str

    def test_docker_cmd_includes_tmpfs_mounts(self):
        """Docker run includes tmpfs for writable directories."""
        config = ScanConfig(repo_url="https://github.com/test/repo")
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        cmd_str = " ".join(cmd)
        assert "/opt/target" in cmd_str
        assert "/opt/scan-results" in cmd_str
        assert "/opt/deps" in cmd_str

    def test_docker_cmd_passes_credentials(self):
        """Docker run passes API key and OAuth token env vars."""
        config = ScanConfig(repo_url="https://github.com/test/repo")
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "-e" in cmd
        cmd_str = " ".join(cmd)
        assert "ANTHROPIC_API_KEY" in cmd_str
        assert "CLAUDE_CODE_OAUTH_TOKEN" in cmd_str
```

- [ ] **Step 5: Implement Docker launcher**

```python
# src/thresher/launcher/docker.py

"""Docker launch mode — runs harness in a container.

Container isolation without VM overhead. Good for Linux, CI.
No egress firewall (container has unrestricted network).
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

DOCKER_IMAGE = "thresher:latest"


def launch_docker(config: ScanConfig) -> int:
    """Launch the harness in a Docker container. Returns exit code."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name

    cmd = _build_docker_cmd(config, config_path)
    logger.info("Launching harness (docker mode)")

    try:
        result = subprocess.run(cmd)
        return result.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)


def _build_docker_cmd(config: ScanConfig, config_path: str) -> list[str]:
    """Build the docker run command with all security hardening."""
    return [
        "docker", "run",
        # Volumes
        "-v", f"{config.output_dir}:/output",
        "-v", f"{config_path}:/config/config.json:ro",
        # Credentials
        "-e", "ANTHROPIC_API_KEY",
        "-e", "CLAUDE_CODE_OAUTH_TOKEN",
        # Security hardening
        "--rm",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=1073741824",
        "--tmpfs", "/home/thresher/.cache:rw,size=536870912",
        "--tmpfs", "/opt/target:rw,size=2147483648",
        "--tmpfs", "/opt/scan-results:rw,size=1073741824",
        "--tmpfs", "/opt/deps:rw,size=2147483648",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "thresher",
        # Image and args
        DOCKER_IMAGE,
        "--config", "/config/config.json",
        "--output", "/output",
    ]
```

- [ ] **Step 6: Write failing tests for Lima launcher**

```python
# tests/unit/test_launcher_lima.py

import pytest
from unittest.mock import patch, MagicMock, call
from thresher.launcher.lima import launch_lima
from thresher.config import ScanConfig


class TestLimaLauncher:

    @patch("thresher.launcher.lima.subprocess.run")
    def test_ensures_vm_running(self, mock_run):
        """Lima mode ensures the VM is running before launching."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Running")
        config = ScanConfig(repo_url="https://github.com/test/repo")
        launch_lima(config)
        # Should check VM status
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("limactl" in c for c in calls)

    @patch("thresher.launcher.lima.subprocess.run")
    def test_runs_docker_inside_lima(self, mock_run):
        """Lima mode runs docker inside the VM."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Running")
        config = ScanConfig(repo_url="https://github.com/test/repo")
        launch_lima(config)
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("docker" in c and "thresher" in c for c in calls)
```

- [ ] **Step 7: Implement Lima launcher**

```python
# src/thresher/launcher/lima.py

"""Lima+Docker launch mode — maximum isolation.

Starts a Lima VM (if not running), applies iptables egress firewall,
then runs the harness Docker container inside the VM.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

BASE_VM_NAME = "thresher-base"
DOCKER_IMAGE = "thresher:latest"


def launch_lima(config: ScanConfig) -> int:
    """Launch harness in Docker inside a Lima VM. Returns exit code."""
    _ensure_vm_running()
    _apply_firewall()

    # Write config to temp file and copy to VM
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name

    try:
        # Copy config into VM
        subprocess.run(
            ["limactl", "copy", config_path, f"{BASE_VM_NAME}:/opt/config.json"],
            check=True,
        )

        # Run docker inside VM
        docker_cmd = _build_lima_docker_cmd(config)
        result = subprocess.run(
            ["limactl", "shell", BASE_VM_NAME, "--"] + docker_cmd,
        )

        # Copy report from VM to host
        if result.returncode == 0:
            _copy_report_to_host(config.output_dir)

        return result.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)


def _ensure_vm_running() -> None:
    """Ensure the base Lima VM exists and is running."""
    result = subprocess.run(
        ["limactl", "list", "--format", "{{.Status}}", BASE_VM_NAME],
        capture_output=True,
    )
    status = result.stdout.decode().strip()

    if status == "Running":
        return
    elif status == "Stopped":
        logger.info("Starting Lima VM: %s", BASE_VM_NAME)
        subprocess.run(["limactl", "start", BASE_VM_NAME], check=True)
    else:
        raise RuntimeError(
            f"Lima VM '{BASE_VM_NAME}' not found. Run 'thresher build' first."
        )


def _apply_firewall() -> None:
    """Apply iptables egress firewall inside the VM."""
    from thresher.vm.firewall import generate_rules
    rules = generate_rules()
    subprocess.run(
        ["limactl", "shell", BASE_VM_NAME, "--", "sudo", "bash", "-c", rules],
        check=True,
    )


def _build_lima_docker_cmd(config: ScanConfig) -> list[str]:
    """Build docker run command for inside the Lima VM."""
    return [
        "docker", "run",
        "-v", "/opt/reports:/output",
        "-v", "/opt/config.json:/config/config.json:ro",
        "-e", "ANTHROPIC_API_KEY",
        "-e", "CLAUDE_CODE_OAUTH_TOKEN",
        "--rm",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=1073741824",
        "--tmpfs", "/home/thresher/.cache:rw,size=536870912",
        "--tmpfs", "/opt/target:rw,size=2147483648",
        "--tmpfs", "/opt/scan-results:rw,size=1073741824",
        "--tmpfs", "/opt/deps:rw,size=2147483648",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "thresher",
        DOCKER_IMAGE,
        "--config", "/config/config.json",
        "--output", "/output",
    ]


def _copy_report_to_host(output_dir: str) -> None:
    """Copy report from VM to host."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["limactl", "copy", "-r",
         f"{BASE_VM_NAME}:/opt/reports/.", output_dir],
        check=True,
    )
```

- [ ] **Step 8: Run all launcher tests**

Run: `python -m pytest tests/unit/test_launcher_direct.py tests/unit/test_launcher_docker.py tests/unit/test_launcher_lima.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/thresher/launcher/ tests/unit/test_launcher_*.py
git commit -m "feat: create launcher package with direct, docker, and lima modes"
```

---

### Task 10: Simplify CLI — delegate to launchers

**Files:**
- Modify: `src/thresher/cli.py:75-132,607-722`
- Modify: `tests/integration/test_cli.py`

- [ ] **Step 1: Write test for new CLI scan with launch mode**

```python
# tests/integration/test_cli.py — add new tests

from unittest.mock import patch, MagicMock

class TestScanCommandRefactored:

    @patch("thresher.cli.launch_direct")
    def test_scan_no_vm_uses_direct_launcher(self, mock_launch):
        """thresher scan --no-vm delegates to direct launcher."""
        mock_launch.return_value = 0
        from click.testing import CliRunner
        from thresher.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo", "--no-vm"])
        mock_launch.assert_called_once()

    @patch("thresher.cli.launch_docker")
    def test_scan_docker_uses_docker_launcher(self, mock_launch):
        """thresher scan --docker delegates to docker launcher."""
        mock_launch.return_value = 0
        from click.testing import CliRunner
        from thresher.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo", "--docker"])
        mock_launch.assert_called_once()

    @patch("thresher.cli.launch_lima")
    def test_scan_default_uses_lima_launcher(self, mock_launch):
        """thresher scan (default) delegates to lima launcher."""
        mock_launch.return_value = 0
        from click.testing import CliRunner
        from thresher.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo"])
        mock_launch.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_cli.py::TestScanCommandRefactored -v`
Expected: FAIL

- [ ] **Step 3: Update CLI scan command**

In `src/thresher/cli.py`, replace the scan orchestration. The `scan()` function (lines 75-132) should:

1. Add `--docker` and `--no-vm` flags
2. Set `launch_mode` on config
3. Delegate to the appropriate launcher

```python
@click.command()
@click.argument("repo_url")
@click.option("--skip-ai", is_flag=True, help="Skip AI analysis agents")
@click.option("--high-risk-dep", is_flag=True, help="Download high-risk hidden deps")
@click.option("--docker", "use_docker", is_flag=True, help="Run in Docker (no VM)")
@click.option("--no-vm", "no_vm", is_flag=True, help="Run directly (dev mode)")
@click.option("--tmux", is_flag=True, help="Use tmux split-pane UI")
@click.option("--verbose", is_flag=True, help="Enable debug logging")
@click.option("--model", default=None, help="AI model to use")
@click.option("--branch", default="", help="Git branch to scan")
@click.option("--depth", default=None, type=int, help="Transitive dependency depth")
def scan(repo_url, skip_ai, high_risk_dep, use_docker, no_vm,
         tmux, verbose, model, branch, depth):
    """Scan a repository for supply chain security issues."""
    config = load_config(
        repo_url=repo_url, skip_ai=skip_ai, high_risk_dep=high_risk_dep,
        tmux=tmux, verbose=verbose, model=model, branch=branch, depth=depth,
    )

    if no_vm:
        config.launch_mode = "direct"
    elif use_docker:
        config.launch_mode = "docker"
    # else: default "lima" from config

    config.validate()

    from thresher.launcher.direct import launch_direct
    from thresher.launcher.docker import launch_docker
    from thresher.launcher.lima import launch_lima

    launchers = {
        "direct": launch_direct,
        "docker": launch_docker,
        "lima": launch_lima,
    }

    launcher = launchers[config.launch_mode]
    exit_code = launcher(config)
    sys.exit(exit_code)
```

Remove the old `_run_scan()` function (lines 607-722) — all orchestration now lives in the harness.

- [ ] **Step 4: Update `thresher build` command**

`thresher build` should now build the Docker image instead of provisioning a Lima VM:

```python
@click.command()
def build():
    """Build the Thresher Docker image."""
    import subprocess
    project_root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        ["docker", "build", "-t", "thresher:latest", "-f", "docker/Dockerfile", "."],
        cwd=str(project_root),
    )
    sys.exit(result.returncode)
```

- [ ] **Step 5: Run CLI tests**

Run: `python -m pytest tests/integration/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/thresher/cli.py tests/integration/test_cli.py
git commit -m "refactor: simplify CLI to delegate to launcher modules"
```

---

### Task 11: Dockerfile, Lima simplification, and cleanup

**Files:**
- Create: `docker/Dockerfile`
- Modify: `src/thresher/vm/lima.py` (simplify)
- Modify: `lima/thresher.yaml` (simplify)
- Delete: `src/thresher/vm/ssh.py`
- Delete: `src/thresher/vm/safe_io.py`
- Delete: `src/thresher/docker/sandbox.py`
- Delete: `docker/Dockerfile.scanner-deps`
- Delete: `docker/scripts/*.sh`
- Delete: `vm_scripts/provision.sh`
- Delete: `vm_scripts/safe_clone.sh`
- Delete: `vm_scripts/download_deps.sh`
- Delete: `vm_scripts/run_scanners.sh`
- Delete: `vm_scripts/validate_*_output.sh`
- Delete: `tests/unit/test_ssh.py`
- Delete: `tests/unit/test_safe_io.py`
- Delete: `tests/unit/test_sandbox.py`

- [ ] **Step 1: Create the Dockerfile**

```dockerfile
# docker/Dockerfile
# Thresher — single image containing CLI, harness, and all scanner tools

FROM ubuntu:24.04

# -- System deps --
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget jq ca-certificates \
    python3 python3-pip python3-venv python3-dev \
    ruby \
    && rm -rf /var/lib/apt/lists/*

# -- Language runtimes (for dependency resolution) --
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

ARG TARGETARCH
RUN wget -q https://go.dev/dl/go1.22.5.linux-${TARGETARCH}.tar.gz \
    && tar -C /usr/local -xzf go*.tar.gz && rm go*.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# -- Security scanners (pip-installable) --
RUN pip3 install --break-system-packages \
    semgrep bandit checkov guarddog scancode-toolkit

# -- Security scanners (binary installs) --
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_${TARGETARCH}.tar.gz \
    | tar xz -C /usr/local/bin gitleaks
RUN HADOLINT_ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -sSfL "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-${HADOLINT_ARCH}" \
    -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest \
    && cp /root/go/bin/osv-scanner /usr/local/bin/
RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
    && cp /root/go/bin/govulncheck /usr/local/bin/
RUN cargo install cargo-audit && cp /root/.cargo/bin/cargo-audit /usr/local/bin/

# -- ClamAV --
RUN apt-get update && apt-get install -y --no-install-recommends clamav \
    && rm -rf /var/lib/apt/lists/* \
    && freshclam || true

# -- YARA --
RUN apt-get update && apt-get install -y --no-install-recommends yara \
    && rm -rf /var/lib/apt/lists/*

# -- Claude Code (for AI agents) --
RUN npm install -g @anthropic-ai/claude-code

# -- Pre-populate scanner databases --
RUN grype db update || true
RUN trivy --download-db-only || true

# -- Non-root user --
RUN useradd -m -s /bin/bash thresher
RUN mkdir -p /output /opt/scan-results /opt/target /opt/deps \
    && chown -R thresher:thresher /output /opt/scan-results /opt/target /opt/deps

# -- Custom rules --
COPY rules/ /opt/rules/

# -- Thresher (changes most often, last layer) --
COPY pyproject.toml /opt/thresher/
COPY src/ /opt/thresher/src/
RUN pip3 install --break-system-packages /opt/thresher/

VOLUME /output
USER thresher
ENTRYPOINT ["python3", "-m", "thresher.harness"]
```

- [ ] **Step 2: Simplify lima.py**

Replace `src/thresher/vm/lima.py` — remove `provision_vm()` (lines 221-371) and all script-copying logic. The simplified module retains only VM lifecycle:

```python
# src/thresher/vm/lima.py (simplified)

"""Lima VM lifecycle — create, start, stop, destroy.

In v0.4.0, Lima is just a Docker host with an iptables firewall.
All tools live in the Docker image, not installed in the VM.
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_VM_NAME = "thresher-base"
_TEMPLATE_PATH = Path(__file__).parent.parent.parent.parent / "lima" / "thresher.yaml"


def base_exists() -> bool:
    """Check if the base Lima VM exists."""
    result = subprocess.run(
        ["limactl", "list", "--format", "{{.Name}}", BASE_VM_NAME],
        capture_output=True,
    )
    return BASE_VM_NAME in result.stdout.decode()


def create_vm() -> None:
    """Create the base Lima VM from template."""
    logger.info("Creating Lima VM: %s", BASE_VM_NAME)
    subprocess.run(
        ["limactl", "create", "--name", BASE_VM_NAME, str(_TEMPLATE_PATH)],
        check=True,
    )
    start_vm()
    _provision_docker()


def start_vm() -> None:
    """Start the base Lima VM."""
    logger.info("Starting Lima VM: %s", BASE_VM_NAME)
    subprocess.run(["limactl", "start", BASE_VM_NAME], check=True)


def stop_vm() -> None:
    """Stop the base Lima VM."""
    subprocess.run(["limactl", "stop", BASE_VM_NAME], check=True)


def destroy_vm() -> None:
    """Force-delete the Lima VM."""
    subprocess.run(["limactl", "delete", "--force", BASE_VM_NAME], check=True)


def ensure_base_running() -> str:
    """Ensure base VM exists and is running. Returns VM name."""
    if not base_exists():
        create_vm()
    else:
        result = subprocess.run(
            ["limactl", "list", "--format", "{{.Status}}", BASE_VM_NAME],
            capture_output=True,
        )
        if "Stopped" in result.stdout.decode():
            start_vm()
    return BASE_VM_NAME


def _provision_docker() -> None:
    """Minimal provisioning: install Docker, load thresher image."""
    logger.info("Provisioning Docker in VM")
    subprocess.run(
        ["limactl", "shell", BASE_VM_NAME, "--",
         "bash", "-c",
         "curl -fsSL https://get.docker.com | sh && "
         "sudo usermod -aG docker $USER"],
        check=True,
    )


def load_image(image_path: str) -> None:
    """Load a Docker image into the Lima VM."""
    subprocess.run(
        ["limactl", "shell", BASE_VM_NAME, "--",
         "docker", "load", "-i", image_path],
        check=True,
    )
```

Remove: `provision_vm()`, `clean_working_dirs()`, all script-copying functions, `_VM_SCRIPTS_DIR`, `_RULES_DIR`, `_DOCKER_DIR` constants.

The Lima template (`lima/thresher.yaml`) should be simplified to a minimal Ubuntu + Docker template (no tool installation provisioning).

- [ ] **Step 3: Delete old files**

```bash
# SSH and boundary code (replaced by direct subprocess + harness/report.py)
rm -f src/thresher/vm/ssh.py
rm -f src/thresher/vm/safe_io.py

# Docker sandbox (replaced by harness/deps.py)
rm -f src/thresher/docker/sandbox.py

# Old Dockerfile (replaced by docker/Dockerfile)
rm -f docker/Dockerfile.scanner-deps

# Shell scripts (replaced by Python modules)
rm -f docker/scripts/run.sh
rm -f docker/scripts/detect.sh
rm -f docker/scripts/download_python.sh
rm -f docker/scripts/download_node.sh
rm -f docker/scripts/download_rust.sh
rm -f docker/scripts/download_go.sh
rm -f docker/scripts/download_hidden.sh
rm -f docker/scripts/manifest.sh
rm -f docker/scripts/build_manifest.py

# VM provisioning scripts (replaced by Dockerfile)
rm -f vm_scripts/provision.sh
rm -f vm_scripts/safe_clone.sh
rm -f vm_scripts/download_deps.sh
rm -f vm_scripts/run_scanners.sh
rm -f vm_scripts/validate_*.sh

# Old tests
rm -f tests/unit/test_ssh.py
rm -f tests/unit/test_safe_io.py
rm -f tests/unit/test_sandbox.py
```

- [ ] **Step 4: Update imports across codebase**

Search for and remove all imports of deleted modules:
- `from thresher.vm.ssh import ssh_exec, ssh_write_file, ssh_copy_to, ssh_copy_from`
- `from thresher.vm.safe_io import safe_json_loads, validate_copied_tree, ssh_copy_from_safe`
- `from thresher.docker.sandbox import download_dependencies`

- [ ] **Step 5: Run full test suite**

Run: `python -m pytest tests/unit/ tests/integration/ -v`
Expected: PASS (with deleted test files gone and updated imports)

- [ ] **Step 6: Verify Docker image builds**

Run: `docker build -t thresher:latest -f docker/Dockerfile .`
Expected: Image builds successfully

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add Dockerfile, simplify Lima, delete SSH/safe_io/shell scripts"
```

---

### Task 12: Integration test — full harness pipeline

**Files:**
- Create: `tests/integration/test_harness.py`

- [ ] **Step 1: Write integration test**

```python
# tests/integration/test_harness.py

"""Integration test for the full harness pipeline with mocked tools."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from thresher.config import ScanConfig
from thresher.harness.pipeline import run_pipeline


class TestHarnessPipeline:

    @patch("thresher.harness.clone.subprocess.run")
    @patch("thresher.harness.deps.subprocess.run")
    @patch("thresher.scanners.syft.subprocess.run")
    @patch("thresher.scanners.grype.subprocess.run")
    @patch("thresher.harness.report.enrich_findings")
    def test_full_pipeline_skip_ai(
        self, mock_enrich, mock_grype, mock_syft, mock_deps, mock_clone, tmp_path
    ):
        """Full pipeline with skip_ai runs clone, deps, scanners, report."""
        # Setup mocks
        mock_clone.return_value = MagicMock(returncode=0)
        mock_deps.return_value = MagicMock(returncode=0, stdout=b"")
        mock_syft.return_value = MagicMock(returncode=0,
                                           stdout=b'{"components":[]}')
        mock_grype.return_value = MagicMock(returncode=0,
                                           stdout=b'{"matches":[]}')
        mock_enrich.return_value = []

        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            output_dir=str(tmp_path),
            skip_ai=True,
        )

        # This will fail on missing scanners but validates the wiring
        # In a real test, all scanner subprocess calls would be mocked
        with patch("thresher.harness.scanning._get_scanner_tasks") as mock_tasks:
            mock_tasks.return_value = []  # No scanners for this test
            with patch("thresher.harness.report.generate_report") as mock_report:
                mock_report.return_value = str(tmp_path)
                run_pipeline(config)
                mock_report.assert_called_once()

    def test_config_round_trip(self):
        """Config serializes and deserializes correctly for harness handoff."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            skip_ai=True,
            model="opus",
            depth=3,
            high_risk_dep=True,
        )
        json_str = config.to_json()
        restored = ScanConfig.from_json(json_str)
        assert restored.repo_url == config.repo_url
        assert restored.skip_ai == config.skip_ai
        assert restored.model == config.model
        assert restored.depth == config.depth
        assert restored.high_risk_dep == config.high_risk_dep
```

- [ ] **Step 2: Run integration tests**

Run: `python -m pytest tests/integration/test_harness.py -v`
Expected: PASS

- [ ] **Step 3: Run full test suite one final time**

Run: `python -m pytest tests/unit/ tests/integration/ -v`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_harness.py
git commit -m "test: add harness integration tests"
```
