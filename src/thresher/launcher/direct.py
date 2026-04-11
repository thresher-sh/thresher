"""Direct launch mode — runs harness as a subprocess on the host."""

import logging
import subprocess
import sys

from thresher.config import ScanConfig
from thresher.fs import tempfile_with

logger = logging.getLogger(__name__)


def launch_direct(config: ScanConfig) -> int:
    """Launch the harness as a local subprocess. Returns exit code."""
    with tempfile_with(config.to_json(), suffix=".json") as config_path:
        cmd = [
            sys.executable,
            "-m", "thresher.harness",
            "--config", str(config_path),
            "--output", config.output_dir,
        ]
        logger.info("Launching harness (direct mode): %s", " ".join(cmd))
        result = subprocess.run(cmd)
        return result.returncode
