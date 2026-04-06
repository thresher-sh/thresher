"""Direct launch mode — runs harness as a subprocess on the host."""

import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


def launch_direct(config: ScanConfig) -> int:
    """Launch the harness as a local subprocess. Returns exit code."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name
    cmd = [
        sys.executable,
        "-m", "thresher.harness",
        "--config", config_path,
        "--output", config.output_dir,
    ]
    logger.info("Launching harness (direct mode): %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd)
        return result.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)
