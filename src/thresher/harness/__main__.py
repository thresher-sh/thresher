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
