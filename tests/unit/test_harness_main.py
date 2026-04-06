import json
import pytest
import tempfile
from thresher.harness.__main__ import parse_args


def test_parse_args_requires_config():
    """Harness requires --config argument."""
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
