"""Launcher package — selects and invokes the harness in the configured mode.

Modes:
  direct  — subprocess on the host (dev / --no-vm)
  docker  — Docker container on the host
  lima    — Docker inside a Lima VM (maximum isolation, default)
"""
