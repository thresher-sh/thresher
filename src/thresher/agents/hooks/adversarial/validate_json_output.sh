#!/usr/bin/env bash
# Stop hook for adversarial agent — delegates to the shared validator.
set -euo pipefail
exec python3 "$(dirname "$0")/../_common/validate.py" adversarial
