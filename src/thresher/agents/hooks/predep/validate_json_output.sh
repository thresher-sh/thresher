#!/usr/bin/env bash
# Stop hook for predep agent — delegates to the shared validator.
set -euo pipefail
exec python3 "$(dirname "$0")/../_common/validate.py" predep
