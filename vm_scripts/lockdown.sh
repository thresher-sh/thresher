#!/bin/bash
# lockdown.sh — Final provisioning step. Strips all sudo access from the
# scan user except the scanner-docker wrapper. Must run AFTER provision.sh
# and firewall.sh are complete (those scripts use sudo extensively).
set -euo pipefail

LOG_PREFIX="[lockdown]"
log() { echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"; }

SCAN_USER="${1:-scanner}"
WRAPPER_PATH="/usr/local/bin/scanner-docker"
SUDOERS_FILE="/etc/sudoers.d/scanner-lockdown"

# ---------------------------------------------------------------------------
# Install the Docker wrapper script
# ---------------------------------------------------------------------------
log "Installing scanner-docker wrapper at ${WRAPPER_PATH}..."
cp /tmp/scanner-docker "${WRAPPER_PATH}"
chown root:root "${WRAPPER_PATH}"
chmod 755 "${WRAPPER_PATH}"

# ---------------------------------------------------------------------------
# Lock down sudoers — allow ONLY the wrapper, nothing else
# ---------------------------------------------------------------------------
log "Writing sudoers lockdown for user '${SCAN_USER}'..."

cat > "${SUDOERS_FILE}" << EOF
# Thresher lockdown: scan user can only invoke the Docker wrapper.
# All other sudo access is denied.
${SCAN_USER} ALL=(root) NOPASSWD: ${WRAPPER_PATH}
EOF

chmod 440 "${SUDOERS_FILE}"

# Validate sudoers syntax before committing
if ! visudo -c -f "${SUDOERS_FILE}" 2>/dev/null; then
    log "ERROR: Invalid sudoers syntax. Removing lockdown file."
    rm -f "${SUDOERS_FILE}"
    exit 1
fi

# Remove default Lima NOPASSWD:ALL entry if present
# Lima typically adds this in /etc/sudoers.d/<username> or inline
LIMA_SUDOERS="/etc/sudoers.d/${SCAN_USER}"
if [ -f "${LIMA_SUDOERS}" ] && [ "${LIMA_SUDOERS}" != "${SUDOERS_FILE}" ]; then
    log "Removing default Lima sudoers entry: ${LIMA_SUDOERS}"
    rm -f "${LIMA_SUDOERS}"
fi

# Also check for a 90-cloud-init-users or similar broad entry
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    [ "$f" = "${SUDOERS_FILE}" ] && continue
    if grep -q "${SCAN_USER}.*NOPASSWD.*ALL" "$f" 2>/dev/null; then
        log "Removing broad sudo entry from: $f"
        # Remove just the matching line rather than the whole file,
        # in case the file covers other users too
        sed -i "/^${SCAN_USER}.*NOPASSWD.*ALL/d" "$f"
    fi
done

# ---------------------------------------------------------------------------
# Remove scan user from the docker group (no direct docker access)
# ---------------------------------------------------------------------------
if id -nG "${SCAN_USER}" | grep -qw docker; then
    log "Removing '${SCAN_USER}' from docker group..."
    gpasswd -d "${SCAN_USER}" docker 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Verify lockdown
# ---------------------------------------------------------------------------
log "Verifying lockdown..."

# The wrapper should be the only allowed sudo command
ALLOWED=$(sudo -l -U "${SCAN_USER}" 2>/dev/null | grep -c "NOPASSWD" || true)
if [ "$ALLOWED" -gt 1 ]; then
    log "WARNING: User '${SCAN_USER}' has more than one NOPASSWD entry."
    sudo -l -U "${SCAN_USER}" 2>/dev/null || true
fi

log "Lockdown complete. User '${SCAN_USER}' can only run: sudo ${WRAPPER_PATH}"
